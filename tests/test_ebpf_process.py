"""Tests for the eBPF process sensor.

Nothing here needs root or a kernel hook: the decoder is exercised with
synthetic raw records, and the sensor's failure paths are driven with patched
support probes.
"""

import os
from types import SimpleNamespace

import pytest

from sentinelforge.models.event import EventType, Severity
from sentinelforge.sensors.base import SensorUnavailableError
from sentinelforge.sensors.ebpf import loader
from sentinelforge.sensors.ebpf.process import (
    ARGSIZE,
    MAX_ARGS,
    EbpfProcessSensor,
    build_program,
    decode_process_event,
    resolve_user,
    synthetic_record,
)


class TestBpfProgram:
    def test_constants_are_substituted(self):
        program = build_program()
        assert "__ARGSIZE__" not in program
        assert "__MAX_ARGS__" not in program
        assert f"#define ARGSIZE  {ARGSIZE}" in program
        assert f"#define MAX_ARGS {MAX_ARGS}" in program

    def test_program_is_read_only(self):
        """The BPF program observes; it must not contain any write helper."""
        program = build_program()
        for forbidden in (
            "bpf_probe_write_user",
            "bpf_send_signal",
            "bpf_override_return",
            "bpf_sock_ops_cb",
            "bpf_skb_store_bytes",
        ):
            assert forbidden not in program

    def test_kernel_side_filters_exist(self):
        program = build_program()
        assert "SELF_PID" in program  # never report our own execs
        assert "FILTER_UID" in program  # optional per-user filter, in-kernel

    def test_argument_capture_is_compiled_out_when_disabled(self):
        sensor = EbpfProcessSensor(capture_args=False)
        assert "-DCAPTURE_ARGS=1" not in sensor.cflags()
        assert any(flag.startswith("-DSELF_PID=") for flag in sensor.cflags())

    def test_uid_filter_becomes_a_compile_flag(self):
        assert "-DFILTER_UID=1000" in EbpfProcessSensor(uid=1000).cflags()


class TestDecoder:
    def test_decodes_a_full_record(self):
        event = decode_process_event(synthetic_record(), host="fedora")

        assert event.event_type == EventType.PROCESS_START
        assert event.severity == Severity.INFO
        assert event.source == "ebpf"
        assert event.host == "fedora"
        assert event.process == "curl"
        assert event.executable == "/usr/bin/curl"
        assert event.command_line == "curl http://198.51.100.9/x.sh"
        assert event.pid == 4101
        assert event.ppid == 4100
        assert event.parent_process == "bash"
        assert event.metadata["uid"] == 1000

    def test_process_lineage_is_preserved(self):
        """pid/ppid/executable/parent are what future process-tree work needs."""
        event = decode_process_event(synthetic_record(), host="fedora")
        assert (event.pid, event.ppid) == (4101, 4100)
        assert event.parent_process == "bash"
        assert event.executable == "/usr/bin/curl"

    def test_nul_terminated_buffers_are_trimmed(self):
        event = decode_process_event(
            synthetic_record(comm=b"curl\x00\x00\x00\x00", filename=b"/usr/bin/curl\x00junk")
        )
        assert event.process == "curl"
        assert event.executable == "/usr/bin/curl"

    def test_missing_fields_become_none_not_guesses(self):
        record = SimpleNamespace(ts=0, pid=10, comm=b"sh\x00")
        event = decode_process_event(record)
        assert event.pid == 10
        assert event.ppid is None
        assert event.executable is None
        assert event.parent_process is None
        assert event.command_line is None
        assert event.process == "sh"

    def test_completely_empty_record_does_not_raise(self):
        event = decode_process_event(SimpleNamespace())
        assert event.event_type == EventType.PROCESS_START
        assert event.process is None
        assert event.metadata == {}

    def test_malformed_buffers_are_replaced_not_fatal(self):
        event = decode_process_event(
            synthetic_record(comm=b"\xff\xfe bad", filename=b"\x80\x81\x00")
        )
        assert event.event_type == EventType.PROCESS_START
        assert event.to_json()  # still serializable

    def test_arguments_beyond_the_cap_are_flagged(self):
        record = synthetic_record(
            nargs=MAX_ARGS, argv=[f"arg{i}".encode() + b"\x00" for i in range(MAX_ARGS)]
        )
        event = decode_process_event(record)
        assert event.metadata["args_truncated"] is True
        assert len(event.command_line.split()) == MAX_ARGS

    def test_nargs_zero_means_no_command_line(self):
        event = decode_process_event(synthetic_record(nargs=0))
        assert event.command_line is None
        assert "command_line" not in event.metadata

    def test_user_is_resolved_only_when_a_lookup_is_given(self):
        assert decode_process_event(synthetic_record()).user is None
        event = decode_process_event(synthetic_record(), user_lookup=lambda uid: f"uid{uid}")
        assert event.user == "uid1000"

    def test_timestamps_come_from_the_boot_clock(self):
        clock = loader.BootClock()
        event = decode_process_event(
            synthetic_record(ts=clock.monotonic_ns), clock=clock
        )
        assert event.timestamp.endswith("Z")

    def test_resolve_user_handles_unknown_uids(self):
        assert resolve_user(os.getuid()) is not None
        assert resolve_user(4294967294) is None

    def test_event_is_serializable_with_metadata(self):
        import json

        data = json.loads(decode_process_event(synthetic_record()).to_json())
        assert data["metadata"]["ppid"] == 4100
        assert data["source"] == "ebpf"


class TestSensorLifecycle:
    def test_unavailable_ebpf_raises_with_a_remedy(self, monkeypatch):
        monkeypatch.setattr(
            "sentinelforge.sensors.ebpf.process.check_ebpf_support",
            lambda: loader.EbpfSupport(
                supported=False, reasons=["insufficient privileges"], remedy="run with sudo"
            ),
        )
        sensor = EbpfProcessSensor()
        with pytest.raises(SensorUnavailableError) as exc:
            sensor.start()
        assert "insufficient privileges" in exc.value.reason
        assert exc.value.remedy
        assert sensor.running is False

    def test_status_reports_why_it_cannot_run(self, monkeypatch):
        monkeypatch.setattr(
            "sentinelforge.sensors.ebpf.process.check_ebpf_support",
            lambda: loader.EbpfSupport(
                supported=False, reasons=["no BCC"], remedy="dnf install", details={"x": 1}
            ),
        )
        status = EbpfProcessSensor.status()
        assert status.available is False
        assert status.reason == "no BCC"
        assert status.remedy == "dnf install"

    def test_stop_is_safe_before_start_and_twice(self):
        sensor = EbpfProcessSensor()
        sensor.stop()
        sensor.stop()
        assert sensor.running is False

    def test_a_malformed_kernel_record_is_skipped_not_fatal(self, caplog):
        """_handle_event must swallow decode failures."""

        class Boom:
            def event(self, data):
                raise ValueError("truncated perf record")

        sensor = EbpfProcessSensor()
        sensor._bpf = {"exec_events": Boom()}
        sensor._handle_event(0, b"", 0)  # must not raise
        assert sensor.events_seen == 0
        assert "unreadable exec record" in caplog.text

    def test_dropped_events_are_counted(self, caplog):
        sensor = EbpfProcessSensor()
        sensor._handle_lost(17)
        assert sensor.events_dropped == 17
        assert "dropped" in caplog.text
