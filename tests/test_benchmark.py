"""Phase 8: the benchmark, and the honesty of its numbers.

A benchmark that measures the wrong thing is worse than none, so these tests
check the *measurement*, not the speed:

* the workload is bounded, deterministic, and actually produces alerts (a
  workload that the engines skip would report a wonderful events/second);
* timings come from a monotonic clock and never from the synthetic event
  timestamps -- a workload spanning days of log time must not report days;
* memory instrumentation does not contaminate the timings;
* the reported alert and incident counts are the ones the engines produced.

Performance *thresholds* are deliberately loose and few. A test that fails
because a laptop was busy teaches nothing, so what is asserted is scaling
behaviour and sanity, not milliseconds.
"""

import os
import time

import pytest

from sentinelforge.simulation.benchmark import (
    DEFAULT_SIZES,
    MAX_EVENTS,
    BenchmarkReport,
    describe_environment,
    measure_latency,
    measure_throughput,
    run_benchmark,
    synthetic_workload,
)
from sentinelforge.models.event import EventType, parse_timestamp

#: How much worse a ten-times workload may be before a scaling test fails.
#: Deliberately generous -- a busy CI runner must not fail the suite, while a
#: change from linear to quadratic complexity (which cost ~98x before the
#: correlation index was cached) still does. Override it on a slow machine:
#:
#:     SENTINELFORGE_BENCH_SCALING_FACTOR=80 pytest tests/test_benchmark.py
SCALING_FACTOR = float(os.environ.get("SENTINELFORGE_BENCH_SCALING_FACTOR", "40"))
#: Fixed allowance, in milliseconds, so a sub-millisecond baseline cannot make
#: the ratio meaningless.
SCALING_SLACK_MS = float(os.environ.get("SENTINELFORGE_BENCH_SLACK_MS", "50"))


class TestWorkload:
    @pytest.mark.parametrize("count", [1, 7, 10, 100, 1000])
    def test_exactly_the_requested_number_of_events(self, count):
        assert len(synthetic_workload(count)) == count

    def test_the_workload_is_bounded(self):
        assert len(synthetic_workload(MAX_EVENTS + 5_000)) == MAX_EVENTS

    def test_a_nonsensical_size_still_produces_something_usable(self):
        assert len(synthetic_workload(0)) == 1
        assert len(synthetic_workload(-10)) == 1

    def test_the_workload_is_deterministic(self):
        first = [event.to_json() for event in synthetic_workload(200)]
        second = [event.to_json() for event in synthetic_workload(200)]
        assert first == second

    def test_the_workload_exercises_every_stage_of_the_pipeline(self):
        kinds = {event.event_type for event in synthetic_workload(100)}
        assert EventType.AUTHENTICATION_FAILURE in kinds
        assert EventType.AUTHENTICATION_SUCCESS in kinds
        assert EventType.SUDO in kinds
        assert EventType.PROCESS_START in kinds
        assert EventType.NETWORK_CONNECTION in kinds

    def test_the_workload_uses_documentation_addresses_only(self):
        import ipaddress

        allowed = (
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("10.0.0.0/8"),
        )
        for event in synthetic_workload(300):
            for value in (event.src_ip, (event.metadata or {}).get("destination_ip")):
                if not value:
                    continue
                assert any(ipaddress.ip_address(value) in net for net in allowed)

    def test_alert_volume_scales_with_event_volume(self):
        """A workload that deduplicated away would flatter the throughput figure."""
        small = measure_throughput(200, measure_memory=False)
        large = measure_throughput(2000, measure_memory=False)
        assert small.alerts > 0 and large.alerts > small.alerts * 5


class TestThroughputMeasurement:
    def test_the_counts_come_from_the_engines(self):
        from sentinelforge.correlation.engine import CorrelationEngine
        from sentinelforge.detection.engine import DetectionEngine

        events = synthetic_workload(300)
        alerts = DetectionEngine().run(events)
        incidents = CorrelationEngine().run(alerts)

        result = measure_throughput(300, measure_memory=False)
        assert result.events == len(events)
        assert result.alerts == len(alerts)
        assert result.incidents == len(incidents)

    def test_timings_are_wall_time_not_log_time(self):
        """The workload spans days of synthetic log time; the run does not."""
        events = synthetic_workload(1000)
        span = parse_timestamp(events[-1].timestamp) - parse_timestamp(events[0].timestamp)
        assert span.total_seconds() > 3600, "the workload should span hours of log time"

        started = time.perf_counter()
        result = measure_throughput(1000, measure_memory=False)
        elapsed_ms = (time.perf_counter() - started) * 1000
        assert result.total_ms <= elapsed_ms + 1
        assert result.total_ms < 60_000

    def test_derived_rates_agree_with_the_measurements(self):
        result = measure_throughput(500, measure_memory=False)
        assert result.total_ms == pytest.approx(
            result.detection_ms + result.correlation_ms
        )
        assert result.events_per_second == pytest.approx(
            result.events / (result.total_ms / 1000.0), rel=1e-6
        )
        assert result.microseconds_per_event == pytest.approx(
            result.total_ms * 1000 / result.events, rel=1e-6
        )

    def test_cpu_time_is_recorded_and_plausible(self):
        result = measure_throughput(2000, measure_memory=False)
        assert result.cpu_seconds > 0
        # Single-threaded work: CPU time cannot exceed wall time by much.
        assert result.cpu_seconds <= (result.total_ms / 1000.0) * 2 + 0.5

    def test_memory_is_measured_in_a_separate_pass(self):
        """Instrumenting allocations would inflate the timings, so it must not."""
        instrumented = measure_throughput(2000, measure_memory=True)
        clean = measure_throughput(2000, measure_memory=False)
        assert instrumented.peak_allocated_kb > 0
        assert instrumented.memory_measured is True
        assert clean.peak_allocated_kb == 0
        assert clean.memory_measured is False
        assert clean.to_dict()["peak_allocated_kb"] is None
        # Timings should be the same order of magnitude, not 3x apart.
        assert instrumented.total_ms < clean.total_ms * 5 + 50

    def test_memory_use_is_bounded_and_scales_sensibly(self):
        small = measure_throughput(500)
        large = measure_throughput(5000)
        assert large.peak_allocated_kb > small.peak_allocated_kb
        # Ten times the events must not cost a hundred times the memory.
        assert large.peak_allocated_kb < small.peak_allocated_kb * 30


class TestScaling:
    def test_detection_throughput_does_not_collapse_with_scale(self):
        """Detection is linear; a regression to quadratic shows up here.

        The bound is deliberately generous -- see :data:`SCALING_FACTOR`, which
        is configurable -- so that a loaded machine does not fail the suite,
        while a genuine change in complexity still does.
        """
        small = measure_throughput(500, measure_memory=False)
        large = measure_throughput(5000, measure_memory=False)
        assert large.detection_ms < small.detection_ms * SCALING_FACTOR + SCALING_SLACK_MS

    def test_correlation_throughput_does_not_collapse_with_scale(self):
        """Regression guard for the quadratic correlation Phase 8 found.

        Before the ATT&CK index was cached, a 10x workload cost roughly 98x the
        correlation time. The same configurable bound as detection is used.
        """
        small = measure_throughput(500, measure_memory=False)
        large = measure_throughput(5000, measure_memory=False)
        assert large.correlation_ms < small.correlation_ms * SCALING_FACTOR + SCALING_SLACK_MS


class TestLatency:
    def test_every_stage_is_measured(self):
        result = measure_latency("full-attack")
        assert result.generation_ms > 0
        assert result.detection_ms > 0
        assert result.correlation_ms > 0
        assert result.ai_ms > 0
        assert result.total_ms == pytest.approx(
            result.detection_ms + result.correlation_ms + result.ai_ms
        )

    def test_the_counts_match_the_scenario(self):
        result = measure_latency("full-attack")
        assert result.events == 12
        assert result.alerts == 5
        assert result.incidents == 1

    def test_the_ai_stage_is_labelled_as_the_offline_provider(self):
        payload = measure_latency("ssh-bruteforce").to_dict()
        assert payload["ai_provider"] == "mock"
        assert "network round trip" in payload["ai_note"]

    def test_a_benign_scenario_has_no_ai_stage_to_measure(self):
        result = measure_latency("benign-sudo")
        assert result.incidents == 0
        assert result.ai_ms == 0

    def test_an_unknown_scenario_is_refused_by_name(self):
        with pytest.raises(KeyError):
            measure_latency("no-such-scenario")


class TestReport:
    def test_the_report_records_the_environment(self):
        env = describe_environment()
        for key in ("python", "implementation", "system", "machine", "measured_at"):
            assert env.get(key)

    def test_a_full_run_produces_every_section(self):
        report = run_benchmark(sizes=(50, 100), measure_memory=False)
        assert isinstance(report, BenchmarkReport)
        payload = report.to_dict()
        assert len(payload["throughput"]) == 2
        assert payload["latency"]["scenario_id"] == "full-attack"
        assert payload["environment"]["python"]
        assert any("perf_counter" in note for note in payload["notes"])

    def test_the_default_sizes_are_bounded(self):
        assert all(size <= MAX_EVENTS for size in DEFAULT_SIZES)
        assert DEFAULT_SIZES == tuple(sorted(DEFAULT_SIZES))


class TestThresholdsAreConfigurable:
    """Performance thresholds must not make the suite flaky on a slow machine."""

    def test_the_scaling_tolerance_can_be_overridden(self, monkeypatch):
        import importlib

        monkeypatch.setenv("SENTINELFORGE_BENCH_SCALING_FACTOR", "123")
        monkeypatch.setenv("SENTINELFORGE_BENCH_SLACK_MS", "999")
        module = importlib.reload(importlib.import_module("test_benchmark"))
        try:
            assert module.SCALING_FACTOR == 123
            assert module.SCALING_SLACK_MS == 999
        finally:
            monkeypatch.delenv("SENTINELFORGE_BENCH_SCALING_FACTOR")
            monkeypatch.delenv("SENTINELFORGE_BENCH_SLACK_MS")
            importlib.reload(module)

    def test_the_defaults_are_generous(self):
        assert SCALING_FACTOR >= 10, (
            "a tolerance near the ideal ratio would fail whenever the machine is busy"
        )
