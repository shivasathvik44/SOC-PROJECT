"""Dashboard runtime state: configuration, live buffers, store access (Phase 6).

The incident store is the system of record.  This module holds only what a
*live* view needs and a database cannot give: the recent stream of events and
alerts as they arrive, plus a few counters.

Everything here is bounded.  A SOC console left open for a week must not grow
without limit, so the live buffers are ``deque``s with a maximum length and the
rate counter keeps one minute of timestamps -- no more.

Database connections are deliberately **not** cached on this object.  SQLite
connections belong to the thread that created them, and a Flask server is
multi-threaded, so every request opens and closes its own short-lived store.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from ..ai.client import LLMConfig
from ..bus import DEFAULT_QUEUE_SIZE, EventBus, Topic, default_bus
from ..models.event import utc_now
from ..sensors.registry import get_spec, sensor_statuses
from ..storage.sqlite import IncidentStore, default_database_path
from .serializers import serialize_sensor_status

LOGGER = logging.getLogger(__name__)

#: How many live items each buffer keeps.  The live view is a window on recent
#: activity, not an archive; the archive is the incident store.
DEFAULT_LIVE_BUFFER = 500

#: Window used to compute the events-per-second figure on the overview.
RATE_WINDOW_SECONDS = 60


@dataclass
class DashboardConfig:
    """How one dashboard process is configured.

    Attributes:
        db_path: Incident database.  The Phase 3 store, reused as-is.
        host / port: Bind address.  Loopback by default -- the dashboard has no
            authentication and is not meant to face a network.
        debug: Flask debug mode.  Development only; never on by default,
            because the Werkzeug debugger is an arbitrary-code-execution
            console by design.
        demo: Whether this process is showing synthetic data.
        live_buffer: Maximum retained live events / alerts / activity items.
        events_file / alerts_file: Optional JSON Lines files to follow, as
            written by ``sentinelforge collect -o`` and ``detect -o``.  This is
            how live events and alerts reach a dashboard that runs in a
            different process from the pipeline.
        poll_interval: Seconds between incident-store checks.
        sensor_interval: Seconds between sensor availability probes.
        max_page_size: Hard ceiling on any API ``limit``.
        alert_scan_incidents: How many recent incidents the alert list reads.
        response_enabled: Whether the Phase 7 response API is served at all.
            Off automatically when the dashboard is not bound to loopback: the
            console has no authentication, and an unauthenticated containment
            endpoint on a network interface would be a remote control for the
            host.  See :meth:`response_available`.
    """

    db_path: str | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    debug: bool = False
    demo: bool = False
    live_buffer: int = DEFAULT_LIVE_BUFFER
    events_file: str | None = None
    alerts_file: str | None = None
    poll_interval: float = 2.0
    sensor_interval: float = 30.0
    max_page_size: int = 500
    alert_scan_incidents: int = 200
    response_enabled: bool = True

    def resolved_db_path(self) -> str:
        return self.db_path or default_database_path()

    def store(self) -> IncidentStore:
        """A fresh, unopened store for the calling thread."""
        return IncidentStore(self.resolved_db_path())

    @property
    def is_loopback(self) -> bool:
        return self.host in ("127.0.0.1", "::1", "localhost")

    def response_available(self) -> tuple[bool, str | None]:
        """Whether this process may serve response endpoints, and why not.

        Two conditions, both structural rather than advisory: the operator has
        not turned the response API off, and the dashboard is bound to
        loopback.  A dashboard reachable from the network has no authentication
        to put in front of a containment endpoint, so it does not get one.
        """
        if not self.response_enabled:
            return False, (
                "the response API is disabled in this dashboard process "
                "(started with --no-response). Use the sentinelforge response "
                "commands instead."
            )
        if not self.is_loopback:
            return False, (
                f"the dashboard is bound to {self.host}, not loopback. The response API "
                "is served on 127.0.0.1 only: this console has no authentication, and an "
                "unauthenticated containment endpoint must not be reachable from a "
                "network. Use the sentinelforge response commands on the host instead."
            )
        return True, None


class LiveState:
    """Bounded, thread-safe record of what just happened.

    Fed from the bus by a single pump thread, so publishers never touch this
    object and a slow browser cannot back-pressure the pipeline.
    """

    def __init__(self, bus: EventBus | None = None, buffer_size: int = DEFAULT_LIVE_BUFFER) -> None:
        self.bus = bus or default_bus()
        self.buffer_size = max(1, int(buffer_size))
        self._lock = threading.Lock()
        self.events: deque = deque(maxlen=self.buffer_size)
        self.alerts: deque = deque(maxlen=self.buffer_size)
        self.activity: deque = deque(maxlen=self.buffer_size)
        self._event_times: deque = deque(maxlen=5000)
        self.counters = {
            "events_received": 0,
            "alerts_created": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "ai_analyses": 0,
            "response_actions": 0,
        }
        self.started_at = utc_now()
        self._started_monotonic = time.monotonic()
        self._subscription = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "LiveState":
        """Subscribe to the bus and start draining it in the background."""
        if self._thread is not None:
            return self
        self._subscription = self.bus.subscribe(maxsize=DEFAULT_QUEUE_SIZE * 2)
        self._thread = threading.Thread(
            target=self._pump, name="sentinelforge-live-state", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._subscription is not None:
            self._subscription.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _pump(self) -> None:
        assert self._subscription is not None
        while not self._stop.is_set():
            message = self._subscription.get(timeout=0.5)
            if message is None:
                continue
            try:
                self.record(message.topic, message.payload, message.sequence)
            except Exception:  # pragma: no cover - a bad payload must not kill the pump
                LOGGER.exception("could not record bus message %s", message.topic)

    # -- recording ---------------------------------------------------------
    def record(self, topic: str, payload: dict, sequence: int = 0) -> None:
        """Fold one bus message into the live state."""
        item = {
            "sequence": sequence,
            "topic": topic,
            "received_at": utc_now(),
            "payload": payload,
        }
        with self._lock:
            if topic == Topic.EVENT_RECEIVED:
                self.counters["events_received"] += 1
                self.events.append(item)
                self._event_times.append(time.monotonic())
            elif topic == Topic.ALERT_CREATED:
                self.counters["alerts_created"] += 1
                self.alerts.append(item)
            elif topic == Topic.INCIDENT_CREATED:
                self.counters["incidents_created"] += 1
            elif topic == Topic.INCIDENT_UPDATED:
                self.counters["incidents_updated"] += 1
            elif topic == Topic.AI_ANALYSIS_COMPLETED:
                self.counters["ai_analyses"] += 1
            elif topic == Topic.RESPONSE_ACTION:
                self.counters["response_actions"] += 1
            if topic != Topic.HEARTBEAT:
                self.activity.append(item)

    # -- reading -----------------------------------------------------------
    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self.events)[-limit:][::-1]

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self.alerts)[-limit:][::-1]

    def recent_activity(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self.activity)[-limit:][::-1]

    def events_per_second(self) -> float:
        """Event rate over the last minute (0.0 when nothing arrived)."""
        cutoff = time.monotonic() - RATE_WINDOW_SECONDS
        with self._lock:
            while self._event_times and self._event_times[0] < cutoff:
                self._event_times.popleft()
            count = len(self._event_times)
        elapsed = min(RATE_WINDOW_SECONDS, max(1.0, time.monotonic() - self._started_monotonic))
        return round(count / elapsed, 2)

    def snapshot(self) -> dict:
        """Counters for the overview page."""
        with self._lock:
            counters = dict(self.counters)
        counters.update(
            {
                "events_per_second": self.events_per_second(),
                "buffered_events": len(self.events),
                "buffered_alerts": len(self.alerts),
                "buffer_size": self.buffer_size,
                "started_at": self.started_at,
                "uptime_seconds": int(time.monotonic() - self._started_monotonic),
                "subscribers": self.bus.subscriber_count,
            }
        )
        return counters


class DashboardContext:
    """Everything a request handler needs, assembled once at startup.

    Holds the configuration, the bus, the live state and the sensor cache.  It
    holds no database connection and no model objects: those are read per
    request from the store, so a long-lived dashboard never serves a stale
    incident from memory.
    """

    def __init__(self, config: DashboardConfig | None = None, bus: EventBus | None = None) -> None:
        self.config = config or DashboardConfig()
        self.bus = bus or default_bus()
        self.live = LiveState(self.bus, self.config.live_buffer)
        self._sensor_cache: list[dict] = []
        self._sensor_checked_at: float = 0.0
        self._sensor_lock = threading.Lock()
        self.monitors = None  # set by app.create_app when monitors are started
        self._response_engine = None
        self._response_lock = threading.Lock()

    # -- store -------------------------------------------------------------
    def store(self) -> IncidentStore:
        return self.config.store()

    # -- sensors -----------------------------------------------------------
    def sensor_snapshot(self, max_age: float | None = None) -> list[dict]:
        """Sensor availability, cached briefly.

        Probing asks whether ``journalctl`` exists, whether BCC is importable
        and whether this process has the privileges eBPF needs.  That is cheap
        but not free, and nothing about it changes between two page loads, so
        the result is cached for ``sensor_interval`` seconds.
        """
        max_age = self.config.sensor_interval if max_age is None else max_age
        now = time.monotonic()
        with self._sensor_lock:
            fresh = self._sensor_cache and (now - self._sensor_checked_at) < max_age
            if fresh:
                return list(self._sensor_cache)
        snapshot = []
        for status in sensor_statuses():
            spec = get_spec(status.name)
            snapshot.append(
                serialize_sensor_status(status, spec.description if spec else None)
            )
        snapshot.append(self.ai_status())
        with self._sensor_lock:
            self._sensor_cache = snapshot
            self._sensor_checked_at = now
        return list(snapshot)

    # -- response ----------------------------------------------------------
    def response_engine(self):
        """The Phase 7 engine this dashboard drives, built once and shared.

        Two deliberate choices.  In **demo mode** the engine is built on the
        mock backends, so the response panel can be clicked through end to end
        on any machine without a firewall rule or a signal ever being real --
        the same rule the rest of demo mode follows.  When the response API is
        **not available** here (disabled, or not on loopback) the engine is
        built with execution switched off, so even a mistake in a route cannot
        reach a backend that changes anything.

        The engine holds no database connection: it opens one per operation,
        which is what makes it safe to share across Flask's request threads.
        """
        with self._response_lock:
            if self._response_engine is not None:
                return self._response_engine
            from ..response.actions import ResponseBackends
            from ..response.engine import ResponseEngine

            available, _ = self.config.response_available()
            if self.config.demo:
                from ..response.backends.mock import (
                    MockFirewallBackend,
                    MockProcessBackend,
                    MockSessionBackend,
                )
                from ..response.executor import ReadOnlyCommandRunner

                backends = ResponseBackends(
                    firewall=MockFirewallBackend(zone_name="demo-zone"),
                    process=_demo_process_backend(MockProcessBackend()),
                    session=_demo_session_backend(MockSessionBackend()),
                    runner=ReadOnlyCommandRunner(),
                )
            else:
                backends = ResponseBackends.detect(execution_enabled=available)
            self._response_engine = ResponseEngine(
                db_path=self.config.resolved_db_path(),
                backends=backends,
                execution_enabled=available,
            )
            return self._response_engine

    def ai_status(self) -> dict:
        """AI provider availability, with no secret in it.

        Reports *whether* a key is configured, never its value -- the same rule
        the CLI follows.
        """
        config = LLMConfig.from_env()
        described = config.describe()
        is_mock = config.provider == "mock"
        configured = is_mock or (config.has_api_key and bool(config.model))
        if is_mock:
            reason = "offline mock provider: synthetic analysis, no API key, no network"
        elif configured:
            reason = f"provider '{config.provider}' configured"
        elif not config.model:
            reason = f"provider '{config.provider}' has no model configured "
            reason += "(set SENTINELFORGE_LLM_MODEL)"
        else:
            reason = f"provider '{config.provider}' has no API key configured"
        return {
            "name": "ai-analyst",
            "available": bool(configured),
            "state": "configured" if configured else "not configured",
            "description": f"AI SOC analyst ({described['provider']} / {described['model']})",
            "reason": reason,
            "remedy": None
            if configured
            else "export SENTINELFORGE_LLM_PROVIDER / SENTINELFORGE_LLM_MODEL / OPENAI_API_KEY, "
            "or use the offline mock provider",
            "is_mock": is_mock,
        }

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "DashboardContext":
        self.live.start()
        return self

    def stop(self) -> None:
        if self.monitors is not None:
            self.monitors.stop()
        self.live.stop()


def _demo_process_backend(backend):
    """Give demo mode the processes the synthetic incident talks about."""
    backend.add(
        4250,
        name="python3",
        executable="/usr/bin/python3",
        command_line="python3 -c import socket,subprocess",
        username="capslock",
        ppid=4242,
    )
    backend.add(4242, name="bash", executable="/usr/bin/bash", command_line="bash -i",
                username="capslock")
    return backend


def _demo_session_backend(backend):
    """Give demo mode one synthetic remote session to terminate."""
    backend.add("42", name="capslock", remotehost="198.51.100.25", type="tty")
    return backend
