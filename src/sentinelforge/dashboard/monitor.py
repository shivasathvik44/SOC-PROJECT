"""Background monitors that feed the dashboard's event bus (Phase 6).

SentinelForge is a set of small read-only processes: one terminal collects,
another detects, another correlates.  The dashboard is a fourth.  Nothing in
Phases 1-5 knows about it, and this module is what keeps it that way -- the
dashboard *observes* the pipeline's own outputs rather than being wired into it:

* :class:`IncidentWatcher` compares the incident store's revision index between
  ticks.  A new row is an ``incident_created``; a changed ``updated_at`` is an
  ``incident_updated``; an incident that has gained an ``ai_analysis`` is an
  ``ai_analysis_completed``.
* :class:`JsonlTailer` follows the JSON Lines files the collector and detector
  already write (``collect -o events.jsonl``, ``detect -o alerts.jsonl``) the
  way ``tail -f`` does, and republishes each line as a bus message.
* :class:`SensorMonitor` re-probes sensor availability and reports changes.

All three are polling loops, and that is a deliberate trade: the alternative is
making the detection engine aware of a web UI, or adding an IPC layer between
processes that are meant to be independently runnable.  Polling a SQLite index
and a file offset costs almost nothing, and the pipeline stays exactly as it
was.  The intervals are configurable.

Every monitor is read-only: it opens files and databases for reading, and it
never writes, deletes, or executes anything.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading

from ..bus import EventBus, Topic, default_bus
from ..models.alert import Alert
from ..models.event import SecurityEvent
from .serializers import serialize_alert, serialize_event, serialize_incident_summary

LOGGER = logging.getLogger(__name__)

#: A single tail read never returns more than this many lines, so a monitor
#: cannot monopolise the CPU when a file grows quickly.
MAX_LINES_PER_TICK = 200


class Monitor(threading.Thread):
    """Base class: a daemon thread with a stop event and a fixed interval."""

    def __init__(self, interval: float, bus: EventBus | None = None, name: str = "monitor") -> None:
        super().__init__(name=f"sentinelforge-{name}", daemon=True)
        self.interval = max(0.1, float(interval))
        self.bus = bus or default_bus()
        self._stop = threading.Event()
        self.errors = 0

    def run(self) -> None:  # pragma: no cover - exercised through tick()
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                self.errors += 1
                LOGGER.exception("%s failed; continuing", self.name)
            self._stop.wait(self.interval)

    def tick(self) -> None:
        """One iteration.  Called by :meth:`run`, and directly by tests."""
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()


class IncidentWatcher(Monitor):
    """Publishes incident changes by diffing the store's revision index.

    Args:
        config: The dashboard configuration (for the database path).
        bus: Where to publish.
        prime: When ``True`` (the default) the first tick records what already
            exists without announcing it, so opening the dashboard does not
            replay every historical incident as "new".
    """

    def __init__(self, config, bus: EventBus | None = None, prime: bool = True) -> None:
        super().__init__(config.poll_interval, bus, name="incident-watcher")
        self.config = config
        self._revisions: dict[str, str] = {}
        self._analyzed: set[str] = set()
        self._primed = not prime

    def tick(self) -> None:
        try:
            with self.config.store() as store:
                revisions = store.revision_index()
                changed = [
                    incident_id
                    for incident_id, updated in revisions.items()
                    if self._revisions.get(incident_id) != updated
                ]
                if not self._primed:
                    # First pass: remember the world as it is, announce nothing.
                    self._revisions = revisions
                    for incident_id in changed:
                        incident = store.get(incident_id)
                        if incident is not None and incident.ai_analysis:
                            self._analyzed.add(incident_id)
                    self._primed = True
                    return
                incidents = {
                    incident_id: store.get(incident_id) for incident_id in changed
                }
        except sqlite3.Error as exc:
            # A database that is missing or momentarily locked is not fatal:
            # the dashboard keeps serving what it already has.
            LOGGER.debug("incident watcher could not read the store: %s", exc)
            return

        for incident_id in changed:
            incident = incidents.get(incident_id)
            if incident is None:
                continue
            first_seen_here = incident_id not in self._revisions
            self._revisions[incident_id] = revisions[incident_id]
            payload = serialize_incident_summary(incident)
            payload["demo"] = self.config.demo
            self.bus.publish(
                Topic.INCIDENT_CREATED if first_seen_here else Topic.INCIDENT_UPDATED,
                payload,
            )
            if incident.ai_analysis and incident_id not in self._analyzed:
                self._analyzed.add(incident_id)
                analysis = incident.ai_analysis or {}
                self.bus.publish(
                    Topic.AI_ANALYSIS_COMPLETED,
                    {
                        "incident_id": incident_id,
                        "status": analysis.get("status"),
                        "assessment": analysis.get("assessment"),
                        "confidence": analysis.get("confidence"),
                        "severity_assessment": analysis.get("severity_assessment"),
                        "severity_disagreement": analysis.get("severity_disagreement"),
                        "provider": (analysis.get("audit") or {}).get("provider"),
                        "is_mock": (analysis.get("audit") or {}).get("is_mock"),
                        "demo": self.config.demo,
                    },
                )

        # Incidents that vanished (a deleted row) simply stop being tracked.
        for incident_id in list(self._revisions):
            if incident_id not in revisions:
                self._revisions.pop(incident_id, None)
                self._analyzed.discard(incident_id)


class JsonlTailer(Monitor):
    """Follows a JSON Lines file and republishes each record on the bus.

    This is how a dashboard sees live events and alerts produced by a pipeline
    running in another terminal::

        sentinelforge collect -f -o events.jsonl
        sentinelforge detect events.jsonl -o alerts.jsonl
        sentinelforge dashboard --watch-events events.jsonl --watch-alerts alerts.jsonl

    Args:
        path: File to follow.  It does not have to exist yet.
        kind: ``"events"`` or ``"alerts"``.
        from_start: Read the file from the beginning instead of following only
            new lines.  Off by default: a dashboard should show what is
            happening, not replay yesterday.
    """

    KINDS = ("events", "alerts")

    def __init__(
        self,
        path: str,
        kind: str,
        bus: EventBus | None = None,
        interval: float = 1.0,
        from_start: bool = False,
        demo: bool = False,
    ) -> None:
        super().__init__(interval, bus, name=f"tail-{kind}")
        if kind not in self.KINDS:
            raise ValueError(f"unknown tail kind {kind!r} (expected one of {self.KINDS})")
        self.path = path
        self.kind = kind
        self.demo = demo
        self._offset = 0 if from_start else None
        self._inode = None
        self.published = 0
        self.skipped = 0

    def tick(self) -> None:
        try:
            stat = os.stat(self.path)
        except OSError:
            return  # not created yet, or removed; keep waiting quietly

        if self._offset is None:
            # Start at the end: only new activity is "live".
            self._offset = stat.st_size
            self._inode = stat.st_ino
            return
        if self._inode is not None and stat.st_ino != self._inode:
            self._offset = 0  # rotated
        elif stat.st_size < self._offset:
            self._offset = 0  # truncated
        self._inode = stat.st_ino
        if stat.st_size == self._offset:
            return

        lines: list[str] = []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._offset)
                position = self._offset
                for _ in range(MAX_LINES_PER_TICK):
                    line = handle.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        # A half-written line: leave the offset before it so the
                        # next tick re-reads it once the writer has finished.
                        break
                    lines.append(line)
                    position = handle.tell()
                self._offset = position
        except OSError as exc:
            LOGGER.debug("could not read %s: %s", self.path, exc)
            return

        for line in lines:
            self._publish(line)

    def _publish(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            data = json.loads(line)
        except ValueError:
            self.skipped += 1
            return
        if not isinstance(data, dict):
            self.skipped += 1
            return
        try:
            if self.kind == "events":
                payload = serialize_event(SecurityEvent.from_dict(data))
                topic = Topic.EVENT_RECEIVED
            else:
                payload = serialize_alert(Alert.from_dict(data))
                topic = Topic.ALERT_CREATED
        except Exception:
            # Malformed telemetry is skipped, never rendered half-parsed.
            self.skipped += 1
            return
        payload["demo"] = self.demo
        payload["origin"] = os.path.basename(self.path)
        self.bus.publish(topic, payload)
        self.published += 1


class SensorMonitor(Monitor):
    """Publishes sensor availability changes (eBPF appearing or disappearing)."""

    def __init__(self, context, bus: EventBus | None = None) -> None:
        super().__init__(context.config.sensor_interval, bus, name="sensor-monitor")
        self.context = context
        self._previous: dict[str, bool] = {}

    def tick(self) -> None:
        snapshot = self.context.sensor_snapshot(max_age=0.0)
        for sensor in snapshot:
            name = sensor["name"]
            available = bool(sensor["available"])
            if name in self._previous and self._previous[name] != available:
                self.bus.publish(Topic.SENSOR_STATUS_CHANGED, dict(sensor))
            self._previous[name] = available


class MonitorSet:
    """Starts and stops the monitors a dashboard process needs."""

    def __init__(self, monitors: list[Monitor] | None = None) -> None:
        self.monitors = list(monitors or [])

    @classmethod
    def for_context(cls, context) -> "MonitorSet":
        config = context.config
        monitors: list[Monitor] = [
            IncidentWatcher(config, context.bus),
            SensorMonitor(context, context.bus),
        ]
        if config.events_file:
            monitors.append(
                JsonlTailer(config.events_file, "events", context.bus, demo=config.demo)
            )
        if config.alerts_file:
            monitors.append(
                JsonlTailer(config.alerts_file, "alerts", context.bus, demo=config.demo)
            )
        return cls(monitors)

    def start(self) -> "MonitorSet":
        for monitor in self.monitors:
            if not monitor.is_alive():
                monitor.start()
        return self

    def stop(self) -> None:
        for monitor in self.monitors:
            monitor.stop()
        for monitor in self.monitors:
            if monitor.is_alive():
                monitor.join(timeout=2.0)

    def describe(self) -> list[dict]:
        return [
            {"name": monitor.name, "alive": monitor.is_alive(), "errors": monitor.errors}
            for monitor in self.monitors
        ]
