"""Sensor interface shared by every telemetry source (Phase 4).

A *collector* (Phase 1) reads log files.  A *sensor* observes the running
system directly -- today through eBPF.  Both end up producing the same
:class:`~sentinelforge.models.event.SecurityEvent`, so the detection and
correlation engines never need to know where an event came from.

Sensors are strictly **read-only observers**.  They do not modify files, kill
processes, touch firewall rules, change kernel settings, or run commands.
"""

from __future__ import annotations

import abc
import logging
import socket
from dataclasses import dataclass, field
from typing import Iterator

from ..models.event import SecurityEvent

LOGGER = logging.getLogger(__name__)


class SensorError(RuntimeError):
    """A sensor failed while running."""


class SensorUnavailableError(SensorError):
    """The sensor cannot run here (missing tooling, kernel support or privileges).

    Attributes:
        reason: Short explanation of what is missing.
        remedy: What the *user* can do about it -- typically a command for them
            to run themselves.  SentinelForge never escalates privileges on its
            own behalf.
    """

    def __init__(self, reason: str, remedy: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.remedy = remedy

    def report(self) -> str:
        text = f"sensor unavailable: {self.reason}"
        if self.remedy:
            text += f"\n{self.remedy}"
        return text


@dataclass
class SensorStatus:
    """Whether a sensor can run, and why not when it cannot."""

    name: str
    available: bool
    reason: str | None = None
    remedy: str | None = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "available": self.available,
            "reason": self.reason,
            "remedy": self.remedy,
            "details": dict(self.details),
        }


def local_hostname() -> str:
    """Best-effort local hostname, stamped onto every event a sensor produces."""
    try:
        return socket.gethostname() or "unknown"
    except OSError:  # pragma: no cover - extremely unlikely
        return "unknown"


class Sensor(abc.ABC):
    """Base class for telemetry sensors.

    The lifecycle is deliberately small::

        sensor.start()
        for event in sensor.events():
            ...
        sensor.stop()

    :meth:`events` is a generator so a sensor never builds an unbounded list in
    memory.  Implementations must be safe to :meth:`stop` at any time, including
    from a signal handler or a ``finally`` block.
    """

    #: Short identifier used by the CLI, e.g. ``ebpf-process``.
    name: str = "unnamed"
    #: One-line description shown by ``sentinelforge sensor list``.
    description: str = ""
    #: Value written into each event's ``source`` field.
    source: str = "unknown"

    def __init__(self, host: str | None = None) -> None:
        self.host = host or local_hostname()
        self._running = False

    # -- availability ------------------------------------------------------
    @classmethod
    def status(cls) -> SensorStatus:
        """Report whether this sensor can run on this machine right now."""
        return SensorStatus(name=cls.name, available=True)

    @classmethod
    def available(cls) -> bool:
        return cls.status().available

    # -- lifecycle ---------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Attach to the telemetry source.

        Raises:
            SensorUnavailableError: when the sensor cannot run here.  The
                message tells the user exactly what to do; it never escalates
                privileges by itself.
        """
        self._running = True

    def stop(self) -> None:
        """Detach and release resources.  Safe to call twice."""
        self._running = False

    @abc.abstractmethod
    def events(self) -> Iterator[SecurityEvent]:
        """Yield normalized events until the sensor is stopped."""
        raise NotImplementedError

    # -- convenience -------------------------------------------------------
    def __enter__(self) -> "Sensor":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()

    def __iter__(self) -> Iterator[SecurityEvent]:
        return self.events()

    def collect(self, limit: int | None = None) -> list[SecurityEvent]:
        """Start, read up to ``limit`` events, stop.  Mostly for tests and demos."""
        collected: list[SecurityEvent] = []
        self.start()
        try:
            for event in self.events():
                collected.append(event)
                if limit is not None and len(collected) >= limit:
                    break
        finally:
            self.stop()
        return collected

    def __repr__(self) -> str:  # pragma: no cover - debugging convenience
        return f"<{type(self).__name__} {self.name} running={self._running}>"
