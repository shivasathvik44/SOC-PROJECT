"""The sensor registry: one place that knows every telemetry source by name.

Phase 1's log collectors appear here too, wrapped as sensors, so
``sentinelforge sensor list`` shows the whole telemetry surface in one table
rather than splitting it into "collectors" and "sensors".  The wrappers reuse
the existing collector and normalization code; nothing is duplicated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

from ..collector.file import DEFAULT_LOG_PATHS, FilesCollector, detect_log_files
from ..collector.journal import JournalCollector
from ..models.event import SecurityEvent
from ..pipeline.normalize import normalize_all
from .base import Sensor, SensorStatus
from .ebpf.network import EbpfNetworkSensor
from .ebpf.process import EbpfProcessSensor
from .mock import MockSensor


class CollectorSensor(Sensor):
    """Adapts a Phase 1 collector to the sensor interface.

    The collector reads its source and the existing normalization pipeline turns
    records into events, exactly as ``sentinelforge collect`` does.
    """

    def __init__(self, collector, host: str | None = None) -> None:
        super().__init__(host=host)
        self.collector = collector

    def events(self) -> Iterator[SecurityEvent]:
        if not self.running:
            self.start()
        for event in normalize_all(self.collector.collect(), host_default=self.host):
            if not self.running:
                return
            yield event


class JournalSensor(CollectorSensor):
    """systemd journal, through the Phase 1 :class:`JournalCollector`."""

    name = "journal"
    description = "systemd journal entries via journalctl (Phase 1 collector)"
    source = "systemd-journal"

    def __init__(self, follow: bool = False, since: str = "1 hour ago", **kwargs) -> None:
        super().__init__(JournalCollector(since=since, follow=follow), **kwargs)

    @classmethod
    def status(cls) -> SensorStatus:
        if JournalCollector.available():
            return SensorStatus(name=cls.name, available=True)
        return SensorStatus(
            name=cls.name,
            available=False,
            reason="journalctl was not found on this system",
            remedy="Install systemd, or use --source files instead.",
        )


class FileSensor(CollectorSensor):
    """Auth log files, through the Phase 1 :class:`FilesCollector`."""

    name = "file"
    description = "/var/log/secure and /var/log/auth.log (Phase 1 collector)"
    source = "logfile"

    def __init__(self, follow: bool = False, paths=None, **kwargs) -> None:
        super().__init__(FilesCollector(paths=paths, follow=follow), **kwargs)

    @classmethod
    def status(cls) -> SensorStatus:
        found = detect_log_files()
        if found:
            return SensorStatus(name=cls.name, available=True, details={"files": found})
        return SensorStatus(
            name=cls.name,
            available=False,
            reason="no readable auth log file (" + ", ".join(DEFAULT_LOG_PATHS) + ")",
            remedy="Read them as root, or add your user to the 'adm' group.",
        )


@dataclass(frozen=True)
class SensorSpec:
    """One registered sensor: how to describe it, check it and build it."""

    name: str
    description: str
    factory: Callable[..., Sensor]
    sensor_class: type

    def status(self) -> SensorStatus:
        return self.sensor_class.status()


#: Every sensor SentinelForge knows about, in display order.
SENSOR_SPECS: tuple[SensorSpec, ...] = (
    SensorSpec(
        JournalSensor.name, JournalSensor.description, JournalSensor, JournalSensor
    ),
    SensorSpec(FileSensor.name, FileSensor.description, FileSensor, FileSensor),
    SensorSpec(
        EbpfProcessSensor.name,
        EbpfProcessSensor.description,
        EbpfProcessSensor,
        EbpfProcessSensor,
    ),
    SensorSpec(
        EbpfNetworkSensor.name,
        EbpfNetworkSensor.description,
        EbpfNetworkSensor,
        EbpfNetworkSensor,
    ),
    SensorSpec(MockSensor.name, MockSensor.description, MockSensor, MockSensor),
)

SENSOR_NAMES: tuple[str, ...] = tuple(spec.name for spec in SENSOR_SPECS)


def get_spec(name: str) -> SensorSpec | None:
    """Look up a sensor by name."""
    for spec in SENSOR_SPECS:
        if spec.name == name:
            return spec
    return None


def build_sensor(name: str, **options) -> Sensor:
    """Instantiate a sensor by name.

    Raises:
        KeyError: when the name is not registered.
    """
    spec = get_spec(name)
    if spec is None:
        raise KeyError(
            f"unknown sensor {name!r} (available: {', '.join(SENSOR_NAMES)})"
        )
    return spec.factory(**options)


def sensor_statuses() -> list[SensorStatus]:
    """Availability of every registered sensor, for ``sensor list``."""
    statuses = []
    for spec in SENSOR_SPECS:
        try:
            statuses.append(spec.status())
        except Exception as exc:  # pragma: no cover - a probe must never crash the CLI
            statuses.append(
                SensorStatus(name=spec.name, available=False, reason=f"probe failed: {exc}")
            )
    return statuses
