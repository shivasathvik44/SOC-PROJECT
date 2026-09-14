"""Telemetry sensors (Phase 4): eBPF and friends."""

from .base import Sensor, SensorError, SensorStatus, SensorUnavailableError
from .mock import MockSensor
from .registry import (
    SENSOR_NAMES,
    SENSOR_SPECS,
    FileSensor,
    JournalSensor,
    SensorSpec,
    build_sensor,
    get_spec,
    sensor_statuses,
)

__all__ = [
    "SENSOR_NAMES",
    "SENSOR_SPECS",
    "FileSensor",
    "JournalSensor",
    "MockSensor",
    "Sensor",
    "SensorError",
    "SensorSpec",
    "SensorStatus",
    "SensorUnavailableError",
    "build_sensor",
    "get_spec",
    "sensor_statuses",
]
