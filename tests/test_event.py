"""Tests for the normalized event model (creation + JSON serialization)."""

import json
from datetime import datetime, timezone

import pytest

from sentinelforge.models.event import (
    FIELD_ORDER,
    EventType,
    SecurityEvent,
    Severity,
    format_timestamp,
)


def test_event_defaults_are_safe():
    event = SecurityEvent()
    assert event.event_type == EventType.UNKNOWN
    assert event.severity == Severity.INFO
    # Optional fields stay None instead of being invented.
    assert event.user is None
    assert event.src_ip is None
    assert event.process is None
    assert event.timestamp.endswith("Z")


def test_event_creation_with_all_fields():
    event = SecurityEvent(
        timestamp="2026-09-12T10:30:00Z",
        host="fedora",
        source="systemd-journal",
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.MEDIUM,
        user="root",
        src_ip="192.168.1.50",
        process="sshd",
        message="Failed password for root from 192.168.1.50",
        raw="original log message",
    )
    assert event.host == "fedora"
    assert event.user == "root"
    assert event.src_ip == "192.168.1.50"


def test_unknown_event_type_and_severity_fall_back():
    event = SecurityEvent(event_type="definitely_not_real", severity="apocalyptic")
    assert event.event_type == EventType.UNKNOWN
    assert event.severity == Severity.INFO


def test_to_dict_key_order_is_stable():
    event = SecurityEvent(host="fedora")
    # Sensor metadata is omitted while empty, so Phase 1 output is unchanged.
    assert list(event.to_dict().keys()) == [key for key in FIELD_ORDER if key != "metadata"]


def test_metadata_is_serialized_only_when_a_sensor_filled_it_in():
    plain = SecurityEvent(host="fedora")
    assert "metadata" not in plain.to_dict()

    telemetry = SecurityEvent(host="fedora", metadata={"pid": 1234})
    assert list(telemetry.to_dict().keys()) == list(FIELD_ORDER)
    assert telemetry.to_dict()["metadata"] == {"pid": 1234}
    assert SecurityEvent.from_dict(telemetry.to_dict()).pid == 1234


def test_metadata_accessors_return_none_when_unavailable():
    event = SecurityEvent(metadata={"pid": 7, "destination_port": None})
    assert event.pid == 7
    assert event.ppid is None
    assert event.dst_port is None
    assert event.executable is None
    assert SecurityEvent(metadata="not a dict").metadata == {}


def test_to_json_is_single_line_and_round_trips():
    event = SecurityEvent(
        host="fedora",
        source="systemd-journal",
        event_type=EventType.SUDO,
        severity=Severity.MEDIUM,
        user="capslock",
        message="capslock : TTY=pts/0 ; COMMAND=/usr/bin/dnf",
        raw="raw line",
    )
    line = event.to_json()
    assert "\n" not in line

    data = json.loads(line)
    assert data["event_type"] == "sudo"
    assert data["user"] == "capslock"
    assert data["src_ip"] is None

    rebuilt = SecurityEvent.from_dict(data)
    assert rebuilt == event


def test_compact_json_omits_null_fields():
    event = SecurityEvent(host="fedora", message="hello")
    data = json.loads(event.to_json(include_empty=False))
    assert "user" not in data
    assert "src_ip" not in data
    assert data["host"] == "fedora"


def test_from_dict_ignores_unknown_keys():
    event = SecurityEvent.from_dict(
        {"host": "fedora", "message": "hi", "mitre_technique": "T1110"}
    )
    assert event.host == "fedora"
    assert event.message == "hi"


def test_non_string_values_are_coerced():
    event = SecurityEvent(host=123, user=456, message=None, raw=b"")
    assert event.host == "123"
    assert event.user == "456"
    assert event.message == ""


@pytest.mark.parametrize(
    "value,expected",
    [
        (datetime(2026, 9, 12, 10, 30, 0, tzinfo=timezone.utc), "2026-09-12T10:30:00Z"),
        (datetime(2026, 9, 12, 10, 30, 0), "2026-09-12T10:30:00Z"),
    ],
)
def test_format_timestamp(value, expected):
    assert format_timestamp(value) == expected
