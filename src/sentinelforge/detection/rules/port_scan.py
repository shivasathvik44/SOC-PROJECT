"""Port scan detection - enabled by the Phase 4 eBPF network sensor.

A port scan is one source touching many different destination ports in a short
time.  Deciding that requires per-connection telemetry with a **destination
port**, and Phase 1 collects none: journald and ``/var/log/secure`` describe
authentication, not connections.

Phase 4 added that telemetry: the eBPF network sensor fills in
``metadata["destination_port"]``, which the event model exposes as
``event.dst_port``.  The rule is therefore enabled, and keeps its declared data
requirement (``requires = ("dst_port",)``) so that a run over authentication
logs alone is reported as *unavailable* rather than as "nothing found".

Note what this rule can and cannot see: the eBPF sensor traces *outbound*
connections from this host, so it detects this host scanning others.  Detecting
an inbound scan needs accept/drop telemetry, which is listed in the README as
future work.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from ...models.event import SecurityEvent, Severity
from ..mitre import mapping
from ..risk import RiskFactor
from ..rule import Detection, Rule, find_bursts, group_by, most_common_value

#: Why this rule does not run yet, shown by ``sentinelforge rules``.
UNAVAILABLE_REASON = (
    "needs per-connection network telemetry (dst_ip/dst_port); start the eBPF "
    "network sensor with 'sentinelforge sensor start ebpf-network', or feed it "
    "events that already carry it"
)


def _port(event: SecurityEvent) -> str | None:
    """Read a destination port from an event's sensor metadata, if present."""
    value = getattr(event, "dst_port", None)
    return str(value) if value else None


class PortScanRule(Rule):
    """One source contacting many distinct destination ports in a short window.

    Args:
        distinct_ports: How many different ports are needed to trigger.
        window_seconds: Sliding window length.
    """

    rule_id = "PORT_SCAN"
    name = "Port Scan"
    description = (
        "A single source contacted many different destination ports in a short time."
    )
    severity = Severity.MEDIUM
    mitre = mapping("T1046")
    requires = ("dst_port",)

    def __init__(self, distinct_ports: int = 10, window_seconds: int = 60) -> None:
        self.distinct_ports = int(distinct_ports)
        self.window_seconds = int(window_seconds)

    def unavailable_reason(self, events: Sequence[SecurityEvent]) -> str | None:
        if any(_port(event) for event in events):
            return None
        return UNAVAILABLE_REASON

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        connections = [event for event in events if event.src_ip and _port(event)]

        for source_ip, ip_events in group_by(connections, lambda event: event.src_ip).items():
            for burst in find_bursts(ip_events, self.window_seconds, self.distinct_ports):
                ports = sorted({_port(event) for event in burst if _port(event)})
                if len(ports) < self.distinct_ports:
                    continue
                factors = []
                if len(ports) >= self.distinct_ports * 5:
                    factors.append(
                        RiskFactor(10, f"{len(ports)} distinct ports were contacted")
                    )
                yield Detection(
                    dedup_key=source_ip,
                    evidence=burst,
                    description=(
                        f"{source_ip} contacted {len(ports)} distinct destination ports "
                        f"in {self.window_seconds}s."
                    ),
                    source_ip=source_ip,
                    host=most_common_value(burst, "host"),
                    risk_factors=factors,
                )
