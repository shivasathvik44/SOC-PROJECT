"""Detection rule interface and shared time-window helpers.

A rule is a small, self-contained class: it declares who it is (``rule_id``,
``name``, ``description``, ``severity``, ATT&CK ``mitre`` mapping) and
implements :meth:`Rule.evaluate`, which receives normalized events and yields
:class:`Detection` objects.

Rules deliberately do **not** build :class:`~sentinelforge.models.alert.Alert`
objects themselves.  They describe *what* they found; the engine assigns alert
ids, applies risk scoring and handles deduplication.  Adding a detection later
means writing a new Rule subclass -- the engine never changes.
"""

from __future__ import annotations

import abc
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, Iterator, Sequence

from ..models.event import SecurityEvent, Severity, parse_timestamp
from .mitre import MitreMapping
from .risk import RiskFactor


@dataclass
class Detection:
    """Something a rule found, before it becomes an alert.

    Attributes:
        dedup_key: Identifies the "same thing happening again" (for example
            ``"192.168.1.50"`` for a brute force from one address).  The engine
            uses ``(rule_id, dedup_key)`` for its cooldown window.
        evidence: The events that caused the detection, chronological.
        description: One sentence describing what was observed.
        host / source_ip / user: Context; left ``None`` when unknown.
        risk_factors: Contextual scoring adjustments with explanations.
        severity / name / mitre: Optional per-detection overrides for rules that
            cover several distinct behaviours (the sudo rule uses all three).
    """

    dedup_key: str
    evidence: list[SecurityEvent]
    description: str
    host: str | None = None
    source_ip: str | None = None
    user: str | None = None
    risk_factors: list[RiskFactor] = field(default_factory=list)
    severity: str | None = None
    name: str | None = None
    mitre: MitreMapping | None = None


class Rule(abc.ABC):
    """Base class for every detection rule.

    Subclasses set the class attributes below and implement :meth:`evaluate`.
    """

    #: Stable identifier, e.g. ``SSH_BRUTE_FORCE``.  Used by ``--rule``.
    rule_id: str = "UNNAMED_RULE"
    #: Short human-readable name.
    name: str = "Unnamed rule"
    #: What the rule looks for, in one or two sentences.
    description: str = ""
    #: Declared base severity; contextual factors may escalate it.
    severity: str = Severity.MEDIUM
    #: ATT&CK mapping from :mod:`sentinelforge.detection.mitre`.
    mitre: MitreMapping | None = None
    #: Set to ``False`` to ship a rule that does not run by default.
    enabled: bool = True
    #: Event fields the rule needs that Phase 1 may not collect yet.
    requires: tuple[str, ...] = ()

    def unavailable_reason(self, events: Sequence[SecurityEvent]) -> str | None:
        """Return why this rule cannot run, or ``None`` when it can.

        The default implementation reports missing telemetry listed in
        :attr:`requires`.  The engine skips such rules and records the reason
        instead of emitting misleading "no findings" results.
        """
        if not self.requires:
            return None
        missing = [
            name
            for name in self.requires
            if not any(getattr(event, name, None) for event in events)
        ]
        if missing:
            return (
                "requires event fields not collected in Phase 1: " + ", ".join(missing)
            )
        return None

    @abc.abstractmethod
    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        """Examine events and yield :class:`Detection` objects.

        Implementations must be read-only and deterministic: same events in,
        same detections out.  They must never execute anything found in a log.
        """
        raise NotImplementedError

    def to_dict(self) -> dict:
        """Describe the rule, for ``sentinelforge rules``."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
            "requires": list(self.requires),
            "mitre": self.mitre.to_dict() if self.mitre else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging convenience
        return f"<{type(self).__name__} {self.rule_id}>"


# --------------------------------------------------------------------------
# Shared helpers.  Rules use these instead of re-implementing time windows.
# --------------------------------------------------------------------------
#: Address ranges treated as "inside this network".  Defined explicitly rather
#: than using ``ipaddress.is_private``, which also covers the documentation
#: ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) that are *not*
#: internal -- a distinction every rule that reasons about "external" needs.
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_external_address(address: str | None) -> bool:
    """Return ``True`` for an address outside :data:`INTERNAL_NETWORKS`.

    Hostnames and unparseable values return ``False``: not enough evidence.
    """
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not any(parsed in network for network in INTERNAL_NETWORKS)



TimedEvent = tuple[datetime, SecurityEvent]


def timed(events: Iterable[SecurityEvent]) -> list[TimedEvent]:
    """Pair events with parsed timestamps, chronologically.

    Events whose timestamp cannot be parsed are dropped: a time-window rule
    cannot say anything meaningful about them, and guessing a time would be
    inventing evidence.
    """
    result: list[TimedEvent] = []
    for event in events:
        moment = parse_timestamp(getattr(event, "timestamp", None))
        if moment is not None:
            result.append((moment, event))
    result.sort(key=lambda pair: pair[0])
    return result


def group_by(
    events: Iterable[SecurityEvent], key: Callable[[SecurityEvent], str | None]
) -> dict[str, list[SecurityEvent]]:
    """Group events by a key, skipping events where the key is missing."""
    groups: dict[str, list[SecurityEvent]] = {}
    for event in events:
        value = key(event)
        if value:
            groups.setdefault(value, []).append(event)
    return groups


def find_bursts(
    events: Sequence[SecurityEvent], window_seconds: int, threshold: int
) -> Iterator[list[SecurityEvent]]:
    """Yield maximal bursts of at least ``threshold`` events within a window.

    A burst starts where ``threshold`` events fall inside ``window_seconds``,
    and keeps absorbing following events while they stay within one window of
    the previous one.  That is what stops 30 failed logins in a single attack
    from producing 26 overlapping detections.
    """
    if threshold <= 0:
        return
    window = timedelta(seconds=max(0, window_seconds))
    pairs = timed(events)
    total = len(pairs)

    start = 0
    while start < total:
        end = start
        while end + 1 < total and pairs[end + 1][0] - pairs[start][0] <= window:
            end += 1
        if end - start + 1 >= threshold:
            last = end
            while last + 1 < total and pairs[last + 1][0] - pairs[last][0] <= window:
                last += 1
            yield [event for _, event in pairs[start : last + 1]]
            start = last + 1
        else:
            start += 1


def events_within(
    reference: datetime, events: Sequence[SecurityEvent], window_seconds: int
) -> list[SecurityEvent]:
    """Return events that happened in the ``window_seconds`` before ``reference``."""
    window = timedelta(seconds=max(0, window_seconds))
    return [
        event
        for moment, event in timed(events)
        if timedelta(0) <= reference - moment <= window
    ]


def first_value(events: Sequence[SecurityEvent], attribute: str) -> str | None:
    """Return the first non-empty value of an attribute across events."""
    for event in events:
        value = getattr(event, attribute, None)
        if value:
            return value
    return None


def most_common_value(events: Sequence[SecurityEvent], attribute: str) -> str | None:
    """Return the most frequent non-empty value of an attribute across events."""
    counts: dict[str, int] = {}
    for event in events:
        value = getattr(event, attribute, None)
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda item: (item[1], item[0]))[0]


def time_span(events: Sequence[SecurityEvent]) -> tuple[str | None, str | None]:
    """Return the (first, last) timestamps of a chronological event list."""
    stamps = [event.timestamp for event in events if getattr(event, "timestamp", None)]
    if not stamps:
        return None, None
    return min(stamps), max(stamps)
