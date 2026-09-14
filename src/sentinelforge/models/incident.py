"""Security incident model (Phase 3).

An :class:`Alert` says "this rule matched".  An :class:`Incident` says "these
alerts are the same story": one attacker, one host, one stretch of time.  The
incident carries the alerts, a chronological timeline, the aggregated ATT&CK
chain, and an explained risk score.

``summary`` is deliberately left ``None`` here.  It is the slot the Phase 5 AI
analyst will fill; Phase 3 never writes prose it cannot derive deterministically.
Phase 5 adds one more optional slot, ``ai_analysis``: an incident is complete and
valid without it, and nothing in detection or correlation ever reads it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .alert import Alert
from .event import Severity, parse_timestamp


class IncidentStatus:
    """Incident lifecycle states.

    Only a human (through the CLI) moves an incident between states in this
    phase.  Nothing here is changed automatically by a response action --
    there are no response actions yet.
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

    ALL = (OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE)
    #: States that still accept newly correlated alerts.
    ACTIVE = (OPEN, INVESTIGATING)

    @staticmethod
    def is_valid(status: str) -> bool:
        return status in IncidentStatus.ALL


#: Timeline entry kinds.
ENTRY_ALERT = "alert"
ENTRY_EVENT = "event"

#: Key order for JSON output.  ``alerts`` and ``timeline`` come last: they are long.
FIELD_ORDER = (
    "incident_id",
    "title",
    "status",
    "severity",
    "risk_score",
    "first_seen",
    "last_seen",
    "host",
    "source_ips",
    "users",
    "rule_ids",
    "alert_count",
    "event_count",
    "correlation_reasons",
    "risk_explanation",
    "matched_chains",
    "attack_chain",
    "timeline",
    "alerts",
    "summary",
    "version",
    "ai_analysis",
)

INCIDENT_ID_TEMPLATE = "INC-{:06d}"


def format_incident_id(number: int) -> str:
    """Format a sequential incident number as ``INC-000001``."""
    return INCIDENT_ID_TEMPLATE.format(int(number))


@dataclass(frozen=True)
class TimelineEntry:
    """One structured point on an incident's attack timeline.

    Attributes:
        timestamp: When it happened (RFC 3339 UTC, from the log data).
        type: ``"event"`` for a raw evidence event, ``"alert"`` for a detection.
        event: The event type or the rule id, e.g. ``SUSPICIOUS_SUDO``.
        description: Human-readable line -- the log message or alert description.
        severity: Severity of the alert, when the entry is an alert.
        alert_id: Which alert this entry belongs to, when applicable.
    """

    timestamp: str | None
    type: str
    event: str
    description: str
    severity: str | None = None
    alert_id: str | None = None

    def to_dict(self) -> dict:
        data = {
            "timestamp": self.timestamp,
            "type": self.type,
            "event": self.event,
            "description": self.description,
        }
        if self.severity:
            data["severity"] = self.severity
        if self.alert_id:
            data["alert_id"] = self.alert_id
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "TimelineEntry":
        return cls(
            timestamp=data.get("timestamp"),
            type=data.get("type", ENTRY_EVENT),
            event=data.get("event", ""),
            description=data.get("description", ""),
            severity=data.get("severity"),
            alert_id=data.get("alert_id"),
        )

    def sort_key(self) -> tuple:
        """Chronological order; at equal timestamps evidence precedes its alert."""
        moment = parse_timestamp(self.timestamp)
        return (
            moment.timestamp() if moment else float("inf"),
            0 if self.type == ENTRY_EVENT else 1,
            self.event,
            self.description,
        )


@dataclass
class Incident:
    """A group of related alerts that tell one story.

    Attributes:
        incident_id: Sequential id, e.g. ``INC-000001``.
        title: Derived from the matched attack chain, or from the strongest alert.
        status: One of :class:`IncidentStatus`; ``open`` by default.
        severity / risk_score: Aggregated across the alerts, see
            :mod:`sentinelforge.correlation.scoring`.
        first_seen / last_seen: Span of the correlated activity, in log time.
        host: The host the activity happened on.
        source_ips / users: Entities seen across the alerts, in order of appearance.
        alerts: The correlated alerts, chronological and unique.
        attack_chain: Aggregated, de-duplicated ATT&CK techniques in order of
            first appearance.
        timeline: Structured, chronological :class:`TimelineEntry` objects.
        matched_chains: Ids of the attack-chain patterns that matched.
        correlation_reasons: Why these alerts were put together.
        risk_explanation: Why the incident scored what it scored.
        summary: Reserved for the AI analyst; always ``None`` when correlation
            writes the incident.
        ai_analysis: Optional serialized :class:`AIIncidentAnalysis` (Phase 5).
            ``None`` until someone runs ``sentinelforge ai analyze``; the
            incident is fully valid without it.
    """

    incident_id: str
    title: str
    status: str = IncidentStatus.OPEN
    severity: str = Severity.MEDIUM
    risk_score: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    host: str | None = None
    source_ips: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    attack_chain: list[dict] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    matched_chains: list[str] = field(default_factory=list)
    correlation_reasons: list[str] = field(default_factory=list)
    risk_explanation: list[str] = field(default_factory=list)
    summary: str | None = None
    ai_analysis: dict | None = None

    def __post_init__(self) -> None:
        if not IncidentStatus.is_valid(self.status):
            self.status = IncidentStatus.OPEN

    # -- derived properties ------------------------------------------------
    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def rule_ids(self) -> list[str]:
        """Distinct rule ids that contributed, in order of first appearance."""
        seen: list[str] = []
        for alert in self.alerts:
            if alert.rule_id not in seen:
                seen.append(alert.rule_id)
        return seen

    @property
    def event_count(self) -> int:
        """Number of unique evidence events across all alerts (no double counting)."""
        return len(self.unique_events())

    def unique_events(self) -> list:
        """Return the de-duplicated evidence events from every alert.

        The same log line can back more than one alert (a failed login supports
        both the brute-force and the compromise detection), so evidence is
        de-duplicated by its content before it is counted or put on a timeline.
        """
        seen: set[tuple] = set()
        events = []
        for alert in self.alerts:
            for event in alert.evidence:
                key = (event.timestamp, event.source, event.event_type, event.message)
                if key in seen:
                    continue
                seen.add(key)
                events.append(event)
        return events

    @property
    def version(self) -> str:
        """Short content fingerprint of the incident's *evidence*.

        Two incidents with the same fingerprint tell the same story: the same
        alerts, entities, timing and score.  Re-running correlation over the
        same alerts therefore reproduces the same version, while a newly
        correlated alert changes it.

        Deliberately excluded: ``status`` (a human's lifecycle decision, not
        new evidence), ``summary`` and ``ai_analysis`` (they are *derived from*
        this fingerprint, so including them would be circular).
        """
        material = json.dumps(
            {
                "incident_id": self.incident_id,
                "title": self.title,
                "severity": self.severity,
                "risk_score": int(self.risk_score),
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "host": self.host,
                "source_ips": sorted(self.source_ips),
                "users": sorted(self.users),
                "matched_chains": sorted(self.matched_chains),
                "timeline": len(self.timeline),
                "alerts": sorted(
                    (alert.alert_id, alert.rule_id, alert.timestamp or "", alert.event_count)
                    for alert in self.alerts
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]

    def is_active(self, reference: str | None, window_seconds: int) -> bool:
        """Whether the incident is still accepting correlated alerts.

        "Inactive" is **not** "resolved": an inactive incident simply stopped
        receiving related alerts, and a human decides its lifecycle status.
        """
        if self.status not in IncidentStatus.ACTIVE:
            return False
        last = parse_timestamp(self.last_seen)
        moment = parse_timestamp(reference)
        if last is None or moment is None:
            return True
        return (moment - last).total_seconds() <= window_seconds

    # -- serialization -----------------------------------------------------
    def to_dict(self, include_alerts: bool = True, include_evidence: bool = True) -> dict:
        """Return the incident as a plain dict with a stable key order."""
        data = {
            "incident_id": self.incident_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "host": self.host,
            "source_ips": list(self.source_ips),
            "users": list(self.users),
            "rule_ids": self.rule_ids,
            "alert_count": self.alert_count,
            "event_count": self.event_count,
            "correlation_reasons": list(self.correlation_reasons),
            "risk_explanation": list(self.risk_explanation),
            "matched_chains": list(self.matched_chains),
            "attack_chain": [dict(item) for item in self.attack_chain],
            "timeline": [entry.to_dict() for entry in self.timeline],
            "alerts": (
                [alert.to_dict(include_evidence=include_evidence) for alert in self.alerts]
                if include_alerts
                else []
            ),
            "summary": self.summary,
            "version": self.version,
            "ai_analysis": self.ai_analysis,
        }
        return {key: data[key] for key in FIELD_ORDER}

    def to_json(self, include_alerts: bool = True, include_evidence: bool = True) -> str:
        """Serialize to a single JSON line (one JSONL record)."""
        return json.dumps(
            self.to_dict(include_alerts=include_alerts, include_evidence=include_evidence),
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Incident":
        """Rebuild an incident from its serialized form."""
        return cls(
            incident_id=data.get("incident_id", ""),
            title=data.get("title", ""),
            status=data.get("status", IncidentStatus.OPEN),
            severity=data.get("severity", Severity.MEDIUM),
            risk_score=int(data.get("risk_score", 0) or 0),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            host=data.get("host"),
            source_ips=list(data.get("source_ips") or []),
            users=list(data.get("users") or []),
            alerts=[Alert.from_dict(item) for item in data.get("alerts") or []],
            attack_chain=[dict(item) for item in data.get("attack_chain") or []],
            timeline=[TimelineEntry.from_dict(item) for item in data.get("timeline") or []],
            matched_chains=list(data.get("matched_chains") or []),
            correlation_reasons=list(data.get("correlation_reasons") or []),
            risk_explanation=list(data.get("risk_explanation") or []),
            summary=data.get("summary"),
            ai_analysis=data.get("ai_analysis") or None,
        )

    def summary_line(self) -> str:
        """One-line summary used by the CLI listing."""
        where = self.host or "unknown host"
        source = ", ".join(self.source_ips) or "-"
        return (
            f"{self.incident_id} [{self.severity.upper():8}] risk={self.risk_score:3} "
            f"{self.status:14} {where} {source} - {self.title} "
            f"({self.alert_count} alert(s))"
        )
