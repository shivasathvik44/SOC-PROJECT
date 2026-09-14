"""Security alert model (Phase 2).

An :class:`Alert` is what a detection rule produces when it matches.  It always
carries the events that caused it (``evidence``), the ATT&CK context, and a
plain-language explanation of its risk score -- the Phase 5 AI analyst reads
exactly these fields, so nothing is thrown away here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .event import SecurityEvent, Severity

#: Key order used for JSON output.  ``evidence`` comes last because it is long.
FIELD_ORDER = (
    "alert_id",
    "timestamp",
    "rule_id",
    "name",
    "severity",
    "risk_score",
    "host",
    "source_ip",
    "user",
    "description",
    "mitre",
    "risk_explanation",
    "event_count",
    "first_seen",
    "last_seen",
    "suppressed_duplicates",
    "evidence",
)

#: Alert ids look like ``ALT-000001``.
ALERT_ID_TEMPLATE = "ALT-{:06d}"


def format_alert_id(number: int) -> str:
    """Format a sequential alert number as ``ALT-000001``."""
    return ALERT_ID_TEMPLATE.format(int(number))


@dataclass
class Alert:
    """A security alert raised by one detection rule.

    Attributes:
        alert_id: Sequential id within a detection run, e.g. ``ALT-000001``.
        timestamp: Time of the newest evidence event (log time, not wall clock),
            so replaying the same events always produces the same alert.
        rule_id: Stable id of the rule that fired, e.g. ``SSH_BRUTE_FORCE``.
        severity: Final severity after contextual escalation.
        risk_score: Deterministic score from 0-100.
        host / source_ip / user: Context, ``None`` when the events do not say.
        evidence: The events that triggered the alert, in chronological order.
        mitre: ATT&CK mapping as a plain dict (see :mod:`sentinelforge.detection.mitre`).
        risk_explanation: Why this score was assigned, one human-readable line
            per scoring factor.
        suppressed_duplicates: How many later matches were folded into this
            alert by the deduplication window.
    """

    alert_id: str
    rule_id: str
    name: str
    description: str
    severity: str = Severity.MEDIUM
    risk_score: int = 0
    timestamp: str | None = None
    host: str | None = None
    source_ip: str | None = None
    user: str | None = None
    evidence: list[SecurityEvent] = field(default_factory=list)
    mitre: dict | None = None
    risk_explanation: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    suppressed_duplicates: int = 0

    @property
    def event_count(self) -> int:
        """How many events back this alert."""
        return len(self.evidence)

    def to_dict(self, include_evidence: bool = True, max_evidence: int | None = None) -> dict:
        """Return the alert as a plain dict with a stable key order.

        Args:
            include_evidence: Set to ``False`` for a compact summary line.
            max_evidence: Keep only the first N evidence events (``None`` keeps
                all of them).
        """
        evidence = self.evidence
        if max_evidence is not None and max_evidence >= 0:
            evidence = evidence[:max_evidence]

        data = {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "host": self.host,
            "source_ip": self.source_ip,
            "user": self.user,
            "description": self.description,
            "mitre": self.mitre,
            "risk_explanation": list(self.risk_explanation),
            "event_count": self.event_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "suppressed_duplicates": self.suppressed_duplicates,
            "evidence": [event.to_dict() for event in evidence] if include_evidence else [],
        }
        return {key: data[key] for key in FIELD_ORDER}

    def to_json(self, include_evidence: bool = True, max_evidence: int | None = None) -> str:
        """Serialize to a single JSON line (one JSONL record)."""
        return json.dumps(
            self.to_dict(include_evidence=include_evidence, max_evidence=max_evidence),
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def summary(self) -> str:
        """One-line human-readable summary, used by the CLI."""
        where = self.source_ip or self.host or "unknown source"
        return (
            f"{self.alert_id} [{self.severity.upper():8}] risk={self.risk_score:3} "
            f"{self.rule_id} {where} - {self.description}"
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        """Rebuild an alert from its serialized form (evidence included)."""
        known = {
            key: data[key]
            for key in FIELD_ORDER
            if key in data and key not in ("evidence", "event_count")
        }
        known["evidence"] = [
            SecurityEvent.from_dict(item) for item in data.get("evidence", []) or []
        ]
        return cls(**known)


#: Alias kept for readability where a list of evidence events is passed around.
AlertEvidence = list
