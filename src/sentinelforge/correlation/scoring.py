"""Incident risk scoring.

Reuses the Phase 2 scoring vocabulary (:class:`RiskFactor`, the severity bands)
so an incident score means the same thing as an alert score.

The model, in words:

1. Start from the **highest** alert risk in the incident -- never the sum, so
   the same activity detected by two rules cannot inflate the score.
2. Add small, named factors for corroboration (distinct rules, a successful
   login, privileged activity, breadth of ATT&CK tactics).
3. Add the bonus of the **single strongest** matched attack chain, not of every
   chain that overlaps it.
4. When a chain matched, floor the score at the next severity band above the
   strongest alert -- that is how ``LOW + LOW`` becomes ``MEDIUM`` and
   ``HIGH + HIGH`` becomes ``CRITICAL``.
5. Clamp to 0-100.

A single-alert incident keeps exactly its alert's score: with nothing to
corroborate, there is nothing to escalate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from ..detection.risk import (
    MAX_SCORE,
    MIN_SCORE,
    SEVERITY_THRESHOLDS,
    RiskFactor,
    severity_for_score,
)
from ..models.alert import Alert
from ..models.event import EventType, Severity
from .chains import PRIVILEGE_ESCALATION, SUCCESSFUL_AUTH, AttackChain

#: Points per distinct detection rule beyond the first, and the cap for them.
POINTS_PER_EXTRA_RULE = 3
MAX_CORROBORATION = 9
#: Fixed contextual bonuses.
POINTS_SUCCESSFUL_AUTH = 4
POINTS_PRIVILEGE_ESCALATION = 4
POINTS_TACTIC_BREADTH = 3
#: How many distinct ATT&CK tactics count as "broad".
TACTIC_BREADTH_THRESHOLD = 3


@dataclass
class IncidentRisk:
    """Outcome of scoring one incident."""

    score: int
    severity: str
    explanation: list[str] = field(default_factory=list)


def _next_band_floor(score: int) -> int | None:
    """Lowest score of the severity band above the one ``score`` falls in.

    Returns ``None`` when the score is already in the top band.
    """
    ascending = sorted(SEVERITY_THRESHOLDS)  # (0, info) ... (90, critical)
    for threshold, _severity in ascending:
        if threshold > score:
            return threshold
    return None


def has_successful_authentication(alerts: Sequence[Alert]) -> bool:
    """True when the incident contains a successful authentication."""
    for alert in alerts:
        if SUCCESSFUL_AUTH.matches(alert):
            return True
        if any(
            event.event_type == EventType.AUTHENTICATION_SUCCESS for event in alert.evidence
        ):
            return True
    return False


def has_privilege_escalation(alerts: Sequence[Alert]) -> bool:
    """True when the incident contains privileged or privilege-changing activity."""
    return any(PRIVILEGE_ESCALATION.matches(alert) for alert in alerts)


def distinct_tactics(alerts: Sequence[Alert]) -> list[str]:
    """ATT&CK tactics across the alerts, in order of first appearance."""
    tactics: list[str] = []
    for alert in alerts:
        tactic = (alert.mitre or {}).get("tactic")
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    return tactics


def score_incident(
    alerts: Sequence[Alert], chains: Sequence[AttackChain] = ()
) -> IncidentRisk:
    """Score an incident from its alerts and the attack chains it matched.

    Args:
        alerts: Unique alerts belonging to the incident.
        chains: Matched chains, strongest first (see
            :func:`sentinelforge.correlation.chains.match_chains`).

    Returns:
        An :class:`IncidentRisk` whose ``explanation`` accounts for every point.
    """
    if not alerts:
        return IncidentRisk(score=0, severity=Severity.INFO, explanation=["no alerts"])

    strongest = max(alerts, key=lambda alert: alert.risk_score)
    base = int(strongest.risk_score)
    explanation = [
        f"base {base}: highest alert risk ({strongest.rule_id}, "
        f"severity '{strongest.severity}')"
    ]

    factors: list[RiskFactor] = []
    if len(alerts) > 1:
        rules = {alert.rule_id for alert in alerts}
        extra = min(MAX_CORROBORATION, POINTS_PER_EXTRA_RULE * (len(rules) - 1))
        if extra:
            factors.append(
                RiskFactor(
                    extra,
                    f"{len(rules)} different detection rules fired on correlated activity",
                )
            )
        if has_successful_authentication(alerts):
            factors.append(
                RiskFactor(POINTS_SUCCESSFUL_AUTH, "a successful authentication is part of the incident")
            )
        if has_privilege_escalation(alerts):
            factors.append(
                RiskFactor(
                    POINTS_PRIVILEGE_ESCALATION,
                    "privileged activity followed the other alerts",
                )
            )
        tactics = distinct_tactics(alerts)
        if len(tactics) >= TACTIC_BREADTH_THRESHOLD:
            factors.append(
                RiskFactor(
                    POINTS_TACTIC_BREADTH,
                    f"activity spans {len(tactics)} ATT&CK tactics ({', '.join(tactics)})",
                )
            )

    # Only the strongest chain contributes; weaker chains it contains would be
    # counting the same behaviour twice.
    strongest_chain = chains[0] if chains else None
    if strongest_chain is not None:
        factors.append(
            RiskFactor(
                strongest_chain.risk_bonus,
                f"attack chain '{strongest_chain.chain_id}' matched "
                f"({' -> '.join(stage.name for stage in strongest_chain.stages)})",
            )
        )

    score = base
    for factor in factors:
        score += factor.points
        explanation.append(factor.describe())

    if strongest_chain is not None:
        floor = _next_band_floor(base)
        if floor is not None and score < floor:
            explanation.append(
                f"raised to {floor}: a matched attack chain puts the incident at least "
                "one severity band above its strongest alert"
            )
            score = floor

    clamped = max(MIN_SCORE, min(MAX_SCORE, score))
    if clamped != score:
        explanation.append(f"clamped to {clamped} (valid range {MIN_SCORE}-{MAX_SCORE})")

    severity = severity_for_score(clamped)
    explanation.append(f"final score {clamped} -> severity '{severity}'")
    return IncidentRisk(score=clamped, severity=severity, explanation=explanation)
