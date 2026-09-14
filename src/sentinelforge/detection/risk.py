"""Deterministic, explainable risk scoring.

No machine learning, no heuristics that cannot be written down: a rule declares
a base severity, context adds or removes a fixed number of points, and every
adjustment carries a sentence explaining itself.  The same events always
produce the same score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models.event import Severity

#: Base score for each severity level.
BASE_SCORES: dict[str, int] = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 90,
}

#: Lowest score that still counts as a given severity.  Used to derive the
#: final severity after contextual adjustments (highest matching band wins).
SEVERITY_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (90, Severity.CRITICAL),
    (75, Severity.HIGH),
    (50, Severity.MEDIUM),
    (25, Severity.LOW),
    (0, Severity.INFO),
)

MIN_SCORE = 0
MAX_SCORE = 100


@dataclass(frozen=True)
class RiskFactor:
    """One contextual adjustment to a base score.

    Attributes:
        points: Added to the score (may be negative to reduce it).
        reason: Plain-language justification shown in the alert.
    """

    points: int
    reason: str

    def describe(self) -> str:
        sign = "+" if self.points >= 0 else ""
        return f"{sign}{self.points}: {self.reason}"


@dataclass
class RiskAssessment:
    """The outcome of scoring one detection."""

    score: int
    severity: str
    explanation: list[str] = field(default_factory=list)


def severity_for_score(score: int) -> str:
    """Map a numeric score back to a severity band."""
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO  # pragma: no cover - unreachable, 0 is the last band


def assess_risk(base_severity: str, factors: list[RiskFactor] | None = None) -> RiskAssessment:
    """Score a detection.

    The base severity sets the starting score; each :class:`RiskFactor` moves it
    up or down.  The final severity is derived from the final score, which is
    how contextual escalation works:

        5 failed logins                      -> high     (75)
        5 failed logins + successful login   -> critical (90)

    Args:
        base_severity: The rule's declared severity.
        factors: Contextual adjustments, in the order they should be explained.

    Returns:
        A :class:`RiskAssessment` whose ``explanation`` lists the base score and
        every adjustment, so an analyst can always see how the number was built.
    """
    if base_severity not in BASE_SCORES:
        base_severity = Severity.MEDIUM
    base = BASE_SCORES[base_severity]

    explanation = [f"base {base}: rule severity is '{base_severity}'"]
    score = base
    for factor in factors or ():
        score += factor.points
        explanation.append(factor.describe())

    clamped = max(MIN_SCORE, min(MAX_SCORE, score))
    if clamped != score:
        explanation.append(f"clamped to {clamped} (valid range {MIN_SCORE}-{MAX_SCORE})")

    severity = severity_for_score(clamped)
    if severity != base_severity:
        explanation.append(f"final score {clamped} raises severity to '{severity}'"
                           if clamped > base else
                           f"final score {clamped} lowers severity to '{severity}'")
    return RiskAssessment(score=clamped, severity=severity, explanation=explanation)
