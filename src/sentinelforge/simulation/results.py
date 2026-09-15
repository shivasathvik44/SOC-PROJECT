"""Expected vs observed: the result model for scenario validation (Phase 8).

Everything Phase 8 reports is built out of one small type, :class:`Check`: an
expectation, an observation, and whether they matched.  There is no third
source of truth -- in particular there is no field anywhere in this package
that a scenario could set to declare itself passing.  A check passes when

    ``observed == expected``

and a stage passes when every check in it passed.  That is the only definition
used, so a scenario that stops detecting what it used to detect reports
``FAIL``, with the expectation and the observation printed side by side.

The vocabulary is deliberately blunt.  ``PASS``, ``FAIL`` and ``SKIP`` are the
only verdicts, and ``SKIP`` exists for one honest reason: a stage that could
not run (the optional Flask dependency is absent, a scenario declares no
containment target) must not be counted as a success.  A skipped stage is
reported as skipped everywhere, and never rolls up into a pass rate.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class Verdict:
    """The three outcomes a check or a stage can have."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"

    ALL = (PASS, FAIL, SKIP)


def _describe(value: object) -> object:
    """Render a value for a report without losing what it was."""
    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)
    if isinstance(value, tuple):
        return list(value)
    return value


@dataclass(frozen=True)
class Check:
    """One expectation compared against one observation.

    Attributes:
        name: What was checked, e.g. ``"detection.rules_fired"``.
        expected: What the scenario said should happen.
        observed: What the pipeline actually produced.
        passed: Whether they matched.  Set by the constructors below, never by
            a scenario.
        detail: Why it failed, or a clarifying note when it passed.
    """

    name: str
    expected: object
    observed: object
    passed: bool
    detail: str = ""

    @property
    def verdict(self) -> str:
        return Verdict.PASS if self.passed else Verdict.FAIL

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "expected": _describe(self.expected),
            "observed": _describe(self.observed),
            "result": self.verdict,
            "detail": self.detail,
        }

    def line(self) -> str:
        """One terminal line: what was wanted, what happened, and the verdict."""
        return (
            f"{self.verdict:4}  {self.name:38} "
            f"expected={_describe(self.expected)!r} observed={_describe(self.observed)!r}"
            + (f"  ({self.detail})" if self.detail else "")
        )


# -- check constructors ----------------------------------------------------
# Each one computes ``passed`` from the values themselves.  None of them takes
# a ``passed`` argument, which is what makes "hardcode the result" impossible
# to express in this package.
def equals(name: str, expected, observed, detail: str = "") -> Check:
    """Pass when ``observed`` equals ``expected``."""
    return Check(name, expected, observed, observed == expected, detail)


def contains_all(name: str, expected, observed, detail: str = "") -> Check:
    """Pass when every item of ``expected`` appears in ``observed``."""
    wanted, got = set(expected), set(observed)
    missing = sorted(wanted - got, key=str)
    return Check(
        name,
        wanted,
        got,
        not missing,
        detail or (f"missing: {', '.join(str(item) for item in missing)}" if missing else ""),
    )


def contains_none(name: str, forbidden, observed, detail: str = "") -> Check:
    """Pass when no item of ``forbidden`` appears in ``observed``."""
    banned, got = set(forbidden), set(observed)
    present = sorted(banned & got, key=str)
    return Check(
        name,
        f"none of {sorted(banned, key=str)}" if banned else "nothing forbidden",
        got,
        not present,
        detail
        or (f"unexpectedly fired: {', '.join(str(item) for item in present)}" if present else ""),
    )


def within(name: str, bounds: tuple[int, int], observed, detail: str = "") -> Check:
    """Pass when ``observed`` falls inside the inclusive ``bounds``."""
    low, high = bounds
    ok = isinstance(observed, (int, float)) and low <= observed <= high
    return Check(name, f"{low}-{high}", observed, ok, detail)


def is_true(name: str, observed: bool, expected_detail: str = "true", detail: str = "") -> Check:
    """Pass when ``observed`` is truthy."""
    return Check(name, expected_detail, bool(observed), bool(observed), detail)


@dataclass
class StageResult:
    """Every check belonging to one purple-team stage.

    Stages mirror the purple-team model: simulate, detect, investigate,
    respond, verify.  Grouping the checks this way is what lets a report say
    *where* the platform failed rather than only *that* it failed.
    """

    name: str
    checks: list[Check] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: str | None = None
    duration_ms: float = 0.0

    def add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    def skip(self, reason: str) -> "StageResult":
        self.skipped = True
        self.skip_reason = reason
        return self

    def fail(self, error: str) -> "StageResult":
        """Record that the stage itself blew up, which is never a pass."""
        self.error = error
        return self

    @property
    def verdict(self) -> str:
        if self.skipped:
            return Verdict.SKIP
        if self.error:
            return Verdict.FAIL
        if not self.checks:
            return Verdict.SKIP
        return Verdict.PASS if all(check.passed for check in self.checks) else Verdict.FAIL

    @property
    def passed(self) -> bool:
        return self.verdict == Verdict.PASS

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.passed]

    def to_dict(self) -> dict:
        return {
            "stage": self.name,
            "result": self.verdict,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 3),
            "checks_total": len(self.checks),
            "checks_passed": sum(1 for check in self.checks if check.passed),
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass
class ScenarioResult:
    """The outcome of running one scenario through the whole platform.

    Carries both the verdicts and the artefacts the verdicts were derived from
    (the events, alerts, incident, analysis and response action), so a caller
    can inspect what actually happened rather than trusting the summary.
    """

    scenario_id: str
    name: str
    kind: str
    description: str = ""
    notes: str = ""
    mitre_techniques: tuple[str, ...] = ()
    stages: list[StageResult] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    #: Artefacts, for callers that want to look at the real objects.
    events: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    incidents: list = field(default_factory=list)
    analysis: object | None = None
    action: object | None = None
    audit: list = field(default_factory=list)
    observed: dict = field(default_factory=dict)
    error: str | None = None

    def stage(self, name: str) -> StageResult:
        """Return (creating if needed) the stage with this name."""
        for existing in self.stages:
            if existing.name == name:
                return existing
        created = StageResult(name)
        self.stages.append(created)
        return created

    # -- roll-ups ----------------------------------------------------------
    @property
    def checks(self) -> list[Check]:
        return [check for stage in self.stages for check in stage.checks]

    @property
    def checks_passed(self) -> int:
        return sum(1 for check in self.checks if check.passed)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if not check.passed]

    @property
    def verdict(self) -> str:
        if self.error:
            return Verdict.FAIL
        graded = [stage for stage in self.stages if not stage.skipped]
        if not graded:
            return Verdict.SKIP
        return Verdict.PASS if all(stage.passed for stage in graded) else Verdict.FAIL

    @property
    def passed(self) -> bool:
        return self.verdict == Verdict.PASS

    @property
    def total_ms(self) -> float:
        """Wall time across the measured pipeline stages."""
        return round(sum(self.timings.values()), 3)

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "notes": self.notes,
            "mitre_techniques": list(self.mitre_techniques),
            "result": self.verdict,
            "checks_total": len(self.checks),
            "checks_passed": self.checks_passed,
            "error": self.error,
            "stages": [stage.to_dict() for stage in self.stages],
            "timings_ms": {key: round(value, 3) for key, value in self.timings.items()},
            "total_ms": self.total_ms,
            "observed": self.observed,
        }
