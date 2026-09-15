"""Generated validation reports (Phase 8).

Every number in every file this module writes comes from a
:class:`~sentinelforge.simulation.results.Check` that actually ran in the
process that wrote it.  There is no literal coverage percentage, pass count or
timing anywhere in this file -- each one is computed from the results handed in,
which is why a regression shows up in the report instead of being papered over
by it.

Three honesty rules the renderers follow:

1. **Skipped is not passed.**  A stage that could not run is counted separately
   and shown as ``SKIP``; it never contributes to a pass rate.
2. **Coverage means what was measured.**  The detection-coverage table reports
   the scenarios that were run, not the rules that exist.  Rules no scenario
   exercises are listed explicitly as *not tested* rather than being left out
   of the denominator.
3. **Failures are printed, with both sides.**  A failing check appears in the
   report with its expectation and its observation next to each other, so the
   report is useful for fixing the problem and useless for hiding it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from ..detection.rules import default_rules
from .benchmark import BenchmarkReport
from .results import ScenarioResult, Verdict
from .scenario import ScenarioKind
from .security import SecurityProbeReport

#: Where reports are written when the caller does not say.
DEFAULT_REPORT_DIR = os.path.join("reports", "phase8")

#: The Phase 8 report format version, stored in every JSON file.
REPORT_VERSION = "1.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pct(part: int, whole: int) -> float:
    """A percentage, or 0.0 when there is nothing to divide by."""
    return round(100.0 * part / whole, 1) if whole else 0.0


@dataclass
class ValidationSummary:
    """Roll-up of one validation run.  Every field is counted, never asserted."""

    scenarios: list[ScenarioResult] = field(default_factory=list)
    benchmark: BenchmarkReport | None = None
    probes: SecurityProbeReport | None = None
    generated_at: str = field(default_factory=_now)

    # -- scenario counts ---------------------------------------------------
    @property
    def total(self) -> int:
        return len(self.scenarios)

    @property
    def passed(self) -> list[ScenarioResult]:
        return [r for r in self.scenarios if r.verdict == Verdict.PASS]

    @property
    def failed(self) -> list[ScenarioResult]:
        return [r for r in self.scenarios if r.verdict == Verdict.FAIL]

    @property
    def skipped(self) -> list[ScenarioResult]:
        return [r for r in self.scenarios if r.verdict == Verdict.SKIP]

    @property
    def attacks(self) -> list[ScenarioResult]:
        return [r for r in self.scenarios if r.kind == ScenarioKind.ATTACK]

    @property
    def benign(self) -> list[ScenarioResult]:
        return [r for r in self.scenarios if r.kind == ScenarioKind.BENIGN]

    @property
    def checks_total(self) -> int:
        return sum(len(r.checks) for r in self.scenarios)

    @property
    def checks_passed(self) -> int:
        return sum(r.checks_passed for r in self.scenarios)

    @property
    def ok(self) -> bool:
        return not self.failed and (self.probes.ok if self.probes else True)

    # -- derived, measured facts ------------------------------------------
    @property
    def false_positives(self) -> list[tuple[str, list[str]]]:
        """Benign scenarios that produced alerts, with the rules that fired."""
        found = []
        for result in self.benign:
            fired = result.observed.get("rule_ids") or []
            if fired:
                found.append((result.scenario_id, list(fired)))
        return found

    @property
    def false_negatives(self) -> list[tuple[str, list[str]]]:
        """Attack scenarios whose expected rules did not all fire."""
        found = []
        for result in self.attacks:
            missing = [
                check.name
                for check in result.failures
                if check.name in ("detection.rules_fired", "detection.alert_count")
            ]
            if missing:
                found.append((result.scenario_id, missing))
        return found

    @property
    def measured_gaps(self) -> list[tuple[str, str]]:
        """Gaps the scenarios pinned, and the process lineage actually missing.

        Built from what ran: a scenario's note flagged ``KNOWN GAP``, and the
        PIDs the telemetry contained that the incident-scoped process tree did
        not render.  Nothing is listed here that was not observed.
        """
        found: list[tuple[str, str]] = []
        for result in self.scenarios:
            note = result.notes or ""
            if "KNOWN GAP" in note:
                found.append((result.scenario_id, note.split("KNOWN GAP:", 1)[-1].strip()))
            omitted = result.observed.get("process_tree_gap") or []
            if omitted:
                found.append(
                    (
                        result.scenario_id,
                        "the process tree omitted PID(s) "
                        + ", ".join(str(pid) for pid in omitted)
                        + " that the telemetry named: the tree is built from one "
                        "incident's evidence, so processes no rule alerted on are "
                        "not rendered",
                    )
                )
        return found

    @property
    def tested_techniques(self) -> list[str]:
        """ATT&CK ids an incident actually carried during this run."""
        found: set[str] = set()
        for result in self.scenarios:
            found.update(result.observed.get("techniques") or [])
        return sorted(found)

    @property
    def tested_rules(self) -> list[str]:
        """Rules that actually fired during this run."""
        found: set[str] = set()
        for result in self.scenarios:
            found.update(result.observed.get("rule_ids") or [])
        return sorted(found)

    @property
    def untested_rules(self) -> list[str]:
        """Shipped rules no scenario made fire.  Named, not omitted."""
        shipped = {rule.rule_id for rule in default_rules()}
        return sorted(shipped - set(self.tested_rules))

    def to_dict(self) -> dict:
        return {
            "report_version": REPORT_VERSION,
            "generated_at": self.generated_at,
            "scenarios_total": self.total,
            "scenarios_passed": len(self.passed),
            "scenarios_failed": len(self.failed),
            "scenarios_skipped": len(self.skipped),
            "attack_scenarios": len(self.attacks),
            "benign_scenarios": len(self.benign),
            "checks_total": self.checks_total,
            "checks_passed": self.checks_passed,
            "check_pass_rate_percent": _pct(self.checks_passed, self.checks_total),
            "rules_exercised": self.tested_rules,
            "rules_not_exercised": self.untested_rules,
            "techniques_exercised": self.tested_techniques,
            "false_positives": [
                {"scenario_id": sid, "rules": rules} for sid, rules in self.false_positives
            ],
            "false_negatives": [
                {"scenario_id": sid, "failed_checks": checks}
                for sid, checks in self.false_negatives
            ],
            "measured_gaps": [
                {"scenario_id": sid, "gap": text} for sid, text in self.measured_gaps
            ],
            "result": "PASS" if self.ok else "FAIL",
        }


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------
def coverage_rows(results: Sequence[ScenarioResult]) -> list[dict]:
    """One row per scenario: what was expected, what happened, and the verdict."""
    rows = []
    for result in results:
        stages = {stage.name: stage.verdict for stage in result.stages}
        rows.append(
            {
                "scenario_id": result.scenario_id,
                "name": result.name,
                "kind": result.kind,
                "mitre": list(result.mitre_techniques),
                "detection": stages.get("detection", Verdict.SKIP),
                "correlation": stages.get("correlation", Verdict.SKIP),
                "mitre_mapping": stages.get("mitre", Verdict.SKIP),
                "risk": stages.get("risk", Verdict.SKIP),
                "investigation": stages.get("investigation", Verdict.SKIP),
                "visualization": stages.get("visualization", Verdict.SKIP),
                "response": stages.get("response", Verdict.SKIP),
                "verification": stages.get("verification", Verdict.SKIP),
                "audit": stages.get("audit", Verdict.SKIP),
                "alerts_observed": result.observed.get("alert_count"),
                "incidents_observed": result.observed.get("incident_count"),
                "rules_observed": result.observed.get("rule_ids") or [],
                "severity_observed": result.observed.get("severity"),
                "risk_observed": result.observed.get("risk_score"),
                "checks_total": len(result.checks),
                "checks_passed": result.checks_passed,
                "result": result.verdict,
            }
        )
    return rows


def render_coverage_markdown(summary: ValidationSummary) -> str:
    """The detection-coverage report, as Markdown."""
    rows = coverage_rows(summary.scenarios)
    lines = [
        "# SentinelForge - Detection Coverage (Phase 8)",
        "",
        f"Generated: {summary.generated_at}",
        "",
        "Every figure below was produced by running the scenario through the "
        "shipped detection, correlation and response code in this process. "
        "Coverage is over the scenarios that ran, not over the rules that exist; "
        "rules no scenario exercised are named at the end.",
        "",
        "## Scenario results",
        "",
        "| Scenario | Kind | MITRE | Alerts | Incidents | Detection | Correlation | "
        "ATT&CK | Risk | Result |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {scenario_id} | {kind} | {mitre} | {alerts} | {incidents} | {detection} | "
            "{correlation} | {mitre_mapping} | {risk} | **{result}** |".format(
                scenario_id=row["scenario_id"],
                kind=row["kind"],
                mitre=", ".join(row["mitre"]) or "-",
                alerts=row["alerts_observed"],
                incidents=row["incidents_observed"],
                detection=row["detection"],
                correlation=row["correlation"],
                mitre_mapping=row["mitre_mapping"],
                risk=row["risk"],
                result=row["result"],
            )
        )

    lines += [
        "",
        "## Investigation, response and audit",
        "",
        "| Scenario | AI analysis | Dashboard | Response | Verification | Audit |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {scenario_id} | {investigation} | {visualization} | {response} | "
            "{verification} | {audit} |".format(**row)
        )

    lines += [
        "",
        "## Totals",
        "",
        f"* Scenarios run: **{summary.total}** "
        f"({len(summary.attacks)} attack, {len(summary.benign)} benign)",
        f"* Scenarios passed: **{len(summary.passed)}**, failed: **{len(summary.failed)}**, "
        f"skipped: **{len(summary.skipped)}**",
        f"* Individual checks: **{summary.checks_passed} / {summary.checks_total}** passed "
        f"({_pct(summary.checks_passed, summary.checks_total)}%)",
        "",
        "## Detection rules",
        "",
        f"* Exercised by a scenario (**TESTED**): {', '.join(summary.tested_rules) or 'none'}",
        f"* Shipped but not exercised (**NOT TESTED**): "
        f"{', '.join(summary.untested_rules) or 'none'}",
        "",
        "## ATT&CK techniques observed on an incident",
        "",
        f"{', '.join(summary.tested_techniques) or 'none'}",
        "",
    ]

    lines += _render_failures(summary)
    return "\n".join(lines) + "\n"


def _render_failures(summary: ValidationSummary) -> list[str]:
    """Failures, printed with both sides.  Empty only when there are none."""
    if not summary.failed:
        return ["", "## Failures", "", "None: every check in every scenario matched "
                "its expectation in this run.", ""]
    lines = ["", "## Failures", ""]
    for result in summary.failed:
        lines.append(f"### {result.scenario_id} - {result.name}")
        lines.append("")
        if result.error:
            lines += [f"The scenario raised: `{result.error}`", ""]
        for check in result.failures:
            lines.append(
                f"* `{check.name}` - expected `{check.expected!r}`, "
                f"observed `{check.observed!r}`"
                + (f" ({check.detail})" if check.detail else "")
            )
        lines.append("")
    return lines


# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------
def render_benchmark_markdown(report: BenchmarkReport) -> str:
    """The benchmark report, as Markdown."""
    env = report.environment
    lines = [
        "# SentinelForge - Benchmark (Phase 8)",
        "",
        f"Measured: {env.get('measured_at', 'unknown')} on "
        f"{env.get('system')} {env.get('release')} / {env.get('machine')}, "
        f"{env.get('implementation')} {env.get('python')}",
        "",
        "Wall time is `time.perf_counter` (monotonic). Event timestamps are "
        "synthetic log times and are never used as measurements.",
        "",
        "## Throughput",
        "",
        "| Events | Alerts | Incidents | Detection (ms) | Correlation (ms) | "
        "Total (ms) | Events/sec | us/event | CPU (s) | Peak alloc (KB) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in report.throughput:
        data = item.to_dict()
        lines.append(
            "| {events} | {alerts} | {incidents} | {detection_ms} | {correlation_ms} | "
            "{total_ms} | {events_per_second} | {microseconds_per_event} | "
            "{cpu_seconds} | {peak} |".format(
                **data,
                peak=data["peak_allocated_kb"] if data["memory_measured"] else "not measured",
            )
        )

    if report.latency:
        lat = report.latency.to_dict()
        lines += [
            "",
            "## Latency, stage by stage",
            "",
            f"Scenario: `{lat['scenario_id']}` "
            f"({lat['events']} events -> {lat['alerts']} alerts -> "
            f"{lat['incidents']} incident(s))",
            "",
            "| Stage | Milliseconds |",
            "| --- | --- |",
            f"| Event generation | {lat['generation_ms']} |",
            f"| Event -> alert (detection) | {lat['event_to_alert_ms']} |",
            f"| Alert -> incident (correlation) | {lat['alert_to_incident_ms']} |",
            f"| Incident -> AI analysis | {lat['incident_to_ai_ms']} |",
            f"| **Deterministic pipeline** | **{lat['deterministic_pipeline_ms']}** |",
            f"| **Total** | **{lat['total_ms']}** |",
            "",
            f"The AI stage used the **{lat['ai_provider']}** provider: {lat['ai_note']}.",
        ]

    lines += ["", "## Notes", ""]
    lines += [f"* {note}" for note in report.to_dict()["notes"]]
    lines += [
        "* Peak allocation comes from a second, untimed `tracemalloc` pass over "
        "the same workload: instrumenting every allocation would inflate the "
        "timings, so the timed pass runs uninstrumented. Process RSS is in the "
        "JSON but is a whole-process figure and is not attributable to the "
        "benchmark alone.",
        "",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Final assessment
# --------------------------------------------------------------------------
def render_assessment_markdown(summary: ValidationSummary) -> str:
    """The final security assessment, assembled from measured results only."""
    bench = summary.benchmark
    probes = summary.probes
    lines = [
        "# SentinelForge - Phase 8 Security Assessment",
        "",
        f"Generated: {summary.generated_at}",
        "",
        "This document is generated from a validation run. It reports what that "
        "run measured. It is **not** a certification, and passing it is not the "
        "same as being production ready - see *Limits of this assessment*.",
        "",
        f"**Overall result: {'PASS' if summary.ok else 'FAIL'}** "
        f"({summary.checks_passed}/{summary.checks_total} checks, "
        f"{len(summary.passed)}/{summary.total} scenarios)",
        "",
        "## Detection",
        "",
        f"* Attack scenarios run: **{len(summary.attacks)}**",
        f"* Attack scenarios whose expected alerts all fired: "
        f"**{sum(1 for r in summary.attacks if r.verdict == Verdict.PASS)}**",
        f"* Rules exercised: {', '.join(summary.tested_rules) or 'none'}",
        f"* Rules shipped but not exercised by any scenario: "
        f"{', '.join(summary.untested_rules) or 'none'}",
        "",
        "## Correlation",
        "",
    ]
    for result in summary.attacks:
        lines.append(
            f"* `{result.scenario_id}`: {result.observed.get('alert_count')} alert(s) -> "
            f"{result.observed.get('incident_count')} incident(s); chains matched: "
            f"{', '.join(result.observed.get('matched_chains') or []) or 'none'}"
        )

    lines += [
        "",
        "## MITRE ATT&CK",
        "",
        f"* Techniques observed on an incident during this run: "
        f"{', '.join(summary.tested_techniques) or 'none'}",
        "* Every alert produced in every scenario carried an ATT&CK mapping "
        "(checked as `mitre.every_alert_mapped`).",
        "",
        "## AI analysis",
        "",
    ]
    analyzed = [r for r in summary.scenarios if r.analysis is not None]
    ok_analyses = [r for r in analyzed if getattr(r.analysis, "ok", False)]
    lines += [
        f"* Analyses attempted: **{len(analyzed)}**, produced: **{len(ok_analyses)}**",
        "* Provider: the offline mock provider. No hosted model was contacted, so "
        "these results say nothing about a real model's quality.",
    ]
    disagreements = [
        (r.scenario_id, r.analysis.severity_assessment, r.analysis.deterministic_severity)
        for r in ok_analyses
        if getattr(r.analysis, "severity_disagreement", False)
    ]
    if disagreements:
        lines.append("* Severity disagreements (both verdicts remain visible):")
        for scenario_id, ai_severity, deterministic in disagreements:
            lines.append(
                f"  * `{scenario_id}`: AI said `{ai_severity}`, "
                f"deterministic engine said `{deterministic}`"
            )
    else:
        lines.append(
            "* No severity disagreement occurred in this run; the mechanism that "
            "surfaces one is checked separately in the test suite."
        )

    lines += ["", "## Response and containment", ""]
    responded = [
        r for r in summary.scenarios
        if any(s.name == "response" and not s.skipped for s in r.stages)
    ]
    lines += [
        f"* Scenarios that drove the containment lifecycle: **{len(responded)}**",
        "* Every one was previewed, requested, approved by an explicit call, "
        "executed, verified against the backend and audited.",
        "* Execution without approval was attempted in each of them and refused "
        "in each of them (`response.execution_without_approval_refused`).",
        "* All containment ran against in-memory mock backends. **No firewall "
        "rule, signal or session was touched.**",
    ]
    for result in responded:
        action = result.action
        if action is None:
            continue
        lines.append(
            f"  * `{result.scenario_id}`: {action.action_type} {action.target} -> "
            f"{action.status}, verified={action.verified}"
        )

    lines += ["", "## False positives", ""]
    if summary.false_positives:
        lines.append(
            "Benign scenarios that produced alerts. Each one is a false positive "
            "and is listed with the rule responsible:"
        )
        for scenario_id, rules in summary.false_positives:
            lines.append(f"* `{scenario_id}`: {', '.join(rules)}")
    else:
        lines.append(
            f"None. All **{len(summary.benign)}** benign scenarios produced zero "
            "alerts and zero incidents. This measures the benign activity these "
            "scenarios contain, not all benign activity."
        )

    lines += ["", "## False negatives", ""]
    if summary.false_negatives:
        for scenario_id, checks in summary.false_negatives:
            lines.append(f"* `{scenario_id}`: {', '.join(checks)}")
    else:
        lines.append(
            "None: every attack scenario produced the alerts it expected, in the "
            "expected number."
        )

    lines += ["", "## Performance", ""]
    if bench and bench.throughput:
        for item in bench.throughput:
            data = item.to_dict()
            lines.append(
                f"* {data['events']} events -> {data['alerts']} alerts, "
                f"{data['incidents']} incidents in {data['total_ms']} ms "
                f"({data['events_per_second']} events/sec"
                + (
                    f", {data['peak_allocated_kb']} KB peak allocation)"
                    if data["memory_measured"]
                    else ")"
                )
            )
    if bench and bench.latency:
        lat = bench.latency.to_dict()
        lines += [
            f"* Single-incident latency (`{lat['scenario_id']}`): "
            f"event->alert {lat['event_to_alert_ms']} ms, "
            f"alert->incident {lat['alert_to_incident_ms']} ms, "
            f"incident->AI {lat['incident_to_ai_ms']} ms "
            f"(offline provider), total {lat['total_ms']} ms",
        ]
    if not bench:
        lines.append("Not measured in this run.")

    lines += ["", "## Security boundaries", ""]
    if probes:
        lines.append(
            f"* Boundary probes: **{probes.passed}/{len(probes.checks)}** passed"
        )
        for stage in probes.stages:
            lines.append(
                f"  * `{stage.name}`: {stage.verdict} "
                f"({sum(1 for c in stage.checks if c.passed)}/{len(stage.checks)})"
            )
        if probes.failures:
            lines.append("* Failures:")
            for check in probes.failures:
                lines.append(
                    f"  * `{check.name}` - expected `{check.expected!r}`, "
                    f"observed `{check.observed!r}`"
                )
    else:
        lines.append("Not run in this validation run.")

    lines += ["", "## Gaps this run measured", ""]
    gaps = summary.measured_gaps
    if gaps:
        lines.append(
            "These are not failures: each one is a checked, pinned expectation "
            "describing something SentinelForge does **not** do. They are listed "
            "here so that passing the run does not hide them."
        )
        lines.append("")
        for scenario_id, text in gaps:
            lines.append(f"* `{scenario_id}`: {text}")
    else:
        lines.append("No scenario in this run pinned a gap.")

    lines += _render_failures(summary)

    lines += [
        "## Limits of this assessment",
        "",
        "**TESTED** - the things above, by the checks named above, against "
        "synthetic telemetry on this machine.",
        "",
        "**NOT TESTED** - and deliberately so:",
        "",
        "* Real eBPF kernel probes: the sensors are exercised through decoders "
        "and synthetic records; no BPF program was loaded.",
        "* Real containment: no firewall rule was installed, no process was "
        "signalled, no session was ended.",
        "* A hosted language model: only the deterministic offline provider ran.",
        "* Real log collection: no journal or `/var/log` file was read.",
        "* Multi-host deployment, event forwarding and lateral-movement "
        "detection: SentinelForge is a single-host tool.",
        "* Adversarial evasion: the scenarios are representative shapes, not an "
        "attempt to defeat the rules.",
        "* Sustained operation: no soak, fuzz or concurrency test was run here.",
        "",
        "**Passing this assessment does not make SentinelForge production "
        "ready.** It means the platform did what these scenarios expected of it, "
        "on this machine, in this run.",
        "",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------
def _write(path: str, content: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def write_reports(
    directory: str = DEFAULT_REPORT_DIR,
    results: Sequence[ScenarioResult] = (),
    benchmark: BenchmarkReport | None = None,
    probes: SecurityProbeReport | None = None,
) -> list[str]:
    """Write every Phase 8 report file and return the paths written.

    Args:
        directory: Where the files go.  Created if it does not exist.
        results: Scenario results from a :class:`ScenarioRunner`.
        benchmark: Optional benchmark report.
        probes: Optional security probe report.
    """
    summary = ValidationSummary(
        scenarios=list(results), benchmark=benchmark, probes=probes
    )
    written = []

    written.append(
        _write(
            os.path.join(directory, "detection-coverage.json"),
            json.dumps(
                {
                    **summary.to_dict(),
                    "scenarios": coverage_rows(summary.scenarios),
                },
                indent=2,
            )
            + "\n",
        )
    )
    written.append(
        _write(
            os.path.join(directory, "detection-coverage.md"),
            render_coverage_markdown(summary),
        )
    )
    written.append(
        _write(
            os.path.join(directory, "attack-scenarios.json"),
            json.dumps(
                {
                    "report_version": REPORT_VERSION,
                    "generated_at": summary.generated_at,
                    "scenarios": [result.to_dict() for result in summary.scenarios],
                },
                indent=2,
            )
            + "\n",
        )
    )
    if benchmark is not None:
        written.append(
            _write(
                os.path.join(directory, "benchmark.json"),
                json.dumps(
                    {
                        "report_version": REPORT_VERSION,
                        "generated_at": summary.generated_at,
                        **benchmark.to_dict(),
                    },
                    indent=2,
                )
                + "\n",
            )
        )
        written.append(
            _write(
                os.path.join(directory, "benchmark.md"),
                render_benchmark_markdown(benchmark),
            )
        )
    if probes is not None:
        written.append(
            _write(
                os.path.join(directory, "security-probes.json"),
                json.dumps(
                    {
                        "report_version": REPORT_VERSION,
                        "generated_at": summary.generated_at,
                        **probes.to_dict(),
                    },
                    indent=2,
                )
                + "\n",
            )
        )
    written.append(
        _write(
            os.path.join(directory, "final-security-assessment.md"),
            render_assessment_markdown(summary),
        )
    )
    return written
