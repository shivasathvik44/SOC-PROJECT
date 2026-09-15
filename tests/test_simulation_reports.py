"""Phase 8: the generated reports.

The reports are the artefact someone will read instead of running anything, so
the property that matters is that they cannot flatter the system. These tests
feed the renderers *failing* results and assert the failure is in the output,
feed them skipped stages and assert those are not counted as passes, and check
that no number in a report is a literal rather than a measurement.
"""

import json

import pytest

from sentinelforge.simulation.benchmark import run_benchmark
from sentinelforge.simulation.report import (
    ValidationSummary,
    coverage_rows,
    render_assessment_markdown,
    render_benchmark_markdown,
    render_coverage_markdown,
    write_reports,
)
from sentinelforge.simulation.results import ScenarioResult, equals
from sentinelforge.simulation.runner import ScenarioRunner
from sentinelforge.simulation.security import run_security_probes


@pytest.fixture(scope="module")
def real_results():
    return ScenarioRunner().run_all()


def _failing_result(scenario_id="broken") -> ScenarioResult:
    result = ScenarioResult(scenario_id, "Broken Scenario", "attack")
    stage = result.stage("detection")
    stage.add(equals("detection.alert_count", 3, 0))
    stage.add(equals("detection.rules_fired", {"SSH_BRUTE_FORCE"}, set()))
    result.observed = {"alert_count": 0, "incident_count": 0, "rule_ids": []}
    return result


def _noisy_benign(scenario_id="noisy-benign") -> ScenarioResult:
    result = ScenarioResult(scenario_id, "Noisy Benign", "benign")
    result.stage("detection").add(equals("detection.alert_count", 0, 2))
    result.observed = {"alert_count": 2, "incident_count": 1, "rule_ids": ["SUSPICIOUS_SUDO"]}
    return result


class TestSummaryCounts:
    def test_counts_are_derived_from_the_results(self, real_results):
        summary = ValidationSummary(scenarios=real_results)
        assert summary.total == len(real_results)
        assert len(summary.passed) + len(summary.failed) + len(summary.skipped) == summary.total
        assert summary.checks_total == sum(len(r.checks) for r in real_results)

    def test_a_failing_scenario_makes_the_summary_fail(self, real_results):
        summary = ValidationSummary(scenarios=list(real_results) + [_failing_result()])
        assert not summary.ok
        assert summary.failed

    def test_a_false_positive_is_detected_from_observation(self):
        summary = ValidationSummary(scenarios=[_noisy_benign()])
        assert summary.false_positives == [("noisy-benign", ["SUSPICIOUS_SUDO"])]

    def test_a_false_negative_is_detected_from_observation(self):
        summary = ValidationSummary(scenarios=[_failing_result()])
        assert summary.false_negatives
        assert summary.false_negatives[0][0] == "broken"

    def test_untested_rules_are_named_not_omitted(self):
        """The denominator is every shipped rule, not only the tested ones."""
        summary = ValidationSummary(scenarios=[_failing_result()])
        assert "SSH_BRUTE_FORCE" in summary.untested_rules
        assert summary.tested_rules == []

    def test_a_real_run_exercises_every_rule(self, real_results):
        summary = ValidationSummary(scenarios=real_results)
        assert summary.untested_rules == []

    def test_measured_gaps_come_from_observations(self, real_results):
        summary = ValidationSummary(scenarios=real_results)
        gaps = dict(summary.measured_gaps)
        assert "process-chain" in gaps
        assert "process tree omitted" in gaps["process-chain"]


class TestCoverageReport:
    def test_a_row_per_scenario(self, real_results):
        rows = coverage_rows(real_results)
        assert len(rows) == len(real_results)
        assert {row["scenario_id"] for row in rows} == {
            r.scenario_id for r in real_results
        }

    def test_skipped_stages_are_marked_skip_not_pass(self, real_results):
        rows = {row["scenario_id"]: row for row in coverage_rows(real_results)}
        assert rows["benign-sudo"]["investigation"] == "SKIP"
        assert rows["suspicious-sudo"]["response"] == "SKIP"

    def test_the_markdown_says_what_passed_and_what_was_not_tested(self, real_results):
        markdown = render_coverage_markdown(ValidationSummary(scenarios=real_results))
        assert "## Detection rules" in markdown
        assert "TESTED" in markdown and "NOT TESTED" in markdown
        assert "full-attack" in markdown

    def test_a_failure_appears_in_the_markdown_with_both_sides(self, real_results):
        summary = ValidationSummary(scenarios=list(real_results) + [_failing_result()])
        markdown = render_coverage_markdown(summary)
        assert "### broken" in markdown
        assert "detection.alert_count" in markdown
        assert "expected `3`" in markdown and "observed `0`" in markdown

    def test_the_pass_rate_is_computed_not_asserted(self):
        summary = ValidationSummary(scenarios=[_failing_result()])
        markdown = render_coverage_markdown(summary)
        assert "0 / 2" in markdown and "(0.0%)" in markdown


class TestAssessment:
    def test_a_clean_run_still_refuses_to_claim_production_readiness(self, real_results):
        markdown = render_assessment_markdown(
            ValidationSummary(scenarios=real_results, probes=run_security_probes())
        )
        assert "not the same as being production ready" in markdown
        assert "NOT TESTED" in markdown
        assert "Real eBPF kernel probes" in markdown
        assert "hosted language model" in markdown

    def test_a_false_positive_is_named_in_the_assessment(self):
        summary = ValidationSummary(scenarios=[_noisy_benign()])
        markdown = render_assessment_markdown(summary)
        assert "## False positives" in markdown
        assert "noisy-benign" in markdown
        assert "SUSPICIOUS_SUDO" in markdown

    def test_a_clean_run_says_so_without_overclaiming(self, real_results):
        markdown = render_assessment_markdown(ValidationSummary(scenarios=real_results))
        assert "not all benign activity" in markdown

    def test_measured_gaps_are_listed(self, real_results):
        markdown = render_assessment_markdown(ValidationSummary(scenarios=real_results))
        assert "## Gaps this run measured" in markdown
        assert "process tree omitted" in markdown

    def test_containment_is_labelled_as_mocked(self, real_results):
        markdown = render_assessment_markdown(ValidationSummary(scenarios=real_results))
        assert "in-memory mock backends" in markdown
        assert "No firewall rule, signal or session was touched" in markdown

    def test_the_overall_verdict_follows_the_results(self, real_results):
        clean = render_assessment_markdown(ValidationSummary(scenarios=real_results))
        assert "**Overall result: PASS**" in clean
        broken = render_assessment_markdown(
            ValidationSummary(scenarios=list(real_results) + [_failing_result()])
        )
        assert "**Overall result: FAIL**" in broken


class TestBenchmarkReport:
    def test_the_markdown_carries_the_measurements(self):
        report = run_benchmark(sizes=(100,), measure_memory=False)
        markdown = render_benchmark_markdown(report)
        assert "## Throughput" in markdown
        assert "| 100 |" in markdown
        assert "perf_counter" in markdown
        assert "not measured" in markdown

    def test_the_environment_is_recorded(self):
        markdown = render_benchmark_markdown(run_benchmark(sizes=(50,), measure_memory=False))
        import platform

        assert platform.python_version() in markdown


class TestWriteReports:
    def test_every_file_is_written_and_is_valid(self, tmp_path, real_results):
        paths = write_reports(
            str(tmp_path),
            real_results,
            benchmark=run_benchmark(sizes=(100,), measure_memory=False),
            probes=run_security_probes(str(tmp_path / "probe.db")),
        )
        assert len(paths) == 7
        for path in paths:
            assert path.endswith((".json", ".md"))
            content = open(path, encoding="utf-8").read()
            assert content.strip()
            if path.endswith(".json"):
                json.loads(content)

    def test_the_json_coverage_matches_the_markdown(self, tmp_path, real_results):
        write_reports(str(tmp_path), real_results)
        payload = json.loads((tmp_path / "detection-coverage.json").read_text())
        markdown = (tmp_path / "detection-coverage.md").read_text()
        assert payload["scenarios_total"] == len(real_results)
        assert f"**{payload['scenarios_total']}**" in markdown
        assert payload["result"] == "PASS"

    def test_the_scenario_dump_records_expectation_and_observation(
        self, tmp_path, real_results
    ):
        write_reports(str(tmp_path), real_results)
        payload = json.loads((tmp_path / "attack-scenarios.json").read_text())
        full = next(s for s in payload["scenarios"] if s["scenario_id"] == "full-attack")
        assert full["observed"]["alert_count"] == 5
        checks = [c for stage in full["stages"] for c in stage["checks"]]
        assert any(c["name"] == "detection.alert_count" for c in checks)
        assert all("expected" in c and "observed" in c for c in checks)

    def test_reports_can_be_written_for_a_benchmark_alone(self, tmp_path):
        paths = write_reports(
            str(tmp_path), results=(), benchmark=run_benchmark(sizes=(50,), measure_memory=False)
        )
        assert any(path.endswith("benchmark.md") for path in paths)
