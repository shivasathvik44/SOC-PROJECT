"""Phase 8: the purple-team run itself.

Every scenario, through the whole platform, with the verdicts asserted here
rather than only printed by the CLI.  This is the file that fails when a change
to a detection rule, the correlation engine, the risk model, the serializers or
the response lifecycle alters what SentinelForge concludes about a known
attack.

The tests are deliberately phrased as *the platform must still do this*, not as
*the runner must return PASS*: a failure names the scenario, the check, the
expectation and the observation.
"""

import pytest

from sentinelforge.simulation.results import Verdict
from sentinelforge.simulation.runner import ScenarioRunner
from sentinelforge.simulation.scenarios import (
    all_scenarios,
    attack_scenarios,
    benign_scenarios,
)


@pytest.fixture(scope="module")
def results():
    """One run of every scenario, shared by the tests in this module."""
    return {result.scenario_id: result for result in ScenarioRunner().run_all()}


def _report(result) -> str:
    lines = [f"{result.scenario_id} -> {result.verdict}"]
    if result.error:
        lines.append(f"  scenario raised: {result.error}")
    lines += [f"  {check.line()}" for check in result.failures]
    return "\n".join(lines)


class TestEveryScenario:
    @pytest.mark.parametrize("scenario_id", [s.scenario_id for s in all_scenarios()])
    def test_scenario_matches_its_expectation(self, results, scenario_id):
        result = results[scenario_id]
        assert result.verdict == Verdict.PASS, "\n" + _report(result)

    @pytest.mark.parametrize("scenario_id", [s.scenario_id for s in all_scenarios()])
    def test_no_stage_was_silently_skipped_for_an_attack(self, results, scenario_id):
        """Skips are allowed, but only for reasons the scenario declares."""
        result = results[scenario_id]
        for stage in result.stages:
            if stage.skipped:
                assert stage.skip_reason, f"{scenario_id}/{stage.name} skipped with no reason"


class TestDetectionCoverage:
    def test_each_attack_scenario_produced_its_alerts(self, results):
        for scenario in attack_scenarios():
            result = results[scenario.scenario_id]
            fired = set(result.observed.get("rule_ids") or [])
            assert scenario.expected.rule_ids <= fired, _report(result)

    def test_every_rule_fired_at_least_once_across_the_suite(self, results):
        from sentinelforge.detection.rules import default_rules

        fired = set()
        for result in results.values():
            fired |= set(result.observed.get("rule_ids") or [])
        shipped = {rule.rule_id for rule in default_rules()}
        assert shipped <= fired, f"never fired: {sorted(shipped - fired)}"

    def test_every_alert_carries_an_attack_mapping(self, results):
        for result in results.values():
            for alert in result.alerts:
                assert alert.mitre, f"{result.scenario_id}/{alert.rule_id} has no mapping"


class TestFalsePositives:
    @pytest.mark.parametrize("scenario_id", [s.scenario_id for s in benign_scenarios()])
    def test_benign_activity_raises_no_alert(self, results, scenario_id):
        result = results[scenario_id]
        fired = result.observed.get("rule_ids") or []
        assert not fired, (
            f"{scenario_id} is ordinary activity but raised: {', '.join(fired)}. "
            "That is a false positive; fix the rule or document why the "
            "behaviour is genuinely suspicious - do not weaken the scenario."
        )

    @pytest.mark.parametrize("scenario_id", [s.scenario_id for s in benign_scenarios()])
    def test_benign_activity_creates_no_incident(self, results, scenario_id):
        assert results[scenario_id].observed.get("incident_count") == 0

    def test_the_suite_measures_a_false_positive_rate_from_real_runs(self, results):
        benign = [results[s.scenario_id] for s in benign_scenarios()]
        noisy = [r.scenario_id for r in benign if r.observed.get("alert_count")]
        assert not noisy, f"false positives in: {noisy}"
        assert len(benign) >= 5, "false-positive testing needs a meaningful sample"


class TestCorrelationIsOneStory:
    def test_the_full_attack_becomes_exactly_one_incident(self, results):
        result = results["full-attack"]
        assert result.observed["alert_count"] == 5
        assert result.observed["incident_count"] == 1

    def test_the_full_attack_matches_the_multi_stage_chains(self, results):
        chains = set(results["full-attack"].observed["matched_chains"])
        assert "AUTH_THEN_PROCESS_THEN_NETWORK" in chains
        assert "POSSIBLE_ACCOUNT_COMPROMISE" in chains

    def test_a_failure_only_burst_is_not_reported_as_a_compromise(self, results):
        fired = results["ssh-bruteforce"].observed["rule_ids"]
        assert "SSH_COMPROMISE_SUSPECTED" not in fired
        assert results["ssh-bruteforce"].observed["severity"] == "high"

    def test_the_success_after_failures_escalates_to_critical(self, results):
        assert results["ssh-compromise"].observed["severity"] == "critical"


class TestInvestigationAndResponse:
    def test_every_incident_got_an_analysis(self, results):
        for scenario in attack_scenarios():
            result = results[scenario.scenario_id]
            assert result.analysis is not None, scenario.scenario_id
            assert result.analysis.ok, result.analysis.error

    def test_the_deterministic_verdict_survives_the_ai_stage(self, results):
        for scenario in attack_scenarios():
            result = results[scenario.scenario_id]
            incident = result.incidents[0]
            assert result.analysis.deterministic_severity == incident.severity
            assert result.analysis.deterministic_score == incident.risk_score

    def test_containment_was_verified_and_audited(self, results):
        acted = [r for r in results.values() if r.action is not None]
        assert acted, "no scenario exercised containment"
        for result in acted:
            assert result.action.verified, result.scenario_id
            assert result.audit, result.scenario_id
            events = {record["event"] for record in result.audit}
            assert {"requested", "approved", "executed"} <= events

    def test_execution_without_approval_was_attempted_and_refused(self, results):
        checks = [
            check
            for result in results.values()
            for check in result.checks
            if check.name == "response.execution_without_approval_refused"
        ]
        assert checks, "the approval boundary was never exercised"
        assert all(check.passed for check in checks)
        assert all(check.observed is False for check in checks)
