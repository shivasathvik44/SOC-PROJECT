"""Phase 8: the runner and the expected-vs-observed framework.

The runner is the thing that decides whether SentinelForge passed, so it gets
tested harder than anything it validates.  The properties that matter:

* a check's verdict is **computed**, never supplied - there is no way to write
  a passing check for a mismatched observation;
* a stage that could not run is ``SKIP`` and is excluded from pass rates,
  because "we did not test it" must never read as "it worked";
* a stage that raises is a failure, not a silence;
* containment during a simulation reaches in-memory backends only, whatever
  the host is or who is running it;
* a simulation never writes to the real incident database.
"""

import inspect
import os

from sentinelforge.response.actions import ResponseBackends
from sentinelforge.response.backends.mock import (
    MockFirewallBackend,
    MockProcessBackend,
    MockSessionBackend,
)
from sentinelforge.simulation.results import (
    ScenarioResult,
    StageResult,
    Verdict,
    contains_all,
    contains_none,
    equals,
    is_true,
    within,
)
from sentinelforge.simulation.runner import (
    RunnerConfig,
    ScenarioRunner,
    run_scenario,
    simulation_backends,
)
from sentinelforge.simulation.scenarios import get_scenario
from sentinelforge.storage.sqlite import default_database_path

class TestCheckCannotBeForced:
    def test_no_check_constructor_accepts_a_verdict(self):
        """The point of the framework: a result is derived, never declared."""
        for constructor in (equals, contains_all, contains_none, within, is_true):
            parameters = inspect.signature(constructor).parameters
            assert "passed" not in parameters
            assert "result" not in parameters
            assert "verdict" not in parameters

    def test_equals_fails_on_a_mismatch(self):
        assert equals("x", 1, 1).passed
        assert not equals("x", 1, 2).passed

    def test_contains_all_reports_what_is_missing(self):
        check = contains_all("rules", {"A", "B"}, {"A"})
        assert not check.passed
        assert "B" in check.detail

    def test_contains_none_reports_what_fired(self):
        check = contains_none("silent", {"BAD"}, {"BAD", "GOOD"})
        assert not check.passed
        assert "BAD" in check.detail

    def test_within_is_inclusive_and_rejects_non_numbers(self):
        assert within("score", (50, 60), 50).passed
        assert within("score", (50, 60), 60).passed
        assert not within("score", (50, 60), 61).passed
        assert not within("score", (50, 60), None).passed

    def test_a_check_renders_both_sides(self):
        line = equals("risk.severity", "critical", "high").line()
        assert "FAIL" in line and "critical" in line and "high" in line

class TestStageVerdicts:
    def test_a_stage_with_a_failing_check_fails(self):
        stage = StageResult("detection")
        stage.add(equals("a", 1, 1))
        stage.add(equals("b", 1, 2))
        assert stage.verdict == Verdict.FAIL

    def test_a_skipped_stage_is_skipped_not_passed(self):
        stage = StageResult("investigation").skip("AI disabled")
        assert stage.verdict == Verdict.SKIP
        assert not stage.passed

    def test_a_stage_that_raised_is_a_failure(self):
        stage = StageResult("response")
        stage.add(equals("a", 1, 1))
        stage.fail("boom")
        assert stage.verdict == Verdict.FAIL

    def test_an_empty_stage_is_skipped_not_passed(self):
        assert StageResult("empty").verdict == Verdict.SKIP

    def test_a_result_with_only_skipped_stages_is_skipped(self):
        result = ScenarioResult("x", "X", "attack")
        result.stage("detection").skip("disabled")
        assert result.verdict == Verdict.SKIP
        assert not result.passed

    def test_skipped_stages_do_not_make_a_result_pass(self):
        result = ScenarioResult("x", "X", "attack")
        result.stage("detection").add(equals("a", 1, 2))
        result.stage("response").skip("no target")
        assert result.verdict == Verdict.FAIL

    def test_a_scenario_error_is_a_failure(self):
        result = ScenarioResult("x", "X", "attack")
        result.stage("detection").add(equals("a", 1, 1))
        result.error = "TypeError: boom"
        assert result.verdict == Verdict.FAIL

class TestRunnerSafety:
    def test_simulation_backends_are_in_memory(self):
        backends = simulation_backends()
        assert isinstance(backends.firewall, MockFirewallBackend)
        assert isinstance(backends.process, MockProcessBackend)
        assert isinstance(backends.session, MockSessionBackend)

    def test_the_runner_never_auto_detects_backends(self, monkeypatch):
        """Detection is what would find the real firewall.  It is never called."""

        def explode(cls, execution_enabled: bool = True):  # pragma: no cover - must not run
            raise AssertionError("a simulation must not auto-detect real backends")

        monkeypatch.setattr(ResponseBackends, "detect", classmethod(explode))
        result = run_scenario("ssh-bruteforce")
        assert result.passed

    def test_scenario_pids_become_containment_targets(self):
        scenario = get_scenario("process-chain")
        backends = simulation_backends(scenario.events())
        assert set(backends.process.processes) == {4100, 4150, 4200, 4300}

    def test_a_simulation_does_not_touch_the_real_database(self, tmp_path):
        real = default_database_path()
        before = os.path.getmtime(real) if os.path.exists(real) else None
        run_scenario("full-attack")
        after = os.path.getmtime(real) if os.path.exists(real) else None
        assert before == after

    def test_the_temporary_database_is_removed(self):
        runner = ScenarioRunner()
        paths = []
        original = runner._run_stages

        def capture(scenario, result, timer, db_path):
            paths.append(db_path)
            return original(scenario, result, timer, db_path)

        runner._run_stages = capture
        runner.run("ssh-bruteforce")
        assert paths and not os.path.exists(paths[0])

    def test_an_explicit_database_is_kept(self, tmp_path):
        db_path = str(tmp_path / "sim.db")
        result = ScenarioRunner(db_path=db_path).run("ssh-bruteforce")
        assert result.passed
        assert os.path.exists(db_path)

class TestRunnerStages:
    def test_disabling_a_stage_skips_it_rather_than_passing_it(self):
        config = RunnerConfig(analyze=False, visualize=False, respond=False)
        result = ScenarioRunner(config).run("full-attack")
        skipped = {stage.name for stage in result.stages if stage.skipped}
        assert {"investigation", "visualization", "response"} <= skipped
        assert all(not stage.passed for stage in result.stages if stage.skipped)

    def test_a_scenario_with_no_containment_target_skips_response(self):
        result = run_scenario("suspicious-sudo")
        response = next(s for s in result.stages if s.name == "response")
        assert response.verdict == Verdict.SKIP
        assert "containment target" in response.skip_reason

    def test_a_benign_scenario_skips_everything_after_correlation(self):
        result = run_scenario("benign-sudo")
        assert result.passed
        graded = {stage.name for stage in result.stages if not stage.skipped}
        assert graded == {"simulation", "detection", "correlation"}

    def test_timings_use_a_monotonic_clock_not_event_timestamps(self):
        """A scenario spanning minutes of log time must not report minutes."""
        result = run_scenario("full-attack")
        assert result.total_ms < 60_000
        assert all(value >= 0 for value in result.timings.values())

    def test_pacing_is_excluded_from_the_measured_timings(self):
        published = []
        config = RunnerConfig(
            delay=0.02, publish=lambda topic, payload: published.append(topic),
            analyze=False, visualize=False, respond=False,
        )
        result = ScenarioRunner(config).run("ssh-bruteforce")
        assert published, "the publish hook should have received the events"
        # Six events at 20 ms is 100 ms of deliberate sleeping; none of it may
        # appear in the simulation stage's measurement.
        assert result.timings["simulation"] < 50

    def test_a_raising_stage_is_reported_as_a_failure(self, monkeypatch):
        runner = ScenarioRunner()

        def explode(*args, **kwargs):
            raise RuntimeError("detection exploded")

        monkeypatch.setattr(runner, "_stage_detection", explode)
        result = runner.run("ssh-bruteforce")
        assert result.verdict == Verdict.FAIL
        assert "detection exploded" in (result.error or "")

class TestObservedMismatchIsReported:
    def test_an_altered_expectation_produces_a_failure(self):
        """Change what is expected and the runner says so, with both sides."""
        import dataclasses

        scenario = get_scenario("ssh-bruteforce")
        broken = dataclasses.replace(
            scenario,
            expected=dataclasses.replace(scenario.expected, alerts=99),
        )
        result = ScenarioRunner().run(broken)
        assert result.verdict == Verdict.FAIL
        failure = next(c for c in result.failures if c.name == "detection.alert_count")
        assert failure.expected == 99
        assert failure.observed == 1

    def test_a_forbidden_rule_firing_is_a_failure(self):
        import dataclasses

        scenario = get_scenario("ssh-bruteforce")
        broken = dataclasses.replace(
            scenario,
            expected=dataclasses.replace(
                scenario.expected, forbidden_rule_ids=frozenset({"SSH_BRUTE_FORCE"})
            ),
        )
        result = ScenarioRunner().run(broken)
        assert result.verdict == Verdict.FAIL
        failure = next(c for c in result.failures if c.name == "detection.rules_silent")
        assert "SSH_BRUTE_FORCE" in failure.detail
