"""Phase 8: the ``simulate`` and ``benchmark`` commands.

The CLI is where an operator meets Phase 8, so what matters here is that it
tells the truth: a failing scenario must print ``FAILED`` and exit non-zero, a
skipped stage must say it was skipped, and the numbers on screen must be the
numbers the run produced.

Exit codes follow the existing convention: ``0`` success, ``1`` a usage or
runtime error, and ``2`` for "the validation itself failed", so a CI job can
tell a broken tool from a broken platform.
"""

import dataclasses
import io
import json

import pytest

from sentinelforge.cli import EXIT_VALIDATION_FAILED, build_parser, main
from sentinelforge.simulation.scenarios import get_scenario, scenario_ids


def run(argv, ) -> tuple[int, str]:
    """Run a CLI command, capturing stdout."""
    import contextlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    return code, buffer.getvalue()


class TestHelp:
    def test_simulate_has_help(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["simulate", "--help"])
        assert excinfo.value.code == 0

    def test_benchmark_has_help(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as excinfo:
            parser.parse_args(["benchmark", "--help"])
        assert excinfo.value.code == 0

    def test_the_top_level_help_lists_both_commands(self, capsys):
        code, output = run([])
        assert code == 0
        assert "simulate" in output and "benchmark" in output

    def test_every_existing_command_still_parses(self):
        """Phase 8 must not have disturbed Phases 1-7."""
        parser = build_parser()
        for command in (
            ["sources"], ["rules"], ["collect"], ["detect", "events.jsonl"],
            ["correlate", "alerts.jsonl"], ["incidents"], ["incident", "INC-000001"],
            ["sensor", "list"], ["ai", "providers"], ["dashboard"],
            ["response", "list"],
        ):
            assert parser.parse_args(command).command == command[0]


class TestSimulateList:
    def test_list_shows_every_scenario(self):
        code, output = run(["simulate", "list"])
        assert code == 0
        for scenario_id in scenario_ids():
            assert scenario_id in output

    def test_list_is_the_default(self):
        assert run(["simulate"])[1] == run(["simulate", "list"])[1]

    def test_list_says_the_scenarios_are_synthetic(self):
        _, output = run(["simulate", "list"])
        assert "synthetic" in output.lower()
        assert "no traffic is sent" in output


class TestSimulateOne:
    def test_a_passing_scenario_exits_zero_and_says_so(self):
        code, output = run(["simulate", "ssh-bruteforce"])
        assert code == 0
        assert "SCENARIO PASSED" in output

    def test_the_report_shows_what_was_observed(self):
        _, output = run(["simulate", "full-attack"])
        assert "Events generated : 12" in output
        assert "Alerts           : 5" in output
        assert "Incidents        : 1" in output
        assert "SSH_BRUTE_FORCE" in output
        assert "critical" in output

    def test_every_stage_is_listed_with_its_verdict(self):
        _, output = run(["simulate", "full-attack"])
        for stage in (
            "simulation", "detection", "correlation", "mitre", "risk",
            "investigation", "visualization", "response", "verification", "audit",
        ):
            assert stage in output

    def test_a_skipped_stage_says_why(self):
        _, output = run(["simulate", "suspicious-sudo"])
        assert "SKIP" in output
        assert "containment target" in output

    def test_containment_is_labelled_as_a_mock_backend(self):
        _, output = run(["simulate", "ssh-bruteforce"])
        assert "in-memory mock backend" in output

    def test_checks_prints_every_comparison(self):
        _, quiet = run(["simulate", "ssh-bruteforce"])
        _, verbose = run(["simulate", "ssh-bruteforce", "--checks"])
        assert "detection.alert_count" not in quiet
        assert "detection.alert_count" in verbose
        assert "expected=" in verbose and "observed=" in verbose

    def test_json_output_is_machine_readable(self):
        code, output = run(["simulate", "ssh-bruteforce", "--json"])
        assert code == 0
        payload = json.loads(output)
        assert payload["scenario_id"] == "ssh-bruteforce"
        assert payload["result"] == "PASS"
        assert payload["checks_passed"] == payload["checks_total"]
        assert payload["stages"]
        assert payload["timings_ms"]

    def test_an_unknown_scenario_is_an_error_not_a_failure(self, capsys):
        code, _ = run(["simulate", "no-such-scenario"])
        assert code == 1
        assert "available" in capsys.readouterr().err

    def test_stages_can_be_switched_off(self):
        _, output = run(
            ["simulate", "full-attack", "--no-ai", "--no-dashboard", "--no-response"]
        )
        assert "SCENARIO PASSED" in output
        assert output.count("SKIP") >= 3


class TestSimulateAll:
    def test_every_scenario_runs_and_the_table_totals_agree(self):
        code, output = run(["simulate", "all"])
        assert code == 0
        for scenario_id in scenario_ids():
            assert scenario_id in output
        assert f"{len(scenario_ids())}/{len(scenario_ids())} scenarios passed" in output

    def test_json_output_is_a_list(self):
        code, output = run(["simulate", "all", "--json"])
        assert code == 0
        payload = json.loads(output)
        assert isinstance(payload, list)
        assert len(payload) == len(scenario_ids())


class TestFailureIsVisible:
    """The most important property: a failure must not be able to hide."""

    def test_a_broken_expectation_exits_two_and_prints_both_sides(self, monkeypatch):
        scenario = get_scenario("ssh-bruteforce")
        broken = dataclasses.replace(
            scenario, expected=dataclasses.replace(scenario.expected, incidents=42)
        )
        monkeypatch.setattr(
            "sentinelforge.cli.get_scenario", lambda scenario_id: broken
        )
        code, output = run(["simulate", "ssh-bruteforce"])
        assert code == EXIT_VALIDATION_FAILED
        assert "SCENARIO FAILED" in output
        assert "correlation.incident_count" in output
        assert "expected=42" in output and "observed=1" in output

    def test_a_failing_scenario_in_all_is_surfaced_in_the_table(self, monkeypatch):
        scenario = get_scenario("ssh-bruteforce")
        broken = dataclasses.replace(
            scenario, expected=dataclasses.replace(scenario.expected, alerts=7)
        )

        def patched_all():
            return [broken, get_scenario("benign-sudo")]

        monkeypatch.setattr("sentinelforge.cli.all_scenarios", patched_all)
        monkeypatch.setattr(
            "sentinelforge.simulation.runner.all_scenarios", patched_all
        )
        code, output = run(["simulate", "all"])
        assert code == EXIT_VALIDATION_FAILED
        assert "FAIL" in output
        assert "detection.alert_count" in output


class TestReplayFiles:
    def test_events_and_alerts_are_written_as_json_lines(self, tmp_path):
        events_path = tmp_path / "events.jsonl"
        alerts_path = tmp_path / "alerts.jsonl"
        code, output = run(
            [
                "simulate", "full-attack",
                "--events-out", str(events_path),
                "--alerts-out", str(alerts_path),
            ]
        )
        assert code == 0
        events = [json.loads(line) for line in events_path.read_text().splitlines()]
        alerts = [json.loads(line) for line in alerts_path.read_text().splitlines()]
        assert len(events) == 12
        assert len(alerts) == 5
        assert "Replayed 12 synthetic event" in output

    def test_every_replayed_record_is_labelled_synthetic(self, tmp_path):
        events_path = tmp_path / "events.jsonl"
        run(["simulate", "ssh-bruteforce", "--events-out", str(events_path)])
        for line in events_path.read_text().splitlines():
            payload = json.loads(line)
            assert payload["simulated"] is True
            assert "SYNTHETIC" in payload["simulation_label"]

    def test_the_files_are_appended_not_truncated(self, tmp_path):
        events_path = tmp_path / "events.jsonl"
        run(["simulate", "ssh-bruteforce", "--events-out", str(events_path)])
        run(["simulate", "ssh-bruteforce", "--events-out", str(events_path)])
        assert len(events_path.read_text().splitlines()) == 12

    def test_a_delay_paces_the_replay_without_changing_the_timings(self, tmp_path):
        import time

        events_path = tmp_path / "events.jsonl"
        started = time.perf_counter()
        code, output = run(
            [
                "simulate", "ssh-bruteforce", "--delay", "0.01",
                "--events-out", str(events_path),
            ]
        )
        elapsed = time.perf_counter() - started
        assert code == 0
        assert elapsed >= 0.04, "the delay should actually have paced the replay"
        # The reported pipeline timings must not include the sleeping.
        assert "simulation 0." in output or "simulation 1." in output


class TestSimulateDatabase:
    def test_an_explicit_database_receives_the_incident(self, tmp_path):
        db_path = tmp_path / "sim.db"
        code, _ = run(["simulate", "full-attack", "--db", str(db_path)])
        assert code == 0

        from sentinelforge.storage.sqlite import IncidentStore

        with IncidentStore(str(db_path)) as store:
            incidents = store.list_incidents()
        assert len(incidents) == 1
        assert incidents[0].severity == "critical"
        assert incidents[0].ai_analysis is not None

    def test_the_response_actions_land_in_the_same_database(self, tmp_path):
        db_path = tmp_path / "sim.db"
        run(["simulate", "full-attack", "--db", str(db_path)])

        from sentinelforge.storage.sqlite import ResponseStore

        with ResponseStore(str(db_path)) as store:
            actions = store.list_actions()
            audit = store.list_audit()
        assert actions and audit
        assert all(action.requested_by == "phase8-simulator" for action in actions)


class TestReports:
    def test_reports_are_written_where_asked(self, tmp_path):
        directory = tmp_path / "phase8"
        code, output = run(["simulate", "all", "--report", str(directory)])
        assert code == 0
        for name in (
            "detection-coverage.json",
            "detection-coverage.md",
            "attack-scenarios.json",
            "benchmark.json",
            "benchmark.md",
            "security-probes.json",
            "final-security-assessment.md",
        ):
            assert (directory / name).exists(), name
            assert str(directory / name) in output


class TestBenchmarkCommand:
    def test_the_default_run_reports_every_size(self):
        code, output = run(["benchmark", "--events", "100", "--no-memory"])
        assert code == 0
        assert "SentinelForge Benchmark" in output
        assert "Events/s" in output
        assert "Latency for one incident" in output

    def test_json_output_carries_the_measurements(self):
        code, output = run(["benchmark", "--events", "100", "--json", "--no-memory"])
        assert code == 0
        payload = json.loads(output)
        assert payload["throughput"][0]["events"] == 100
        assert payload["throughput"][0]["events_per_second"] > 0
        assert payload["latency"]["ai_provider"] == "mock"
        assert payload["environment"]["python"]

    def test_several_sizes_can_be_requested(self):
        code, output = run(
            ["benchmark", "--events", "50", "--events", "100", "--json", "--no-memory"]
        )
        payload = json.loads(output)
        assert [item["events"] for item in payload["throughput"]] == [50, 100]

    def test_a_nonsensical_size_is_refused(self, capsys):
        code, _ = run(["benchmark", "--events", "0"])
        assert code == 1
        assert "positive" in capsys.readouterr().err

    def test_an_unknown_latency_scenario_is_refused(self, capsys):
        code, _ = run(["benchmark", "--events", "50", "--scenario", "nope", "--no-memory"])
        assert code == 1

    def test_memory_is_reported_as_not_measured_when_skipped(self):
        code, output = run(["benchmark", "--events", "50", "--json", "--no-memory"])
        payload = json.loads(output)
        assert payload["throughput"][0]["memory_measured"] is False
        assert payload["throughput"][0]["peak_allocated_kb"] is None

    def test_benchmark_can_write_its_report(self, tmp_path):
        directory = tmp_path / "bench"
        code, _ = run(
            ["benchmark", "--events", "50", "--no-memory", "--report", str(directory)]
        )
        assert code == 0
        assert (directory / "benchmark.md").exists()
        assert "Throughput" in (directory / "benchmark.md").read_text()


class TestSimulationNeverTouchesTheRealStore:
    """A simulation writes synthetic incidents; the analyst's store must not get them."""

    def test_the_default_incident_database_is_refused(self, capsys):
        from sentinelforge.storage.sqlite import default_database_path

        code, _ = run(["simulate", "ssh-bruteforce", "--db", default_database_path()])
        assert code == 1
        message = capsys.readouterr().err
        assert "refusing to write synthetic incidents" in message

    def test_a_relative_path_to_the_same_file_is_also_refused(self, capsys, monkeypatch, tmp_path):
        real = tmp_path / "incidents.db"
        monkeypatch.setattr(
            "sentinelforge.cli.default_database_path", lambda: str(real)
        )
        monkeypatch.chdir(tmp_path)
        code, _ = run(["simulate", "ssh-bruteforce", "--db", "./incidents.db"])
        assert code == 1
        assert "refusing" in capsys.readouterr().err

    def test_any_other_path_is_accepted(self, tmp_path):
        code, _ = run(["simulate", "ssh-bruteforce", "--db", str(tmp_path / "mine.db")])
        assert code == 0

    def test_replayed_events_are_self_identifying_after_a_round_trip(self, tmp_path):
        """The dashboard's tailer rebuilds events; the marker must survive it."""
        from sentinelforge.pipeline.load import load_events

        path = tmp_path / "events.jsonl"
        run(["simulate", "ssh-bruteforce", "--events-out", str(path)])
        for event in load_events(str(path)):
            assert event.metadata.get("simulated") is True
            assert "SYNTHETIC" in event.metadata.get("simulation_label", "")
