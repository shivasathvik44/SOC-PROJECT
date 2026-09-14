"""Tests for the ``sentinelforge ai`` commands (Phase 5).

Everything runs against a temporary database and the offline mock provider:
no test needs an API key or a network.
"""

import json

import pytest

from sentinelforge.ai.client import ENV_API_KEY, ENV_MODEL, ENV_PROVIDER
from sentinelforge.cli import (
    build_parser,
    main,
    run_ai_analyze,
    run_ai_cache,
    run_ai_providers,
    run_incident,
)
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.storage.sqlite import IncidentStore


@pytest.fixture
def db(tmp_path, compromise_alerts):
    """A database holding one correlated incident."""
    path = str(tmp_path / "incidents.db")
    incidents = CorrelationEngine().run(compromise_alerts)
    with IncidentStore(path) as store:
        store.save_all(incidents)
    return path


@pytest.fixture
def cache_dir(tmp_path):
    return str(tmp_path / "ai-cache")


def analyze_args(db, cache_dir, *extra):
    return build_parser().parse_args(
        [
            "ai",
            "analyze",
            "INC-000001",
            "--db",
            db,
            "--provider",
            "mock",
            "--cache-dir",
            cache_dir,
            *extra,
        ]
    )


class TestAnalyzeCommand:
    def test_prints_a_readable_report(self, db, cache_dir, capsys):
        assert run_ai_analyze(analyze_args(db, cache_dir)) == 0
        out = capsys.readouterr().out
        assert "SentinelForge AI Analyst" in out
        assert "INC-000001" in out
        assert "Assessment:" in out
        assert "Confidence:" in out
        assert "Deterministic:" in out
        assert "Recommended investigation:" in out

    def test_mock_output_is_labelled(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        assert "MOCK ANALYSIS" in capsys.readouterr().out

    def test_shows_both_severities(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        out = capsys.readouterr().out
        assert "Deterministic: CRITICAL (100)" in out
        assert "AI assessment:" in out

    def test_json_output(self, db, cache_dir, capsys):
        assert run_ai_analyze(analyze_args(db, cache_dir, "--json")) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["incident_id"] == "INC-000001"
        assert data["status"] == "ok"
        assert data["audit"]["is_mock"] is True
        assert 0.0 <= data["confidence"] <= 1.0

    def test_output_file(self, db, cache_dir, tmp_path, capsys):
        out_file = tmp_path / "analysis.json"
        assert run_ai_analyze(analyze_args(db, cache_dir, "--output", str(out_file))) == 0
        data = json.loads(out_file.read_text())
        assert data["incident_id"] == "INC-000001"

    def test_analysis_is_saved_onto_the_incident(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        with IncidentStore(db) as store:
            incident = store.get("INC-000001")
        assert incident.ai_analysis["status"] == "ok"
        assert incident.ai_analysis["audit"]["is_mock"] is True
        # The deterministic result is untouched.
        assert incident.risk_score == 100
        assert incident.status == "open"

    def test_no_save_leaves_the_incident_alone(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir, "--no-save"))
        with IncidentStore(db) as store:
            assert store.get("INC-000001").ai_analysis is None

    def test_incident_report_shows_the_analysis(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        capsys.readouterr()
        args = build_parser().parse_args(["incident", "INC-000001", "--db", db])
        assert run_incident(args) == 0
        out = capsys.readouterr().out
        assert "SentinelForge AI Analyst" in out
        assert "Timeline" in out  # the deterministic report is still there

    def test_unknown_incident_is_reported(self, db, cache_dir):
        args = build_parser().parse_args(
            ["ai", "analyze", "INC-999999", "--db", db, "--provider", "mock"]
        )
        assert run_ai_analyze(args) == 1

    def test_show_prompt_contacts_no_provider(self, db, cache_dir, capsys):
        assert run_ai_analyze(analyze_args(db, cache_dir, "--show-prompt")) == 0
        captured = capsys.readouterr()
        assert "UNTRUSTED SECURITY TELEMETRY" in captured.err
        assert captured.out == ""
        with IncidentStore(db) as store:
            assert store.get("INC-000001").ai_analysis is None

    def test_context_limits_are_configurable(self, db, cache_dir, capsys):
        assert run_ai_analyze(analyze_args(db, cache_dir, "--max-alerts", "1", "--json")) == 0
        data = json.loads(capsys.readouterr().out)
        assert any("showing 1 of 3" in note for note in data["audit"]["truncated"])

    def test_failed_analysis_exits_nonzero_without_crashing(self, db, cache_dir, capsys, monkeypatch):
        """A provider that cannot run must not take the CLI down."""
        monkeypatch.setenv(ENV_PROVIDER, "openai")
        monkeypatch.setenv(ENV_MODEL, "some-model")
        monkeypatch.delenv(ENV_API_KEY, raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        args = build_parser().parse_args(["ai", "analyze", "INC-000001", "--db", db])
        assert run_ai_analyze(args) == 1
        out = capsys.readouterr().out
        assert "UNAVAILABLE" in out
        assert "incident itself is unaffected" in out
        with IncidentStore(db) as store:
            assert store.get("INC-000001") is not None  # the incident still exists


class TestCaching:
    def test_second_run_is_served_from_cache(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        capsys.readouterr()
        run_ai_analyze(analyze_args(db, cache_dir))
        assert "cached analysis" in capsys.readouterr().out

    def test_refresh_reanalyzes(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        capsys.readouterr()
        run_ai_analyze(analyze_args(db, cache_dir, "--refresh"))
        assert "cached analysis" not in capsys.readouterr().out

    def test_no_cache_never_stores(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir, "--no-cache"))
        capsys.readouterr()
        run_ai_analyze(analyze_args(db, cache_dir, "--no-cache"))
        assert "cached analysis" not in capsys.readouterr().out

    def test_cache_command_reports_and_clears(self, db, cache_dir, capsys):
        run_ai_analyze(analyze_args(db, cache_dir))
        capsys.readouterr()
        args = build_parser().parse_args(["ai", "cache", "--cache-dir", cache_dir])
        assert run_ai_cache(args) == 0
        assert "cached analyses: 1" in capsys.readouterr().out

        clear = build_parser().parse_args(["ai", "cache", "--cache-dir", cache_dir, "--clear"])
        assert run_ai_cache(clear) == 0
        assert "removed 1" in capsys.readouterr().out


class TestProvidersCommand:
    def test_reports_configuration_without_the_key(self, capsys, monkeypatch):
        monkeypatch.setenv(ENV_PROVIDER, "openai")
        monkeypatch.setenv(ENV_MODEL, "a-model")
        monkeypatch.setenv(ENV_API_KEY, "sk-do-not-print-me")
        assert run_ai_providers(build_parser().parse_args(["ai", "providers"])) == 0
        out = capsys.readouterr().out
        assert "sk-do-not-print-me" not in out
        assert "configured" in out
        assert "a-model" in out

    def test_reports_a_missing_key(self, capsys, monkeypatch):
        monkeypatch.setenv(ENV_PROVIDER, "openai")
        monkeypatch.delenv(ENV_API_KEY, raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        run_ai_providers(build_parser().parse_args(["ai", "providers"]))
        assert "MISSING" in capsys.readouterr().out

    def test_defaults_to_mock(self, capsys, monkeypatch):
        for name in (ENV_PROVIDER, ENV_MODEL, ENV_API_KEY, "OPENAI_API_KEY"):
            monkeypatch.delenv(name, raising=False)
        run_ai_providers(build_parser().parse_args(["ai", "providers"]))
        out = capsys.readouterr().out
        assert "mock" in out
        assert "never contacted" in out


class TestMainDispatch:
    def test_ai_analyze_through_main(self, db, cache_dir, capsys):
        code = main(
            [
                "ai",
                "analyze",
                "INC-000001",
                "--db",
                db,
                "--provider",
                "mock",
                "--cache-dir",
                cache_dir,
            ]
        )
        assert code == 0
        assert "AI Analyst" in capsys.readouterr().out

    def test_ai_without_subcommand_shows_help(self, capsys):
        with pytest.raises(SystemExit):
            main(["ai"])
