"""Tests for the detection engine, risk scoring, alerts and the detect CLI."""

import json

import pytest

from conftest import at, failed_ssh, successful_ssh, sudo_event
from sentinelforge.cli import build_parser, run_detect, run_rules
from sentinelforge.detection.engine import DetectionEngine, EngineConfig
from sentinelforge.detection.risk import (
    BASE_SCORES,
    RiskFactor,
    assess_risk,
    severity_for_score,
)
from sentinelforge.detection.rule import Detection, Rule
from sentinelforge.detection.rules import SshBruteForceRule, SuspiciousSudoRule
from sentinelforge.models.alert import Alert
from sentinelforge.models.event import EventType, Severity


class BrokenRule(Rule):
    """A rule that always explodes, used to prove the engine survives it."""

    rule_id = "BROKEN_RULE"
    name = "Broken rule"
    severity = Severity.LOW

    def evaluate(self, events):
        raise RuntimeError("this rule is broken on purpose")


class AlwaysFiresRule(Rule):
    """A trivial rule, used to test engine plumbing without real detections."""

    rule_id = "ALWAYS_FIRES"
    name = "Always fires"
    description = "Fires once per event."
    severity = Severity.LOW

    def evaluate(self, events):
        for event in events:
            yield Detection(
                dedup_key=event.message or "none",
                evidence=[event],
                description="test detection",
            )


# ==========================================================================
# Risk scoring
# ==========================================================================
class TestRiskScoring:
    @pytest.mark.parametrize(
        "severity,score",
        [("info", 10), ("low", 25), ("medium", 50), ("high", 75), ("critical", 90)],
    )
    def test_base_scores(self, severity, score):
        assessment = assess_risk(severity)
        assert assessment.score == score
        assert assessment.severity == severity

    def test_context_escalates_high_to_critical(self):
        assessment = assess_risk(
            Severity.HIGH, [RiskFactor(15, "a successful login followed the failures")]
        )
        assert assessment.score == 90
        assert assessment.severity == Severity.CRITICAL

    def test_every_factor_is_explained(self):
        assessment = assess_risk(Severity.HIGH, [RiskFactor(15, "the attack succeeded")])
        assert assessment.explanation[0] == "base 75: rule severity is 'high'"
        assert "+15: the attack succeeded" in assessment.explanation
        assert any("raises severity to 'critical'" in line for line in assessment.explanation)

    def test_scores_are_clamped_to_the_valid_range(self):
        assert assess_risk(Severity.CRITICAL, [RiskFactor(50, "lots")]).score == 100
        assert assess_risk(Severity.INFO, [RiskFactor(-50, "benign")]).score == 0

    def test_negative_factors_can_lower_severity(self):
        assessment = assess_risk(Severity.HIGH, [RiskFactor(-30, "known maintenance window")])
        assert assessment.severity == Severity.LOW

    def test_severity_bands(self):
        assert severity_for_score(90) == Severity.CRITICAL
        assert severity_for_score(89) == Severity.HIGH
        assert severity_for_score(49) == Severity.LOW
        assert severity_for_score(0) == Severity.INFO

    def test_unknown_severity_falls_back_to_medium(self):
        assert assess_risk("apocalyptic").score == BASE_SCORES[Severity.MEDIUM]

    def test_scoring_is_deterministic(self):
        factors = [RiskFactor(10, "x"), RiskFactor(5, "y")]
        assert assess_risk(Severity.MEDIUM, factors) == assess_risk(Severity.MEDIUM, factors)


# ==========================================================================
# Alerts and evidence
# ==========================================================================
class TestAlerts:
    def test_alert_matches_the_documented_schema(self, brute_force_events):
        alerts = DetectionEngine(rules=[SshBruteForceRule()]).run(brute_force_events)
        data = alerts[0].to_dict()

        assert data["alert_id"] == "ALT-000001"
        assert data["rule_id"] == "SSH_BRUTE_FORCE"
        assert data["name"] == "SSH Brute Force"
        assert data["severity"] == Severity.HIGH
        assert data["risk_score"] == 75
        assert data["host"] == "fedora"
        assert data["source_ip"] == "192.168.1.50"
        assert data["user"] == "root"
        assert data["mitre"]["technique_id"] == "T1110"
        assert data["mitre"]["technique"] == "Brute Force"
        assert data["mitre"]["tactic"] == "Credential Access"
        assert data["event_count"] == 5

    def test_evidence_keeps_every_triggering_event(self, brute_force_events):
        alert = DetectionEngine(rules=[SshBruteForceRule()]).run(brute_force_events)[0]
        assert len(alert.evidence) == 5
        assert [e.timestamp for e in alert.evidence] == [e.timestamp for e in brute_force_events]

        serialized = alert.to_dict()["evidence"]
        assert len(serialized) == 5
        assert all(item["event_type"] == EventType.AUTHENTICATION_FAILURE for item in serialized)
        assert all(item["src_ip"] == "192.168.1.50" for item in serialized)
        # The original log line survives all the way into the alert.
        assert serialized[0]["message"] == brute_force_events[0].message

    def test_alert_serializes_to_one_json_line_and_round_trips(self, brute_force_events):
        alert = DetectionEngine(rules=[SshBruteForceRule()]).run(brute_force_events)[0]
        line = alert.to_json()
        assert "\n" not in line
        rebuilt = Alert.from_dict(json.loads(line))
        assert rebuilt.alert_id == alert.alert_id
        assert rebuilt.evidence == alert.evidence

    def test_evidence_can_be_trimmed_for_output_only(self, brute_force_events):
        alert = DetectionEngine(rules=[SshBruteForceRule()]).run(brute_force_events)[0]
        assert len(alert.to_dict(max_evidence=2)["evidence"]) == 2
        assert alert.to_dict(include_evidence=False)["evidence"] == []
        assert len(alert.evidence) == 5  # the alert itself still has everything

    def test_first_and_last_seen_span_the_evidence(self, brute_force_events):
        alert = DetectionEngine(rules=[SshBruteForceRule()]).run(brute_force_events)[0]
        assert alert.first_seen == at(0)
        assert alert.last_seen == at(80)
        assert alert.timestamp == alert.last_seen  # log time, not wall clock


# ==========================================================================
# Engine behaviour
# ==========================================================================
class TestEngine:
    def test_multiple_rules_run_independently(self, brute_force_events):
        events = brute_force_events + [
            successful_ssh(120),
            sudo_event(200, "/bin/systemctl stop firewalld"),
        ]
        alerts = DetectionEngine().run(events)
        rule_ids = {alert.rule_id for alert in alerts}
        assert {"SSH_BRUTE_FORCE", "SSH_COMPROMISE_SUSPECTED", "SUSPICIOUS_SUDO"} <= rule_ids

    def test_a_broken_rule_does_not_stop_the_others(self, brute_force_events):
        engine = DetectionEngine(rules=[BrokenRule(), SshBruteForceRule()])
        alerts = engine.run(brute_force_events)
        assert [alert.rule_id for alert in alerts] == ["SSH_BRUTE_FORCE"]
        assert "BROKEN_RULE" in engine.stats.rule_errors
        assert "broken on purpose" in engine.stats.rule_errors["BROKEN_RULE"]

    def test_malformed_events_are_skipped_not_fatal(self, brute_force_events):
        events = list(brute_force_events)
        events.insert(0, "this is not an event")
        events.insert(1, None)
        events.insert(2, 12345)
        events.insert(3, {"timestamp": "nonsense", "event_type": "not_a_type"})

        engine = DetectionEngine(rules=[SshBruteForceRule()])
        alerts = engine.run(events)
        assert len(alerts) == 1  # the good events still produced their alert
        assert engine.stats.events_skipped == 3  # the dict is usable, the other three are not
        assert engine.stats.events_processed == 6

    def test_events_may_be_plain_dicts(self, brute_force_events):
        payload = [event.to_dict() for event in brute_force_events]
        alerts = DetectionEngine(rules=[SshBruteForceRule()]).run(payload)
        assert len(alerts) == 1
        assert alerts[0].evidence[0].src_ip == "192.168.1.50"

    def test_empty_input_produces_no_alerts(self):
        engine = DetectionEngine()
        assert engine.run([]) == []
        assert engine.stats.alerts_generated == 0

    def test_alert_ids_are_sequential_and_chronological(self):
        events = [
            sudo_event(300, "/bin/systemctl stop firewalld"),
            sudo_event(100, "/usr/bin/cat /etc/shadow"),
        ]
        alerts = DetectionEngine(rules=[SuspiciousSudoRule()]).run(events)
        assert [alert.alert_id for alert in alerts] == ["ALT-000001", "ALT-000002"]
        assert alerts[0].timestamp < alerts[1].timestamp

    def test_min_severity_filters_and_renumbers(self, brute_force_events):
        events = brute_force_events + [sudo_event(200, "/bin/bash")]  # low severity
        engine = DetectionEngine(config=EngineConfig(min_severity=Severity.HIGH))
        alerts = engine.run(events)
        assert alerts
        assert all(Severity.at_least(alert.severity, Severity.HIGH) for alert in alerts)
        assert [alert.alert_id for alert in alerts] == [
            f"ALT-{i:06d}" for i in range(1, len(alerts) + 1)
        ]
        assert engine.stats.alerts_filtered >= 1

    def test_rule_status_reports_unavailable_rules(self):
        status = {entry["rule_id"]: entry for entry in DetectionEngine().rule_status()}
        assert status["SSH_BRUTE_FORCE"]["available"] is True
        assert status["PORT_SCAN"]["available"] is False
        assert "network telemetry" in status["PORT_SCAN"]["unavailable_reason"]

    def test_unavailable_rules_are_skipped_with_a_reason(self, brute_force_events):
        engine = DetectionEngine()
        engine.run(brute_force_events)
        assert "PORT_SCAN" in engine.stats.rules_skipped
        assert "network telemetry" in engine.stats.rules_skipped["PORT_SCAN"]

    def test_the_engine_never_mutates_the_input_events(self, brute_force_events):
        before = [event.to_dict() for event in brute_force_events]
        DetectionEngine().run(brute_force_events)
        assert [event.to_dict() for event in brute_force_events] == before


# ==========================================================================
# Deduplication
# ==========================================================================
class TestDeduplication:
    def _two_bursts(self):
        """Two separate 5-failure bursts, 2 minutes apart."""
        return [failed_ssh(i * 5) for i in range(5)] + [failed_ssh(120 + i * 5) for i in range(5)]

    def test_a_continuous_attack_is_one_alert(self):
        events = [failed_ssh(i * 10) for i in range(30)]
        alerts = DetectionEngine(rules=[SshBruteForceRule()]).run(events)
        assert len(alerts) == 1
        assert alerts[0].event_count == 30

    def test_repeat_findings_fold_into_the_first_alert(self):
        rule = SshBruteForceRule(window_seconds=60)
        engine = DetectionEngine(rules=[rule], config=EngineConfig(dedup_window_seconds=600))
        alerts = engine.run(self._two_bursts())
        assert len(alerts) == 1
        assert alerts[0].suppressed_duplicates == 1
        assert engine.stats.alerts_suppressed == 1

    def test_dedup_window_is_configurable(self):
        rule = SshBruteForceRule(window_seconds=60)
        engine = DetectionEngine(rules=[rule], config=EngineConfig(dedup_window_seconds=30))
        alerts = engine.run(self._two_bursts())
        assert len(alerts) == 2
        assert engine.stats.alerts_suppressed == 0

    def test_dedup_can_be_disabled(self):
        rule = SshBruteForceRule(window_seconds=60)
        engine = DetectionEngine(rules=[rule], config=EngineConfig(dedup_window_seconds=0))
        assert len(engine.run(self._two_bursts())) == 2

    def test_different_sources_are_never_deduplicated_together(self):
        events = [failed_ssh(i * 5, src_ip="192.168.1.50") for i in range(5)]
        events += [failed_ssh(i * 5 + 2, src_ip="10.0.0.9") for i in range(5)]
        alerts = DetectionEngine(rules=[SshBruteForceRule()]).run(events)
        assert len(alerts) == 2
        assert {alert.source_ip for alert in alerts} == {"192.168.1.50", "10.0.0.9"}

    def test_repeated_sudo_abuse_collapses_into_one_alert(self):
        events = [sudo_event(i * 10, "/bin/systemctl stop firewalld") for i in range(20)]
        engine = DetectionEngine(rules=[SuspiciousSudoRule()])
        alerts = engine.run(events)
        assert len(alerts) == 1
        assert alerts[0].suppressed_duplicates == 19


# ==========================================================================
# CLI: sentinelforge detect
# ==========================================================================
def _write_events(path, events):
    path.write_text("\n".join(event.to_json() for event in events) + "\n")
    return str(path)


@pytest.fixture
def events_file(tmp_path, brute_force_events):
    events = brute_force_events + [
        successful_ssh(120),
        sudo_event(200, "/usr/bin/dnf update"),  # benign
        sudo_event(210, "/bin/systemctl stop firewalld"),
    ]
    return _write_events(tmp_path / "events.jsonl", events)


class TestDetectCli:
    def test_detect_writes_alerts_as_jsonl(self, events_file, tmp_path, capsys):
        out = tmp_path / "alerts.jsonl"
        args = build_parser().parse_args(["detect", events_file, "--output", str(out)])
        assert run_detect(args) == 0

        alerts = [json.loads(line) for line in out.read_text().splitlines()]
        rule_ids = {alert["rule_id"] for alert in alerts}
        assert "SSH_BRUTE_FORCE" in rule_ids
        assert "SSH_COMPROMISE_SUSPECTED" in rule_ids
        assert all(alert["alert_id"].startswith("ALT-") for alert in alerts)

    def test_detect_writes_to_stdout_by_default(self, events_file, capsys):
        args = build_parser().parse_args(["detect", events_file])
        assert run_detect(args) == 0
        lines = capsys.readouterr().out.strip().splitlines()
        assert lines and all(json.loads(line)["rule_id"] for line in lines)

    def test_rule_filter(self, events_file, capsys):
        args = build_parser().parse_args(["detect", events_file, "--rule", "SSH_BRUTE_FORCE"])
        assert run_detect(args) == 0
        alerts = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        assert {alert["rule_id"] for alert in alerts} == {"SSH_BRUTE_FORCE"}

    def test_exclude_rule(self, events_file, capsys):
        args = build_parser().parse_args(
            ["detect", events_file, "--exclude-rule", "SSH_BRUTE_FORCE"]
        )
        assert run_detect(args) == 0
        alerts = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        assert "SSH_BRUTE_FORCE" not in {alert["rule_id"] for alert in alerts}

    def test_min_severity_filter(self, events_file, capsys):
        args = build_parser().parse_args(["detect", events_file, "--min-severity", "critical"])
        assert run_detect(args) == 0
        alerts = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        assert {alert["severity"] for alert in alerts} == {"critical"}

    def test_threshold_override(self, tmp_path, capsys):
        events = [failed_ssh(i * 20) for i in range(3)]
        path = _write_events(tmp_path / "few.jsonl", events)

        args = build_parser().parse_args(["detect", path])
        run_detect(args)
        assert capsys.readouterr().out.strip() == ""

        args = build_parser().parse_args(["detect", path, "--threshold", "3"])
        run_detect(args)
        assert "SSH_BRUTE_FORCE" in capsys.readouterr().out

    def test_no_evidence_and_max_evidence_options(self, events_file, capsys):
        args = build_parser().parse_args(["detect", events_file, "--no-evidence"])
        run_detect(args)
        alerts = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        assert all(alert["evidence"] == [] for alert in alerts)

        args = build_parser().parse_args(["detect", events_file, "--max-evidence", "1"])
        run_detect(args)
        alerts = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
        assert all(len(alert["evidence"]) <= 1 for alert in alerts)

    def test_summary_goes_to_stderr_so_stdout_stays_json(self, events_file, capsys):
        args = build_parser().parse_args(["detect", events_file, "--summary"])
        run_detect(args)
        captured = capsys.readouterr()
        assert "detection summary" in captured.err
        for line in captured.out.strip().splitlines():
            json.loads(line)  # stdout is still pure JSONL

    def test_unknown_rule_id_warns_but_does_not_crash(self, events_file, caplog):
        args = build_parser().parse_args(["detect", events_file, "--rule", "NOPE"])
        assert run_detect(args) == 1  # nothing selected
        assert "unknown rule id" in caplog.text

    def test_missing_events_file_is_an_error(self, tmp_path, caplog):
        args = build_parser().parse_args(["detect", str(tmp_path / "nope.jsonl")])
        assert run_detect(args) == 1
        assert "cannot read events" in caplog.text

    def test_malformed_jsonl_lines_are_skipped(self, tmp_path, brute_force_events, capsys, caplog):
        path = tmp_path / "messy.jsonl"
        lines = [event.to_json() for event in brute_force_events]
        lines.insert(2, "{not json at all")
        lines.insert(3, "[1, 2, 3]")
        path.write_text("\n".join(lines) + "\n")

        args = build_parser().parse_args(["detect", str(path)])
        assert run_detect(args) == 0
        assert "SSH_BRUTE_FORCE" in capsys.readouterr().out
        assert "skipping malformed JSON" in caplog.text

    def test_rules_command_lists_mappings_and_availability(self, capsys):
        assert run_rules(build_parser().parse_args(["rules"])) == 0
        output = capsys.readouterr().out
        assert "SSH_BRUTE_FORCE" in output
        assert "T1110.001" in output
        assert "UNAVAILABLE" in output  # PORT_SCAN
