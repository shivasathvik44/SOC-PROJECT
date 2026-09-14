"""Tests for the correlation engine: temporal, entity, chains, risk, timeline."""

import pytest

from conftest import at, make_alert
from sentinelforge.correlation.chains import ATTACK_CHAINS, FUTURE_CHAINS, match_chains
from sentinelforge.correlation.engine import (
    DEFAULT_WINDOW_SECONDS,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationStrength,
)
from sentinelforge.correlation.scoring import score_incident
from sentinelforge.models.event import Severity
from sentinelforge.models.incident import ENTRY_ALERT, ENTRY_EVENT, IncidentStatus


def correlate(alerts, **config):
    return CorrelationEngine(CorrelationConfig(**config)).run(alerts)


# ==========================================================================
# Temporal correlation
# ==========================================================================
class TestTemporalCorrelation:
    def test_default_window_is_fifteen_minutes(self):
        assert DEFAULT_WINDOW_SECONDS == 15 * 60
        assert CorrelationConfig().window_seconds == 15 * 60

    def test_alerts_inside_the_window_correlate(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SUSPICIOUS_SUDO", 120, "ALT-000002", src_ip=None),
        ]
        incidents = correlate(alerts)
        assert len(incidents) == 1
        assert incidents[0].alert_count == 2

    def test_alerts_outside_the_window_do_not_correlate(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SUSPICIOUS_SUDO", 3 * 3600, "ALT-000002", src_ip=None),
        ]
        incidents = correlate(alerts)
        assert len(incidents) == 2
        assert all(incident.alert_count == 1 for incident in incidents)

    def test_window_is_configurable(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SUSPICIOUS_SUDO", 1800, "ALT-000002", src_ip=None),
        ]
        assert len(correlate(alerts)) == 2  # 30 min apart, default 15 min window
        assert len(correlate(alerts, window_seconds=3600)) == 1

    def test_the_window_measures_from_the_last_activity_not_the_first(self):
        """A slow but continuous attack stays one incident."""
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SSH_COMPROMISE_SUSPECTED", 600, "ALT-000002"),
            make_alert("SUSPICIOUS_SUDO", 1200, "ALT-000003", src_ip=None),
        ]
        incidents = correlate(alerts)
        assert len(incidents) == 1
        assert incidents[0].alert_count == 3

    def test_incident_activity_expires_but_is_not_resolved(self):
        incident = correlate([make_alert("SSH_BRUTE_FORCE", 0)])[0]
        assert incident.is_active(at(300), DEFAULT_WINDOW_SECONDS) is True
        assert incident.is_active(at(3 * 3600), DEFAULT_WINDOW_SECONDS) is False
        # Inactive is not a lifecycle state: the incident is still open.
        assert incident.status == IncidentStatus.OPEN

    def test_a_closed_incident_no_longer_accepts_alerts(self):
        engine = CorrelationEngine()
        first = engine.run([make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")])[0]
        first.status = IncidentStatus.RESOLVED
        incidents = engine.run(
            [make_alert("SUSPICIOUS_SUDO", 120, "ALT-000002", src_ip=None)],
            existing_incidents=[first],
        )
        assert [inc.incident_id for inc in incidents] == ["INC-000002"]


# ==========================================================================
# Entity correlation
# ==========================================================================
class TestEntityCorrelation:
    def test_same_host_and_source_ip_is_a_strong_match(self):
        engine = CorrelationEngine()
        incident = engine.run([make_alert("SSH_BRUTE_FORCE", 0)])[0]
        match = engine.correlate(make_alert("SSH_COMPROMISE_SUSPECTED", 60), incident)
        assert match.strength == CorrelationStrength.STRONG
        assert any("same source address" in reason for reason in match.reasons)

    def test_same_host_and_user_is_a_medium_match(self):
        engine = CorrelationEngine()
        incident = engine.run([make_alert("SSH_BRUTE_FORCE", 0)])[0]
        alert = make_alert("SUSPICIOUS_SUDO", 60, src_ip=None, user="capslock")
        match = engine.correlate(alert, incident)
        assert match.strength == CorrelationStrength.MEDIUM
        assert any("same account" in reason for reason in match.reasons)

    def test_same_host_only_is_weak_and_rejected_by_default(self):
        engine = CorrelationEngine()
        incident = engine.run([make_alert("SSH_BRUTE_FORCE", 0, user="root")])[0]
        alert = make_alert("SUSPICIOUS_SUDO", 60, src_ip=None, user="someone-else")
        assert engine.correlate(alert, incident).strength is None

    def test_weak_correlation_can_be_enabled_explicitly(self):
        engine = CorrelationEngine(CorrelationConfig(min_strength=CorrelationStrength.WEAK))
        incident = engine.run([make_alert("SSH_BRUTE_FORCE", 0, user="root")])[0]
        alert = make_alert("SUSPICIOUS_SUDO", 60, src_ip=None, user="someone-else")
        assert engine.correlate(alert, incident).strength == CorrelationStrength.WEAK

    def test_different_source_ips_do_not_correlate(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="192.168.1.50", user="root"),
            make_alert("SSH_BRUTE_FORCE", 60, "ALT-000002", src_ip="10.0.0.9", user="admin"),
        ]
        incidents = correlate(alerts)
        assert len(incidents) == 2
        assert {incident.source_ips[0] for incident in incidents} == {"192.168.1.50", "10.0.0.9"}

    def test_different_hosts_never_correlate(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", host="fedora"),
            make_alert("SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002", host="workstation"),
        ]
        incidents = correlate(alerts)
        assert len(incidents) == 2

    def test_the_same_machine_alone_does_not_merge_everything(self):
        """The engine must not become 'group everything on this host'."""
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="203.0.113.7", user="root"),
            make_alert("AUTH_INVALID_USER", 30, "ALT-000002", src_ip="198.51.100.4", user=None),
            make_alert("SUSPICIOUS_SUDO", 60, "ALT-000003", src_ip=None, user="capslock"),
        ]
        assert len(correlate(alerts)) == 3

    def test_entities_accumulate_so_a_chain_can_hop_between_them(self):
        """IP links alerts 1-2; the account then links alert 3."""
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", user="root"),
            make_alert("SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002", user="capslock"),
            make_alert("SUSPICIOUS_SUDO", 120, "ALT-000003", src_ip=None, user="capslock"),
        ]
        incidents = correlate(alerts)
        assert len(incidents) == 1
        assert incidents[0].users == ["root", "capslock"]
        assert incidents[0].source_ips == ["192.168.1.50"]

    def test_chain_relation_can_promote_weak_when_configured(self):
        engine = CorrelationEngine(CorrelationConfig(chain_upgrades_weak=True))
        incident = engine.run([make_alert("SSH_BRUTE_FORCE", 0, user="root")])[0]
        alert = make_alert("SSH_COMPROMISE_SUSPECTED", 60, src_ip="10.0.0.9", user="other")
        match = engine.correlate(alert, incident)
        assert match.strength == CorrelationStrength.MEDIUM
        assert any("promoted" in reason for reason in match.reasons)


# ==========================================================================
# Attack chains
# ==========================================================================
class TestAttackChains:
    def test_brute_force_then_success(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002"),
        ]
        incident = correlate(alerts)[0]
        assert "BRUTE_FORCE_THEN_SUCCESS" in incident.matched_chains
        assert incident.title == "Possible Account Compromise"

    def test_full_chain_brute_force_success_sudo(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert incident.matched_chains[0] == "POSSIBLE_ACCOUNT_COMPROMISE"
        assert incident.title == "Possible SSH Account Compromise"
        assert incident.severity == Severity.CRITICAL

    def test_success_then_privilege_escalation(self):
        alerts = [
            make_alert("SSH_COMPROMISE_SUSPECTED", 0, "ALT-000001"),
            make_alert("SUSPICIOUS_SUDO", 60, "ALT-000002", src_ip=None),
        ]
        incident = correlate(alerts)[0]
        assert "POST_COMPROMISE_PRIVILEGE_ESCALATION" in incident.matched_chains

    def test_success_then_defense_evasion(self):
        alerts = [
            make_alert("SSH_COMPROMISE_SUSPECTED", 0, "ALT-000001"),
            make_alert("SUSPICIOUS_SUDO", 60, "ALT-000002", src_ip=None, technique="T1562.004"),
        ]
        incident = correlate(alerts)[0]
        assert "POST_COMPROMISE_DEFENSE_EVASION" in incident.matched_chains

    def test_chain_requires_the_right_order(self):
        """sudo before the login is not a post-compromise escalation."""
        alerts = [
            make_alert("SUSPICIOUS_SUDO", 0, "ALT-000001", src_ip=None),
            make_alert("SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002"),
        ]
        incident = correlate(alerts)[0]
        assert "POST_COMPROMISE_PRIVILEGE_ESCALATION" not in incident.matched_chains

    def test_a_single_alert_matches_no_chain(self):
        incident = correlate([make_alert("SSH_BRUTE_FORCE", 0)])[0]
        assert incident.matched_chains == []
        assert incident.title == "SSH Brute Force"

    def test_chain_stages_can_match_on_technique_not_only_rule_id(self):
        alerts = [
            make_alert("AUTH_ROOT_LOGIN_REMOTE", 0, "ALT-000001"),
            make_alert("SOME_FUTURE_RULE", 60, "ALT-000002", src_ip=None, technique="T1070.002"),
        ]
        chains = [chain.chain_id for chain, _ in match_chains(alerts)]
        assert "POST_COMPROMISE_DEFENSE_EVASION" in chains

    def test_telemetry_chains_became_real_in_phase_four(self):
        """The eBPF sensors supply what these two chains were waiting for."""
        implemented = {chain.chain_id for chain in ATTACK_CHAINS}
        assert "PRIVILEGE_ESCALATION_THEN_EXECUTION" in implemented
        assert "AUTH_THEN_PROCESS_THEN_NETWORK" in implemented

    def test_unsupported_chains_are_documented_not_faked(self):
        ids = {chain["chain_id"] for chain in FUTURE_CHAINS}
        assert "INBOUND_SCAN_THEN_EXPLOIT" in ids
        assert "LATERAL_MOVEMENT_BETWEEN_HOSTS" in ids
        implemented = {chain.chain_id for chain in ATTACK_CHAINS}
        assert not (ids & implemented)  # never both documented and pretended
        assert all("requires" in chain for chain in FUTURE_CHAINS)


# ==========================================================================
# Risk scoring
# ==========================================================================
class TestIncidentRisk:
    def test_single_alert_incident_keeps_its_alert_score(self):
        incident = correlate([make_alert("SSH_BRUTE_FORCE", 0)])[0]
        assert incident.risk_score == 75
        assert incident.severity == Severity.HIGH

    def test_score_is_based_on_the_highest_alert_not_the_sum(self):
        alerts = [
            make_alert("AUTH_REPEATED_FAILURES", 0, "ALT-000001"),  # 50
            make_alert("AUTH_INVALID_USER", 30, "ALT-000002", user="capslock"),  # 50
        ]
        incident = correlate(alerts)[0]
        assert incident.risk_score < 100
        assert incident.risk_score >= 50
        assert "base 50" in incident.risk_explanation[0]

    def test_low_plus_low_with_a_chain_becomes_medium(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", severity=Severity.LOW, risk_score=25),
            make_alert(
                "SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002", severity=Severity.LOW, risk_score=25
            ),
        ]
        incident = correlate(alerts)[0]
        assert incident.severity == Severity.MEDIUM
        assert incident.risk_score >= 50

    def test_high_plus_high_with_a_chain_becomes_critical(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", severity=Severity.HIGH, risk_score=75),
            make_alert(
                "SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002", severity=Severity.HIGH, risk_score=75
            ),
        ]
        incident = correlate(alerts)[0]
        assert incident.severity == Severity.CRITICAL
        assert incident.risk_score >= 90

    def test_score_never_exceeds_one_hundred(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert incident.risk_score == 100
        assert any("clamped" in line for line in incident.risk_explanation)

    def test_score_is_never_negative(self):
        assert score_incident([]).score == 0
        alert = make_alert("SSH_BRUTE_FORCE", 0, risk_score=0, severity=Severity.INFO)
        assert score_incident([alert]).score == 0

    def test_every_point_is_explained(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        text = " ".join(incident.risk_explanation)
        assert "base 90" in text
        assert "different detection rules" in text
        assert "successful authentication" in text
        assert "attack chain 'POSSIBLE_ACCOUNT_COMPROMISE' matched" in text
        assert "final score" in incident.risk_explanation[-1]

    def test_only_the_strongest_chain_bonus_is_applied(self, compromise_alerts):
        """Overlapping chains must not each add their bonus."""
        incident = correlate(compromise_alerts)[0]
        bonuses = [line for line in incident.risk_explanation if "attack chain" in line]
        assert len(bonuses) == 1
        assert len(incident.matched_chains) > 1

    def test_scoring_is_deterministic(self, compromise_alerts):
        first = correlate(compromise_alerts)[0]
        second = correlate(compromise_alerts)[0]
        assert (first.risk_score, first.severity) == (second.risk_score, second.severity)


# ==========================================================================
# Evidence and double counting
# ==========================================================================
class TestNoDoubleCounting:
    def test_shared_evidence_events_are_counted_once(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        # 5 failures + 1 success + 1 sudo = 7 unique, though the alerts carry 12.
        assert sum(alert.event_count for alert in incident.alerts) == 12
        assert incident.event_count == 7

    def test_duplicate_alerts_are_not_added_twice(self):
        alerts = [make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")] * 3
        incident = correlate(alerts)[0]
        assert incident.alert_count == 1

    def test_rerunning_the_same_alerts_updates_nothing(self, compromise_alerts):
        engine = CorrelationEngine()
        first = engine.run(compromise_alerts)
        again = engine.run(compromise_alerts, existing_incidents=first)
        assert again == []
        assert engine.stats.alerts_duplicate == 3
        assert engine.stats.incidents_created == 0

    def test_an_alert_renumbered_by_a_new_detect_run_is_still_a_duplicate(
        self, compromise_alerts
    ):
        engine = CorrelationEngine()
        first = engine.run(compromise_alerts)
        renumbered = [
            make_alert(alert.rule_id, 0, "ALT-000999", src_ip=alert.source_ip)
            for alert in compromise_alerts[:1]
        ]
        renumbered[0].timestamp = compromise_alerts[0].timestamp
        renumbered[0].description = compromise_alerts[0].description
        engine.run(renumbered, existing_incidents=first)
        assert engine.stats.alerts_duplicate == 1

    def test_unique_techniques_only(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("AUTH_INVALID_USER", 60, "ALT-000002"),  # same T1110.001
        ]
        incident = correlate(alerts)[0]
        assert len(incident.attack_chain) == 1


# ==========================================================================
# Timeline
# ==========================================================================
class TestTimeline:
    def test_timeline_is_chronological(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        stamps = [entry.timestamp for entry in incident.timeline]
        assert stamps == sorted(stamps)

    def test_timeline_contains_events_and_alerts(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        kinds = {entry.type for entry in incident.timeline}
        assert kinds == {ENTRY_EVENT, ENTRY_ALERT}
        assert len(incident.timeline) == 7 + 3  # unique events + alerts

    def test_timeline_entries_are_structured_objects(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        entry = next(e for e in incident.timeline if e.type == ENTRY_ALERT)
        assert entry.event in {alert.rule_id for alert in compromise_alerts}
        assert entry.severity
        assert entry.alert_id
        assert set(entry.to_dict()) >= {"timestamp", "type", "event", "description"}

    def test_timestamps_are_preserved_exactly(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert incident.timeline[0].timestamp == at(0)
        assert incident.timeline[-1].timestamp == at(420)

    def test_duplicate_evidence_appears_once_on_the_timeline(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        events = [e for e in incident.timeline if e.type == ENTRY_EVENT]
        keys = {(e.timestamp, e.event, e.description) for e in events}
        assert len(keys) == len(events)

    def test_an_alert_sorts_after_the_evidence_it_is_built_from(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        same_moment = [e for e in incident.timeline if e.timestamp == at(300)]
        assert [e.type for e in same_moment] == [ENTRY_EVENT, ENTRY_ALERT]

    def test_events_can_be_left_off_the_timeline(self, compromise_alerts):
        incident = correlate(compromise_alerts, include_events=False)[0]
        assert {entry.type for entry in incident.timeline} == {ENTRY_ALERT}
        assert incident.event_count == 7  # the evidence itself is still there


# ==========================================================================
# MITRE aggregation
# ==========================================================================
class TestMitreAggregation:
    def test_techniques_are_aggregated_in_order_of_appearance(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert [step["technique_id"] for step in incident.attack_chain] == [
            "T1110",
            "T1078",
            "T1548",
        ]

    def test_sub_techniques_are_preserved(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert incident.attack_chain[0]["sub_technique_id"] == "T1110.001"
        assert incident.attack_chain[0]["technique"] == "Brute Force"

    def test_tactics_are_kept(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert incident.attack_chain[0]["tactic"] == "Credential Access"


# ==========================================================================
# Incident lifecycle and serialization
# ==========================================================================
class TestIncidentLifecycle:
    def test_new_incidents_are_open(self, compromise_alerts):
        assert correlate(compromise_alerts)[0].status == IncidentStatus.OPEN

    @pytest.mark.parametrize("status", IncidentStatus.ALL)
    def test_every_state_is_accepted(self, status, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        incident.status = status
        assert incident.to_dict()["status"] == status

    def test_an_unknown_state_falls_back_to_open(self):
        from sentinelforge.models.incident import Incident

        assert Incident(incident_id="INC-000001", title="x", status="banana").status == "open"

    def test_incident_json_round_trips(self, compromise_alerts):
        import json

        from sentinelforge.models.incident import Incident

        incident = correlate(compromise_alerts)[0]
        rebuilt = Incident.from_dict(json.loads(incident.to_json()))
        assert rebuilt.incident_id == incident.incident_id
        assert rebuilt.risk_score == incident.risk_score
        assert rebuilt.alert_count == incident.alert_count
        assert rebuilt.event_count == incident.event_count
        assert [e.to_dict() for e in rebuilt.timeline] == [
            e.to_dict() for e in incident.timeline
        ]

    def test_summary_is_left_for_the_ai_analyst_phase(self, compromise_alerts):
        incident = correlate(compromise_alerts)[0]
        assert incident.summary is None
        assert incident.to_dict()["summary"] is None

    def test_ids_are_sequential(self):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="192.168.1.50", user="root"),
            make_alert("SSH_BRUTE_FORCE", 60, "ALT-000002", src_ip="10.0.0.9", user="admin"),
        ]
        assert [inc.incident_id for inc in correlate(alerts)] == ["INC-000001", "INC-000002"]

    def test_numbering_continues_from_existing_incidents(self, compromise_alerts):
        engine = CorrelationEngine()
        first = engine.run(compromise_alerts)
        later = engine.run(
            [make_alert("SSH_BRUTE_FORCE", 99999, "ALT-000009", src_ip="10.0.0.9")],
            existing_incidents=first,
            start_number=7,
        )
        assert later[0].incident_id == "INC-000007"


# ==========================================================================
# Engine robustness
# ==========================================================================
class TestEngineRobustness:
    def test_malformed_alerts_are_skipped(self, compromise_alerts):
        engine = CorrelationEngine()
        incidents = engine.run(["not an alert", None, 42] + compromise_alerts)
        assert len(incidents) == 1
        assert engine.stats.alerts_skipped == 3
        assert engine.stats.alerts_correlated == 3

    def test_alerts_may_be_plain_dicts(self, compromise_alerts):
        payload = [alert.to_dict() for alert in compromise_alerts]
        incidents = correlate(payload)
        assert len(incidents) == 1
        assert incidents[0].alert_count == 3

    def test_no_alerts_means_no_incidents(self):
        assert correlate([]) == []

    def test_alerts_without_timestamps_do_not_crash(self):
        alert = make_alert("SSH_BRUTE_FORCE", 0)
        alert.timestamp = None
        incidents = correlate([alert])
        assert len(incidents) == 1

    def test_out_of_order_input_is_sorted_before_correlating(self):
        alerts = [
            make_alert("SUSPICIOUS_SUDO", 420, "ALT-000003", src_ip=None),
            make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001"),
            make_alert("SSH_COMPROMISE_SUSPECTED", 300, "ALT-000002"),
        ]
        incident = correlate(alerts)[0]
        assert [alert.rule_id for alert in incident.alerts] == [
            "SSH_BRUTE_FORCE",
            "SSH_COMPROMISE_SUSPECTED",
            "SUSPICIOUS_SUDO",
        ]
        assert incident.matched_chains[0] == "POSSIBLE_ACCOUNT_COMPROMISE"

    def test_correlation_never_mutates_the_input_alerts(self, compromise_alerts):
        before = [alert.to_dict() for alert in compromise_alerts]
        correlate(compromise_alerts)
        assert [alert.to_dict() for alert in compromise_alerts] == before
