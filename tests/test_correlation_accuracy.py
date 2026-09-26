"""Phase 8: correlation accuracy and incident deduplication.

Correlation is the part of SentinelForge with the most expensive failure modes.
Under-correlating turns one intrusion into a queue of disconnected alerts;
over-correlating merges two unrelated problems into one incident and hides the
smaller of them.  So the interesting cases are not "does it group things" but
the pairs that *look* related and are not:

* same host, different attacker;
* same host, different account;
* same address, but hours apart;
* the same ATT&CK technique from two unrelated sources.

The deduplication tests cover the other side: a continuing attack must keep
extending one incident rather than opening INC-000002, INC-000003, ... and
re-running correlation over alerts that are already stored must change nothing.
"""

import pytest

from sentinelforge.correlation.engine import (
    CorrelationConfig,
    CorrelationEngine,
    CorrelationStrength,
)
from sentinelforge.models.incident import IncidentStatus
from sentinelforge.simulation.scenario import BASE_TIME, ssh_failure, ssh_success
from sentinelforge.storage.sqlite import IncidentStore

pytest_plugins = ()


def _alerts(make_alert, *specs):
    """Build alerts from ``(rule_id, offset, id, host, ip, user)`` tuples."""
    return [
        make_alert(rule_id, offset, alert_id, host=host, src_ip=ip, user=user)
        for rule_id, offset, alert_id, host, ip, user in specs
    ]


@pytest.fixture
def make_alert():
    from conftest import make_alert as factory

    return factory


class TestStrongCorrelation:
    def test_same_host_same_address_is_strong(self, make_alert):
        first = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        second = make_alert("SSH_COMPROMISE_SUSPECTED", 120, "ALT-000002")
        incidents = CorrelationEngine().run([first, second])
        assert len(incidents) == 1
        reasons = " ".join(incidents[0].correlation_reasons)
        assert "same source address" in reasons

    def test_same_host_same_account_without_an_address_is_medium(self, make_alert):
        first = make_alert("SSH_COMPROMISE_SUSPECTED", 0, "ALT-000001", user="deploy")
        second = make_alert("SUSPICIOUS_SUDO", 120, "ALT-000002", src_ip=None, user="deploy")
        incidents = CorrelationEngine().run([first, second])
        assert len(incidents) == 1
        assert "same account 'deploy'" in " ".join(incidents[0].correlation_reasons)


class TestNoCorrelation:
    def test_different_hosts_never_correlate(self, make_alert):
        first = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", host="web-1")
        second = make_alert("SSH_COMPROMISE_SUSPECTED", 60, "ALT-000002", host="db-1")
        assert len(CorrelationEngine().run([first, second])) == 2

    def test_same_host_but_different_attacker_and_account_does_not_correlate(
        self, make_alert
    ):
        """The case that matters: two unrelated attacks on one busy machine."""
        first = make_alert(
            "SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="203.0.113.10", user="alice"
        )
        second = make_alert(
            "SSH_BRUTE_FORCE", 60, "ALT-000002", src_ip="203.0.113.99", user="bob"
        )
        assert len(CorrelationEngine().run([first, second])) == 2

    def test_the_same_technique_from_two_sources_is_still_two_incidents(self, make_alert):
        """A shared ATT&CK technique is a supporting reason, never a grouping one."""
        first = make_alert(
            "SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="203.0.113.10", user="alice"
        )
        second = make_alert(
            "AUTH_INVALID_USER", 30, "ALT-000002", src_ip="203.0.113.50", user="bob"
        )
        assert first.mitre["technique_id"] == second.mitre["technique_id"]
        assert len(CorrelationEngine().run([first, second])) == 2

    def test_the_same_entity_far_apart_does_not_correlate(self, make_alert):
        first = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        second = make_alert("SSH_COMPROMISE_SUSPECTED", 7200, "ALT-000002")
        assert len(CorrelationEngine().run([first, second])) == 2

    def test_weak_host_only_matches_are_rejected_by_default(self, make_alert):
        first = make_alert(
            "SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="203.0.113.10", user=None
        )
        second = make_alert(
            "SUSPICIOUS_SUDO", 60, "ALT-000002", src_ip=None, user=None
        )
        default = CorrelationEngine()
        assert default.config.min_strength == CorrelationStrength.MEDIUM
        assert len(default.run([first, second])) == 2

    def test_weak_matches_are_accepted_only_when_asked_for(self, make_alert):
        first = make_alert(
            "SSH_BRUTE_FORCE", 0, "ALT-000001", src_ip="203.0.113.10", user=None
        )
        second = make_alert("SUSPICIOUS_SUDO", 60, "ALT-000002", src_ip=None, user=None)
        engine = CorrelationEngine(
            CorrelationConfig(min_strength=CorrelationStrength.WEAK)
        )
        assert len(engine.run([first, second])) == 1


class TestWindowBoundaries:
    @pytest.mark.parametrize(
        "gap_seconds,expected_incidents",
        [(0, 1), (600, 1), (900, 1), (901, 2), (3600, 2)],
    )
    def test_the_window_edge_is_where_it_says_it_is(
        self, make_alert, gap_seconds, expected_incidents
    ):
        """Default window is fifteen minutes; 900 s is in, 901 s is out."""
        first = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        second = make_alert("SSH_COMPROMISE_SUSPECTED", gap_seconds, "ALT-000002")
        incidents = CorrelationEngine().run([first, second])
        assert len(incidents) == expected_incidents

    def test_a_wider_window_reunites_them(self, make_alert):
        first = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        second = make_alert("SSH_COMPROMISE_SUSPECTED", 3600, "ALT-000002")
        engine = CorrelationEngine(CorrelationConfig(window_seconds=7200))
        assert len(engine.run([first, second])) == 1


class TestIncidentDeduplication:
    def test_a_continuing_attack_extends_one_incident(self, make_alert):
        """Ten alerts from one adversary are one incident, not ten."""
        alerts = [
            make_alert("SSH_BRUTE_FORCE", index * 300, f"ALT-{index + 1:06d}")
            for index in range(10)
        ]
        incidents = CorrelationEngine().run(alerts)
        assert len(incidents) == 1
        assert incidents[0].incident_id == "INC-000001"
        assert incidents[0].alert_count == 10

    def test_rerunning_correlation_over_stored_alerts_creates_nothing(
        self, make_alert, tmp_path
    ):
        alerts = [
            make_alert("SSH_BRUTE_FORCE", index * 120, f"ALT-{index + 1:06d}")
            for index in range(4)
        ]
        first_run = CorrelationEngine().run(alerts)
        db_path = str(tmp_path / "incidents.db")
        with IncidentStore(db_path) as store:
            store.save_all(first_run)
            stored = store.list_incidents()

        engine = CorrelationEngine()
        second_run = engine.run(alerts, existing_incidents=stored)
        assert second_run == []
        assert engine.stats.alerts_duplicate == len(alerts)
        assert engine.stats.incidents_created == 0

    def test_new_activity_updates_the_existing_incident(self, make_alert, tmp_path):
        early = [
            make_alert("SSH_BRUTE_FORCE", index * 60, f"ALT-{index + 1:06d}")
            for index in range(3)
        ]
        first_run = CorrelationEngine().run(early)
        db_path = str(tmp_path / "incidents.db")
        with IncidentStore(db_path) as store:
            store.save_all(first_run)
            stored = store.list_incidents()

        later = [make_alert("SSH_COMPROMISE_SUSPECTED", 300, "ALT-000004")]
        engine = CorrelationEngine()
        updated = engine.run(later, existing_incidents=stored)
        assert len(updated) == 1
        assert updated[0].incident_id == "INC-000001"
        assert engine.stats.incidents_created == 0
        assert engine.stats.incidents_updated == 1

    def test_a_closed_incident_does_not_absorb_new_alerts(self, make_alert):
        first = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        incidents = CorrelationEngine().run([first])
        incidents[0].status = IncidentStatus.RESOLVED
        second = make_alert("SSH_COMPROMISE_SUSPECTED", 120, "ALT-000002")
        engine = CorrelationEngine()
        produced = engine.run([second], existing_incidents=incidents)
        assert len(produced) == 1
        assert produced[0].incident_id != "INC-000001"

    def test_incident_ids_continue_from_what_is_stored(self, make_alert):
        existing = CorrelationEngine().run([make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")])
        unrelated = make_alert(
            "SSH_BRUTE_FORCE", 60, "ALT-000002", host="other-host", src_ip="203.0.113.77"
        )
        produced = CorrelationEngine().run([unrelated], existing_incidents=existing)
        assert produced[0].incident_id == "INC-000002"


def _reference_index(engine, incident):
    """What the index used to be: a full rescan of the incident's alerts."""
    from sentinelforge.correlation.engine import _techniques

    found = set()
    for alert in incident.alerts:
        found |= _techniques(alert)
    return found


class TestCorrelationOptimisationIsBehaviourPreserving:
    """The cached ATT&CK index must answer exactly what a full rescan would.

    Phase 8 benchmarking found the original per-alert rescan made a long-running
    incident quadratic in its own size. The cache that replaced it is only
    legitimate if it never changes a verdict, so that equivalence is asserted
    rather than assumed.
    """

    def test_the_cached_index_matches_a_full_rescan(self, make_alert, monkeypatch):
        import json

        alerts = [
            make_alert(rule_id, offset, f"ALT-{index + 1:06d}")
            for index, (rule_id, offset) in enumerate(
                [
                    ("SSH_BRUTE_FORCE", 0),
                    ("SSH_COMPROMISE_SUSPECTED", 120),
                    ("SUSPICIOUS_SUDO", 240),
                    ("AUTH_INVALID_USER", 360),
                    ("AUTH_ROOT_LOGIN_REMOTE", 480),
                ]
            )
        ]
        cached = json.dumps(
            [inc.to_dict() for inc in CorrelationEngine().run(alerts)], sort_keys=True
        )
        monkeypatch.setattr(CorrelationEngine, "_technique_index", _reference_index)
        rescanned = json.dumps(
            [inc.to_dict() for inc in CorrelationEngine().run(alerts)], sort_keys=True
        )
        assert cached == rescanned

    def test_an_incident_built_elsewhere_is_indexed_on_first_use(self, make_alert):
        """An incident loaded from the database has no cache entry yet."""
        existing = CorrelationEngine().run(
            [make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")]
        )
        engine = CorrelationEngine()
        assert engine._technique_index(existing[0]) == {"T1110", "T1110.001"}


class TestPipelineCorrelation:
    def test_two_simultaneous_attacks_on_one_host_stay_separate(self):
        """End to end, from events: one host, two adversaries, two incidents."""
        from sentinelforge.detection.engine import DetectionEngine

        events = []
        for index in range(6):
            events.append(ssh_failure(index * 20, BASE_TIME, "203.0.113.10", "alice"))
            events.append(ssh_failure(index * 20 + 5, BASE_TIME, "203.0.113.99", "bob"))
        alerts = DetectionEngine().run(events)
        incidents = CorrelationEngine().run(alerts)
        assert len(alerts) == 2
        assert len(incidents) == 2
        assert {inc.source_ips[0] for inc in incidents} == {"203.0.113.10", "203.0.113.99"}

    def test_one_adversary_across_stages_stays_one_incident(self):
        from sentinelforge.detection.engine import DetectionEngine

        events = [ssh_failure(i * 20, BASE_TIME, "203.0.113.10", "deploy") for i in range(6)]
        events.append(ssh_success(140, BASE_TIME, "203.0.113.10", "deploy"))
        alerts = DetectionEngine().run(events)
        incidents = CorrelationEngine().run(alerts)
        assert len(alerts) == 2
        assert len(incidents) == 1
