"""Tests for the AI output contract (Phase 5).

The rule under test: a provider's answer only becomes data after it satisfies
the schema.  Anything else is a failure, never a partially trusted analysis.
"""

import json

import pytest

from sentinelforge.ai.schemas import (
    AIAnalysisAudit,
    AIIncidentAnalysis,
    AnalysisStatus,
    Assessment,
    AttackStage,
    MAX_LIST_ITEMS,
    Priority,
    Relevance,
    SCHEMA_VERSION,
    SchemaValidationError,
    decode_json_object,
    parse_analysis,
    parse_analysis_text,
    response_json_schema,
)
from sentinelforge.models.event import Severity


def valid_payload(**overrides) -> dict:
    payload = {
        "incident_id": "INC-000001",
        "assessment": "likely_malicious",
        "confidence": 0.91,
        "summary": "A possible SSH compromise followed by privilege escalation.",
        "severity_assessment": "critical",
        "attack_stage": "post_compromise",
        "mitre_analysis": [
            {
                "technique_id": "T1110",
                "technique": "Brute Force",
                "relevance": "observed",
                "rationale": "Five failed authentications precede the success.",
            }
        ],
        "key_evidence": [
            {"observation": "5 failed SSH authentications", "significance": "password guessing"}
        ],
        "false_positive_indicators": ["source is an internal address - requires verification"],
        "investigation_steps": ["Verify the successful SSH login with the account owner."],
        "recommended_actions": [
            {"action": "review_account_session", "priority": "high", "reason": "Login followed failures."}
        ],
        "reasoning": "Observed: failures then a success. Inferred: possible compromise.",
    }
    payload.update(overrides)
    return payload


class TestValidResponses:
    def test_full_response_parses(self):
        analysis = parse_analysis(valid_payload())
        assert analysis.ok
        assert analysis.status == AnalysisStatus.OK
        assert analysis.assessment == Assessment.LIKELY_MALICIOUS
        assert analysis.confidence == 0.91
        assert analysis.severity_assessment == Severity.CRITICAL
        assert analysis.attack_stage == AttackStage.POST_COMPROMISE
        assert analysis.mitre_analysis[0].technique_id == "T1110"
        assert analysis.key_evidence[0].observation.startswith("5 failed")
        assert analysis.recommended_actions[0].priority == Priority.HIGH

    def test_enum_values_are_normalized(self):
        analysis = parse_analysis(
            valid_payload(assessment="Likely Malicious", attack_stage="post-compromise")
        )
        assert analysis.assessment == Assessment.LIKELY_MALICIOUS
        assert analysis.attack_stage == AttackStage.POST_COMPROMISE

    def test_incident_id_argument_wins_over_the_model(self):
        """The model does not get to decide which incident it analyzed."""
        analysis = parse_analysis(
            valid_payload(incident_id="INC-999999"), incident_id="INC-000001"
        )
        assert analysis.incident_id == "INC-000001"

    def test_optional_lists_may_be_missing(self):
        payload = valid_payload()
        for key in (
            "mitre_analysis",
            "key_evidence",
            "false_positive_indicators",
            "investigation_steps",
            "recommended_actions",
            "reasoning",
        ):
            payload.pop(key)
        analysis = parse_analysis(payload)
        assert analysis.ok
        assert analysis.key_evidence == []
        assert analysis.reasoning == ""

    def test_plain_strings_are_accepted_as_list_items(self):
        analysis = parse_analysis(
            valid_payload(
                key_evidence=["5 failed SSH authentications"],
                recommended_actions=["review_account_session"],
                mitre_analysis=["T1110"],
            )
        )
        assert analysis.key_evidence[0].observation == "5 failed SSH authentications"
        assert analysis.recommended_actions[0].action == "review_account_session"
        assert analysis.recommended_actions[0].priority == Priority.MEDIUM
        assert analysis.mitre_analysis[0].technique_id == "T1110"

    def test_unknown_nested_enum_falls_back_instead_of_failing(self):
        """A bad supporting value must not throw away an otherwise good analysis."""
        analysis = parse_analysis(
            valid_payload(
                mitre_analysis=[{"technique_id": "T1110", "relevance": "definitely"}],
                recommended_actions=[{"action": "isolate", "priority": "urgent"}],
            )
        )
        assert analysis.mitre_analysis[0].relevance == Relevance.POSSIBLE
        assert analysis.recommended_actions[0].priority == Priority.MEDIUM

    def test_lists_are_capped(self):
        analysis = parse_analysis(
            valid_payload(investigation_steps=[f"step {i}" for i in range(50)])
        )
        assert len(analysis.investigation_steps) == MAX_LIST_ITEMS

    def test_long_text_is_truncated_visibly(self):
        analysis = parse_analysis(valid_payload(summary="x" * 5000))
        assert len(analysis.summary) < 5000
        assert analysis.summary.endswith("…")


class TestInvalidResponses:
    def test_non_object_payload(self):
        with pytest.raises(SchemaValidationError):
            parse_analysis(["not", "an", "object"])

    @pytest.mark.parametrize("field", ["assessment", "confidence", "summary", "severity_assessment"])
    def test_missing_required_field(self, field):
        payload = valid_payload()
        payload.pop(field)
        with pytest.raises(SchemaValidationError) as excinfo:
            parse_analysis(payload)
        assert field in str(excinfo.value)

    def test_unknown_assessment(self):
        with pytest.raises(SchemaValidationError):
            parse_analysis(valid_payload(assessment="definitely_evil"))

    def test_unknown_severity(self):
        with pytest.raises(SchemaValidationError):
            parse_analysis(valid_payload(severity_assessment="apocalyptic"))

    @pytest.mark.parametrize("confidence", [1.5, -0.1, 42, "high", None, float("nan")])
    def test_invalid_confidence(self, confidence):
        with pytest.raises(SchemaValidationError):
            parse_analysis(valid_payload(confidence=confidence))

    def test_empty_summary(self):
        with pytest.raises(SchemaValidationError):
            parse_analysis(valid_payload(summary="   "))

    def test_unknown_attack_stage_degrades_to_unknown(self):
        analysis = parse_analysis(valid_payload(attack_stage="stage 7"))
        assert analysis.attack_stage == AttackStage.UNKNOWN


class TestTextDecoding:
    def test_plain_json(self):
        analysis = parse_analysis_text(json.dumps(valid_payload()))
        assert analysis.ok

    def test_code_fenced_json(self):
        text = "```json\n" + json.dumps(valid_payload()) + "\n```"
        assert parse_analysis_text(text).ok

    def test_json_wrapped_in_prose(self):
        text = "Sure, here is the analysis:\n" + json.dumps(valid_payload()) + "\nHope that helps!"
        assert parse_analysis_text(text).ok

    def test_empty_response(self):
        with pytest.raises(SchemaValidationError):
            parse_analysis_text("   ")

    def test_no_json_at_all(self):
        with pytest.raises(SchemaValidationError):
            parse_analysis_text("I cannot help with that.")

    def test_malformed_json(self):
        with pytest.raises(SchemaValidationError):
            decode_json_object('{"assessment": "likely_malicious", ')


class TestFailedAnalysis:
    def test_failure_state_claims_nothing(self):
        analysis = AIIncidentAnalysis.failed("INC-000001", "provider timed out")
        assert not analysis.ok
        assert analysis.status == AnalysisStatus.FAILED
        assert analysis.assessment == Assessment.UNAVAILABLE
        assert analysis.confidence == 0.0
        assert analysis.summary == ""
        assert analysis.key_evidence == []
        assert "timed out" in analysis.error

    def test_failure_has_no_severity_disagreement(self):
        analysis = AIIncidentAnalysis.failed("INC-000001", "boom")
        analysis.deterministic_severity = Severity.HIGH
        assert analysis.severity_disagreement is False


class TestSeverityDisagreement:
    def test_disagreement_is_exposed_not_resolved(self):
        analysis = parse_analysis(valid_payload(severity_assessment="critical"))
        analysis.deterministic_severity = Severity.HIGH
        analysis.deterministic_score = 78
        data = analysis.to_dict()
        assert data["severity_disagreement"] is True
        assert data["deterministic_severity"] == "high"
        assert data["deterministic_score"] == 78
        assert data["severity_assessment"] == "critical"

    def test_agreement_is_not_flagged(self):
        analysis = parse_analysis(valid_payload(severity_assessment="high"))
        analysis.deterministic_severity = Severity.HIGH
        assert analysis.severity_disagreement is False


class TestRoundTrip:
    def test_to_dict_from_dict_preserves_content(self):
        analysis = parse_analysis(valid_payload())
        analysis.deterministic_severity = Severity.CRITICAL
        analysis.deterministic_score = 94
        analysis.audit = AIAnalysisAudit(
            analysis_id="abc", provider="mock", model="m", incident_version="deadbeef"
        )
        restored = AIIncidentAnalysis.from_dict(json.loads(analysis.to_json()))
        assert restored.to_dict() == analysis.to_dict()

    def test_audit_never_carries_a_key_field(self):
        audit = AIAnalysisAudit(provider="openai", model="m").to_dict()
        assert not any("key" in name and name != "error_kind" for name in audit)


class TestJSONSchema:
    def test_schema_matches_the_validated_fields(self):
        schema = response_json_schema()
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) <= set(schema["properties"])
        assert schema["properties"]["assessment"]["enum"] == list(Assessment.ALL)
        assert schema["properties"]["confidence"]["minimum"] == 0.0
        assert schema["properties"]["confidence"]["maximum"] == 1.0

    def test_schema_version_is_recorded(self):
        assert AIAnalysisAudit().schema_version == SCHEMA_VERSION
