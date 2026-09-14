"""Tests for the AI SOC analyst, caching and incident integration (Phase 5).

Central claims under test:

* incident -> analyst -> a validated ``AIIncidentAnalysis``;
* a provider failure produces a failed analysis, never an exception and never
  an invented one;
* the deterministic score survives whatever the AI says;
* an incident is valid with and without an analysis.
"""

import json

import pytest

from conftest import make_alert
from sentinelforge.ai.analyst import AISocAnalyst, AnalystConfig, attach_analysis
from sentinelforge.ai.cache import (
    FileAnalysisCache,
    MemoryAnalysisCache,
    NullAnalysisCache,
    cache_key,
)
from sentinelforge.ai.client import LLMClient, LLMConfig
from sentinelforge.ai.prompts import PROMPT_VERSION
from sentinelforge.ai.providers import (
    LLMProvider,
    ProviderAuthError,
    ProviderResponse,
    ProviderTimeoutError,
)
from sentinelforge.ai.providers.mock import MockProvider
from sentinelforge.ai.sanitizer import ContextLimits
from sentinelforge.ai.schemas import SCHEMA_VERSION, AnalysisStatus, Assessment
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.models.event import Severity
from sentinelforge.models.incident import Incident
from sentinelforge.storage.sqlite import IncidentStore

VALID_RESPONSE = json.dumps(
    {
        "assessment": "likely_malicious",
        "confidence": 0.88,
        "summary": "Possible SSH compromise followed by privilege escalation.",
        "severity_assessment": "critical",
        "attack_stage": "post_compromise",
        "key_evidence": [{"observation": "5 failed logins", "significance": "guessing"}],
        "investigation_steps": ["Verify the successful login."],
        "recommended_actions": [
            {"action": "review_account_session", "priority": "high", "reason": "because"}
        ],
        "false_positive_indicators": ["may be an admin host - requires verification"],
        "reasoning": "Observed failures then success.",
    }
)


class ScriptedProvider(LLMProvider):
    """Returns queued responses or raises queued errors, in order."""

    name = "scripted"

    def __init__(self, script, model="scripted-model"):
        self.script = list(script)
        self.model = model
        self.calls = 0
        self.prompts = []

    def analyze(self, system_prompt, user_prompt):
        self.calls += 1
        self.prompts.append((system_prompt, user_prompt))
        item = self.script.pop(0) if self.script else self.script_default()
        if isinstance(item, Exception):
            raise item
        return ProviderResponse(item, self.name, self.model)

    def script_default(self):
        return VALID_RESPONSE


def analyst_for(provider, **kwargs):
    client = LLMClient(provider, LLMConfig(max_attempts=1), sleep=lambda _: None)
    cache = kwargs.pop("cache", MemoryAnalysisCache())
    return AISocAnalyst(client, AnalystConfig(**kwargs), cache=cache, clock=lambda: "2026-09-13T00:00:00Z")


class TestHappyPath:
    def test_incident_becomes_a_validated_analysis(self, compromise_incident):
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(compromise_incident)
        assert analysis.ok
        assert analysis.incident_id == "INC-000001"
        assert analysis.assessment == Assessment.LIKELY_MALICIOUS
        assert analysis.confidence == 0.88
        assert analysis.investigation_steps

    def test_deterministic_fields_come_from_the_incident(self, compromise_incident):
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(compromise_incident)
        assert analysis.deterministic_severity == compromise_incident.severity
        assert analysis.deterministic_score == compromise_incident.risk_score

    def test_the_ai_cannot_change_the_incident(self, compromise_incident):
        before = compromise_incident.to_dict()
        analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(compromise_incident)
        assert compromise_incident.to_dict() == before

    def test_severity_disagreement_is_exposed(self):
        alert = make_alert("AUTH_REPEATED_FAILURES", 0, "ALT-000001")
        incident = CorrelationEngine().run([alert])[0]
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(incident)
        assert analysis.severity_assessment == Severity.CRITICAL
        assert analysis.deterministic_severity == incident.severity
        assert analysis.severity_disagreement is True
        # ... and the deterministic score is untouched by the disagreement.
        assert analysis.deterministic_score == incident.risk_score

    def test_audit_trail_is_complete(self, compromise_incident):
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(compromise_incident)
        audit = analysis.audit
        assert audit.provider == "scripted"
        assert audit.model == "scripted-model"
        assert audit.prompt_version == PROMPT_VERSION
        assert audit.schema_version == SCHEMA_VERSION
        assert audit.incident_version == compromise_incident.version
        assert audit.analyzed_at == "2026-09-13T00:00:00Z"
        assert audit.status == AnalysisStatus.OK
        assert audit.confidence == 0.88
        assert audit.analysis_id
        assert audit.attempts == 1

    def test_audit_records_mock_provenance(self, compromise_incident):
        analysis = analyst_for(MockProvider()).analyze(compromise_incident)
        assert analysis.audit.is_mock is True
        assert "MOCK" in analysis.summary

    def test_audit_never_contains_a_key(self, compromise_incident):
        client = LLMClient(
            ScriptedProvider([VALID_RESPONSE]), LLMConfig(api_key="sk-secret"), sleep=lambda _: None
        )
        analysis = AISocAnalyst(client, cache=MemoryAnalysisCache()).analyze(compromise_incident)
        assert "sk-secret" not in json.dumps(analysis.to_dict())


class TestFailureHandling:
    def test_provider_error_returns_a_failed_analysis(self, compromise_incident):
        analysis = analyst_for(ScriptedProvider([ProviderTimeoutError("timed out")])).analyze(
            compromise_incident
        )
        assert not analysis.ok
        assert analysis.status == AnalysisStatus.FAILED
        assert "timed out" in analysis.error
        assert analysis.audit.error_kind == "timeout"
        assert analysis.summary == ""

    def test_missing_api_key_does_not_crash(self, compromise_incident):
        analysis = analyst_for(ScriptedProvider([ProviderAuthError("no API key")])).analyze(
            compromise_incident
        )
        assert not analysis.ok
        assert analysis.audit.error_kind == "missing_api_key"

    def test_malformed_json_is_retried_then_reported(self, compromise_incident):
        provider = ScriptedProvider(["not json at all", "still not json"])
        analysis = analyst_for(provider, max_validation_attempts=2).analyze(compromise_incident)
        assert provider.calls == 2
        assert not analysis.ok
        assert analysis.audit.error_kind == "invalid_response"

    def test_a_retry_can_recover(self, compromise_incident):
        provider = ScriptedProvider(["{{ broken", VALID_RESPONSE])
        analysis = analyst_for(provider, max_validation_attempts=2).analyze(compromise_incident)
        assert analysis.ok
        assert analysis.audit.attempts == 2

    def test_retry_prompt_explains_the_format_problem(self, compromise_incident):
        provider = ScriptedProvider(["nope", VALID_RESPONSE])
        analyst_for(provider, max_validation_attempts=2).analyze(compromise_incident)
        assert "JSON object" in provider.prompts[1][1]

    def test_invalid_confidence_is_rejected(self, compromise_incident):
        bad = json.dumps(
            {
                "assessment": "likely_malicious",
                "confidence": 9.9,
                "summary": "x",
                "severity_assessment": "critical",
            }
        )
        analysis = analyst_for(ScriptedProvider([bad]), max_validation_attempts=1).analyze(
            compromise_incident
        )
        assert not analysis.ok
        assert "confidence" in analysis.error

    def test_failures_are_never_cached(self, compromise_incident):
        cache = MemoryAnalysisCache()
        analyst = analyst_for(ScriptedProvider([ProviderTimeoutError("t")]), cache=cache)
        analyst.analyze(compromise_incident)
        assert cache._entries == {}

    def test_the_rest_of_the_pipeline_is_unaffected(self, compromise_incident, tmp_path):
        """Detection, correlation and persistence do not depend on the AI layer."""
        analysis = analyst_for(ScriptedProvider([ProviderTimeoutError("down")])).analyze(
            compromise_incident
        )
        assert not analysis.ok
        with IncidentStore(str(tmp_path / "db.sqlite")) as store:
            store.save(compromise_incident)
            restored = store.get("INC-000001")
        assert restored.risk_score == compromise_incident.risk_score
        assert restored.ai_analysis is None


class TestCaching:
    def test_same_incident_version_is_served_from_cache(self, compromise_incident):
        provider = ScriptedProvider([VALID_RESPONSE])
        analyst = analyst_for(provider)
        first = analyst.analyze(compromise_incident)
        second = analyst.analyze(compromise_incident)
        assert provider.calls == 1
        assert second.audit.cached is True
        assert first.summary == second.summary

    def test_a_changed_incident_is_analyzed_again(self, compromise_incident):
        provider = ScriptedProvider([VALID_RESPONSE, VALID_RESPONSE])
        analyst = analyst_for(provider)
        analyst.analyze(compromise_incident)
        before = compromise_incident.version

        # Correlation attaches a new alert: same id, different story.
        compromise_incident.alerts.append(make_alert("PORT_SCAN", 600, "ALT-000004"))
        assert compromise_incident.version != before

        analysis = analyst.analyze(compromise_incident)
        assert provider.calls == 2
        assert analysis.audit.cached is False
        assert analysis.audit.incident_version == compromise_incident.version

    def test_refresh_bypasses_the_cache(self, compromise_incident):
        provider = ScriptedProvider([VALID_RESPONSE, VALID_RESPONSE])
        analyst = analyst_for(provider)
        analyst.analyze(compromise_incident)
        analyst.analyze(compromise_incident, refresh=True)
        assert provider.calls == 2

    def test_use_cache_false_disables_it_entirely(self, compromise_incident):
        provider = ScriptedProvider([VALID_RESPONSE, VALID_RESPONSE])
        analyst = analyst_for(provider, use_cache=False)
        analyst.analyze(compromise_incident)
        analyst.analyze(compromise_incident)
        assert provider.calls == 2
        assert isinstance(analyst.cache, NullAnalysisCache)

    def test_cache_key_covers_everything_that_changes_the_answer(self):
        base = ("INC-000001", "v1", "openai", "model-a", "1.0", "1.0")
        key = cache_key(*base)
        for index in range(len(base)):
            changed = list(base)
            changed[index] = "different"
            assert cache_key(*changed) != key, f"field {index} must change the key"

    def test_file_cache_round_trip(self, tmp_path, compromise_incident):
        directory = str(tmp_path / "cache")
        provider = ScriptedProvider([VALID_RESPONSE])
        first = analyst_for(provider, cache=FileAnalysisCache(directory)).analyze(
            compromise_incident
        )
        # A second analyst, a fresh process's worth of state, same directory.
        second = analyst_for(ScriptedProvider([]), cache=FileAnalysisCache(directory)).analyze(
            compromise_incident
        )
        assert second.audit.cached is True
        assert second.summary == first.summary

    def test_file_cache_survives_an_unwritable_directory(self, compromise_incident):
        cache = FileAnalysisCache("/proc/definitely-not-writable/sentinelforge")
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE]), cache=cache).analyze(
            compromise_incident
        )
        assert analysis.ok  # a broken cache degrades, it does not fail the run

    def test_corrupt_cache_entry_is_ignored(self, tmp_path, compromise_incident):
        directory = tmp_path / "cache"
        directory.mkdir()
        cache = FileAnalysisCache(str(directory))
        key = cache_key("INC-000001", compromise_incident.version, "scripted", "scripted-model", PROMPT_VERSION, SCHEMA_VERSION)
        (directory / f"{key}.json").write_text("{ this is not json")
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE]), cache=cache).analyze(
            compromise_incident
        )
        assert analysis.ok
        assert analysis.audit.cached is False


class TestCostControl:
    def test_limits_bound_what_is_sent(self, compromise_incident):
        provider = ScriptedProvider([VALID_RESPONSE])
        analyst = analyst_for(provider, limits=ContextLimits(max_alerts=1, max_timeline_entries=2))
        analysis = analyst.analyze(compromise_incident)
        _, user_prompt = provider.prompts[0]
        assert user_prompt.count('"alert_id"') == 1
        assert analysis.audit.truncated

    def test_truncation_is_recorded_in_the_audit(self, compromise_incident):
        analyst = analyst_for(ScriptedProvider([VALID_RESPONSE]), limits=ContextLimits(max_alerts=1))
        analysis = analyst.analyze(compromise_incident)
        assert any("showing 1 of 3" in note for note in analysis.audit.truncated)

    def test_one_incident_is_one_call(self, compromise_incident):
        provider = ScriptedProvider([VALID_RESPONSE])
        analyst_for(provider).analyze(compromise_incident)
        assert provider.calls == 1


class TestIncidentIntegration:
    def test_incident_is_valid_without_an_analysis(self, compromise_incident):
        data = compromise_incident.to_dict()
        assert data["ai_analysis"] is None
        assert Incident.from_dict(data).ai_analysis is None

    def test_attach_stores_the_analysis_without_touching_deterministic_fields(
        self, compromise_incident
    ):
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(compromise_incident)
        severity, score, alerts = (
            compromise_incident.severity,
            compromise_incident.risk_score,
            compromise_incident.alert_count,
        )
        attach_analysis(compromise_incident, analysis)
        assert compromise_incident.severity == severity
        assert compromise_incident.risk_score == score
        assert compromise_incident.alert_count == alerts
        assert compromise_incident.ai_analysis["assessment"] == "likely_malicious"
        assert compromise_incident.summary == analysis.summary

    def test_a_failed_analysis_writes_no_prose(self, compromise_incident):
        analysis = analyst_for(ScriptedProvider([ProviderTimeoutError("t")])).analyze(
            compromise_incident
        )
        attach_analysis(compromise_incident, analysis)
        assert compromise_incident.summary is None
        assert compromise_incident.ai_analysis["status"] == AnalysisStatus.FAILED

    def test_analysis_survives_persistence(self, tmp_path, compromise_incident):
        analysis = analyst_for(ScriptedProvider([VALID_RESPONSE])).analyze(compromise_incident)
        attach_analysis(compromise_incident, analysis)
        with IncidentStore(str(tmp_path / "db.sqlite")) as store:
            store.save(compromise_incident)
            restored = store.get("INC-000001")
        assert restored.ai_analysis["confidence"] == 0.88
        assert restored.ai_analysis["audit"]["provider"] == "scripted"

    def test_old_incidents_without_the_field_still_load(self):
        """Backwards compatibility: Phase 3/4 JSON has no ``ai_analysis`` key."""
        legacy = {
            "incident_id": "INC-000042",
            "title": "Old incident",
            "severity": "high",
            "risk_score": 70,
            "alerts": [],
        }
        incident = Incident.from_dict(legacy)
        assert incident.ai_analysis is None
        assert incident.to_dict()["ai_analysis"] is None

    def test_version_ignores_lifecycle_and_analysis_changes(self, compromise_incident):
        """A human triaging an incident must not invalidate its analysis."""
        version = compromise_incident.version
        compromise_incident.status = "investigating"
        compromise_incident.ai_analysis = {"assessment": "likely_benign"}
        compromise_incident.summary = "someone wrote a summary"
        assert compromise_incident.version == version


class TestAnalystConstruction:
    def test_from_env_defaults_to_the_mock_provider(self, monkeypatch, compromise_incident):
        for name in ("SENTINELFORGE_LLM_PROVIDER", "SENTINELFORGE_LLM_MODEL"):
            monkeypatch.delenv(name, raising=False)
        analyst = AISocAnalyst.from_env(cache=MemoryAnalysisCache())
        assert analyst.client.is_mock
        assert analyst.analyze(compromise_incident).ok
