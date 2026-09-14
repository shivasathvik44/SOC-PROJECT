"""The AI SOC analyst (Phase 5).

Position in the pipeline::

    logs / eBPF -> events -> deterministic detection -> alerts
                -> correlation -> incident -> AI SOC analyst -> analysis

Everything to the left of the analyst happens without it, and keeps happening
when it is unavailable.  The analyst reads a finished incident and produces a
reading of it; it never creates, scores, merges or closes anything.

What this class will not do, by construction:

* execute a command, a script, or any provider-suggested action -- a
  ``recommended_actions`` entry is a string in a dataclass and nothing dispatches
  on it;
* read the host -- the provider sees the incident that was handed in, nothing else;
* change an incident's deterministic fields -- it writes exactly one optional
  slot, ``incident.ai_analysis``, and only when asked to;
* raise on provider failure -- a failed analysis is a value, so a broken API key
  cannot take down a SOC pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..models.event import utc_now
from ..models.incident import Incident
from .cache import AnalysisCache, MemoryAnalysisCache, NullAnalysisCache, cache_key
from .client import LLMClient, LLMConfig
from .prompts import (
    FENCE_MARKERS,
    PROMPT_VERSION,
    build_prompts,
    retry_instruction,
)
from .sanitizer import ContextLimits, build_incident_context
from .schemas import (
    AIAnalysisAudit,
    AIIncidentAnalysis,
    AnalysisStatus,
    SCHEMA_VERSION,
    SchemaValidationError,
    parse_analysis_text,
)
from .providers import ProviderError

LOGGER = logging.getLogger(__name__)


@dataclass
class AnalystConfig:
    """How the analyst behaves, independently of which provider it talks to.

    Args:
        limits: Bounds on how much of an incident is sent (cost control).
        use_cache: Reuse a stored analysis for an unchanged incident version.
        max_validation_attempts: How many times a response that fails schema
            validation is re-requested.  Bounded and small: a model that cannot
            produce the schema twice will not produce it on the tenth try, and
            every attempt costs the user money.
    """

    limits: ContextLimits = field(default_factory=ContextLimits)
    use_cache: bool = True
    max_validation_attempts: int = 2


class AISocAnalyst:
    """Turns one incident into one validated :class:`AIIncidentAnalysis`.

    Args:
        client: The configured :class:`LLMClient`.
        config: Analyst behaviour (limits, caching, retries).
        cache: Where completed analyses are stored.  Defaults to an in-process
            cache; the CLI supplies a file-backed one.
        clock: Injectable timestamp source, for deterministic tests.
    """

    def __init__(
        self,
        client: LLMClient,
        config: AnalystConfig | None = None,
        cache: AnalysisCache | None = None,
        clock=utc_now,
    ) -> None:
        self.client = client
        self.config = config or AnalystConfig()
        self.cache = cache if cache is not None else MemoryAnalysisCache()
        if not self.config.use_cache:
            self.cache = NullAnalysisCache()
        self._clock = clock

    @classmethod
    def from_env(cls, cache: AnalysisCache | None = None, **overrides) -> "AISocAnalyst":
        """Build an analyst from environment configuration (see :class:`LLMConfig`)."""
        return cls(LLMClient.from_config(LLMConfig.from_env(**overrides)), cache=cache)

    # -- the one operation -------------------------------------------------
    def analyze(self, incident: Incident, refresh: bool = False) -> AIIncidentAnalysis:
        """Analyze one incident.  Never raises for a provider problem.

        Args:
            incident: A finished incident from the correlation engine.
            refresh: Ignore any cached analysis and ask the provider again.

        Returns:
            A validated analysis, or -- on any provider or validation failure --
            an :class:`AIIncidentAnalysis` with ``status == "failed"`` that
            carries the reason and claims nothing about the incident.
        """
        version = incident.version
        provider_name = getattr(self.client.provider, "name", "unknown")
        model = getattr(self.client.provider, "model", "") or ""
        key = cache_key(
            incident.incident_id, version, provider_name, model, PROMPT_VERSION, SCHEMA_VERSION
        )

        if not refresh:
            cached = self.cache.get(key)
            if cached is not None:
                LOGGER.info(
                    "using cached AI analysis for %s (version %s)",
                    incident.incident_id,
                    version,
                )
                analysis = AIIncidentAnalysis.from_dict(cached)
                analysis.audit = AIAnalysisAudit.from_dict(
                    {**analysis.audit.to_dict(), "cached": True}
                )
                return analysis

        context = build_incident_context(
            incident, limits=self.config.limits, markers=FENCE_MARKERS
        )
        system_prompt, user_prompt = build_prompts(context)

        def audit(status: str, confidence: float, attempts: int, error_kind=None) -> AIAnalysisAudit:
            return AIAnalysisAudit(
                analysis_id=key,
                provider=provider_name,
                model=model,
                is_mock=self.client.is_mock,
                prompt_version=PROMPT_VERSION,
                schema_version=SCHEMA_VERSION,
                incident_version=version,
                analyzed_at=self._clock(),
                status=status,
                confidence=confidence,
                cached=False,
                attempts=attempts,
                truncated=list(context.truncated),
                redactions=dict(context.redactions),
                error_kind=error_kind,
            )

        attempts = max(1, int(self.config.max_validation_attempts))
        prompt = user_prompt
        last_error: str = "analysis did not run"
        last_kind: str = "unknown"

        for attempt in range(1, attempts + 1):
            try:
                response = self.client.analyze(system_prompt, prompt)
            except ProviderError as exc:
                # Provider failures are terminal for this run: the client has
                # already retried whatever was worth retrying.
                LOGGER.error(
                    "AI analysis of %s failed (%s): %s", incident.incident_id, exc.kind, exc
                )
                # The remedy (when the provider offers one) names the variable
                # or command *the user* can fix, never a key or a secret.
                remedy = getattr(exc, "remedy", None)
                return AIIncidentAnalysis.failed(
                    incident.incident_id,
                    error=f"{exc} - {remedy}" if remedy else str(exc),
                    audit=audit(AnalysisStatus.FAILED, 0.0, attempt, exc.kind),
                )
            except Exception as exc:  # pragma: no cover - provider bug, not an API failure
                LOGGER.exception("AI provider raised an unexpected error")
                return AIIncidentAnalysis.failed(
                    incident.incident_id,
                    error=f"provider raised {type(exc).__name__}: {exc}",
                    audit=audit(AnalysisStatus.FAILED, 0.0, attempt, "provider_exception"),
                )

            try:
                analysis = parse_analysis_text(response.text, incident_id=incident.incident_id)
            except SchemaValidationError as exc:
                last_error, last_kind = str(exc), "invalid_response"
                LOGGER.warning(
                    "AI response for %s failed validation (attempt %d/%d): %s",
                    incident.incident_id,
                    attempt,
                    attempts,
                    exc,
                )
                if attempt < attempts:
                    prompt = user_prompt + retry_instruction(str(exc))
                continue

            analysis.deterministic_severity = incident.severity
            analysis.deterministic_score = int(incident.risk_score)
            analysis.audit = audit(AnalysisStatus.OK, analysis.confidence, attempt)
            if analysis.severity_disagreement:
                LOGGER.info(
                    "%s: AI severity '%s' differs from deterministic '%s' (score %d)",
                    incident.incident_id,
                    analysis.severity_assessment,
                    incident.severity,
                    incident.risk_score,
                )
            self.cache.put(key, analysis.to_dict())
            return analysis

        return AIIncidentAnalysis.failed(
            incident.incident_id,
            error=f"provider response failed validation after {attempts} attempt(s): {last_error}",
            audit=audit(AnalysisStatus.FAILED, 0.0, attempts, last_kind),
        )


def attach_analysis(incident: Incident, analysis: AIIncidentAnalysis) -> Incident:
    """Store an analysis on an incident, leaving every other field untouched.

    The deterministic severity, risk score, alerts and timeline are *not*
    modified -- the analysis goes in its own slot next to them.  A one-line
    summary is mirrored into ``incident.summary`` only when the analysis
    succeeded, so a failed run never puts prose on an incident.
    """
    incident.ai_analysis = analysis.to_dict()
    if analysis.ok and analysis.summary:
        incident.summary = analysis.summary
    return incident
