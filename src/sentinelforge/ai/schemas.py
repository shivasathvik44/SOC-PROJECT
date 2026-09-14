"""Typed schema for AI analyst output (Phase 5).

The LLM returns text.  Text is not a data structure, so nothing in
SentinelForge ever consumes a provider's answer directly: it is parsed,
validated against the contract in this module, and only then becomes an
:class:`AIIncidentAnalysis`.  Anything that fails validation produces a
*failed* analysis, never a half-trusted one.

Two validation styles live here on purpose:

* **Strict** for the fields an analyst reads as a verdict -- ``assessment``,
  ``confidence``, ``severity_assessment``, ``summary``.  A wrong value there
  would mislead, so it fails the whole response.
* **Lenient but normalizing** for the supporting lists.  An unusable list item
  is dropped or coerced rather than discarding an otherwise good analysis, and
  every list is capped so a runaway response cannot flood the incident store.

The deterministic fields (``deterministic_severity``, ``deterministic_score``)
are filled in by the analyst from the incident itself.  The model is not asked
for them and cannot overwrite them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..models.event import Severity

#: Bumped when the output contract changes.  Stored with every analysis.
SCHEMA_VERSION = "1.0"


class SchemaValidationError(ValueError):
    """The provider's response did not satisfy the output contract."""


class Assessment:
    """What the AI thinks the incident is.

    Deliberately hedged: the deterministic engine decides whether something
    *fired*, the AI only offers a reading of it.
    """

    LIKELY_MALICIOUS = "likely_malicious"
    POSSIBLY_MALICIOUS = "possibly_malicious"
    LIKELY_BENIGN = "likely_benign"
    INCONCLUSIVE = "inconclusive"
    #: Not a verdict: the marker written when no analysis could be produced.
    UNAVAILABLE = "unavailable"

    #: The only values a provider may return.
    ALL = (LIKELY_MALICIOUS, POSSIBLY_MALICIOUS, LIKELY_BENIGN, INCONCLUSIVE)


class AttackStage:
    """Where in an intrusion the observed activity appears to sit."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    POST_COMPROMISE = "post_compromise"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"

    ALL = (
        RECONNAISSANCE,
        INITIAL_ACCESS,
        EXECUTION,
        POST_COMPROMISE,
        LATERAL_MOVEMENT,
        EXFILTRATION,
        IMPACT,
        UNKNOWN,
    )


class Priority:
    """Priority of a recommended action.  Recommendations only -- see analyst.py."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    ALL = (LOW, MEDIUM, HIGH)


class Relevance:
    """How strongly the evidence supports an ATT&CK technique."""

    OBSERVED = "observed"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"

    ALL = (OBSERVED, POSSIBLE, UNLIKELY)


class AnalysisStatus:
    """Whether an analysis actually happened."""

    OK = "ok"
    FAILED = "failed"

    ALL = (OK, FAILED)


# -- output size limits ----------------------------------------------------
# A provider can return arbitrarily long text.  These caps bound what gets
# stored in an incident and shown in a terminal; truncation is marked with an
# ellipsis rather than hidden.
MAX_SUMMARY_CHARS = 1200
MAX_REASONING_CHARS = 4000
MAX_ITEM_CHARS = 600
MAX_LIST_ITEMS = 12


def _normalize_enum(value: object) -> str:
    """Lower-case and underscore a model's enum-ish answer (``"Post-Compromise"``)."""
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _clean_text(value: object, limit: int = MAX_ITEM_CHARS) -> str:
    """Coerce to a single readable string, collapsed and length-capped."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _as_list(value: object) -> list:
    """Accept a list, a single item, or nothing."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@dataclass(frozen=True)
class MitreAssessment:
    """The AI's reading of one ATT&CK technique in the incident's context."""

    technique_id: str
    technique: str = ""
    relevance: str = Relevance.POSSIBLE
    rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique": self.technique,
            "relevance": self.relevance,
            "rationale": self.rationale,
        }

    @classmethod
    def parse(cls, data: object) -> "MitreAssessment | None":
        if isinstance(data, str):
            return cls(technique_id=_clean_text(data, 32)) if data.strip() else None
        if not isinstance(data, dict):
            return None
        technique_id = _clean_text(data.get("technique_id") or data.get("id"), 32)
        if not technique_id:
            return None
        relevance = _normalize_enum(data.get("relevance") or data.get("assessment"))
        return cls(
            technique_id=technique_id,
            technique=_clean_text(data.get("technique") or data.get("name"), 120),
            relevance=relevance if relevance in Relevance.ALL else Relevance.POSSIBLE,
            rationale=_clean_text(data.get("rationale") or data.get("reason")),
        )


@dataclass(frozen=True)
class KeyEvidence:
    """One thing the incident actually contains, plus why it matters.

    ``observation`` must stay descriptive ("5 failed SSH authentications");
    the interpretation belongs in ``significance``.  Keeping them in separate
    fields is what lets a reader tell evidence from inference at a glance.
    """

    observation: str
    significance: str = ""

    def to_dict(self) -> dict:
        return {"observation": self.observation, "significance": self.significance}

    @classmethod
    def parse(cls, data: object) -> "KeyEvidence | None":
        if isinstance(data, str):
            text = _clean_text(data)
            return cls(observation=text) if text else None
        if not isinstance(data, dict):
            return None
        observation = _clean_text(data.get("observation") or data.get("evidence"))
        if not observation:
            return None
        return cls(
            observation=observation,
            significance=_clean_text(data.get("significance") or data.get("why")),
        )


@dataclass(frozen=True)
class RecommendedAction:
    """A suggested action for a *human* analyst.

    SentinelForge never executes these.  There is no code path from this
    dataclass to a shell, a firewall, or a process.
    """

    action: str
    priority: str = Priority.MEDIUM
    reason: str = ""

    def to_dict(self) -> dict:
        return {"action": self.action, "priority": self.priority, "reason": self.reason}

    @classmethod
    def parse(cls, data: object) -> "RecommendedAction | None":
        if isinstance(data, str):
            text = _clean_text(data, 120)
            return cls(action=text) if text else None
        if not isinstance(data, dict):
            return None
        action = _clean_text(data.get("action") or data.get("name"), 120)
        if not action:
            return None
        priority = _normalize_enum(data.get("priority"))
        return cls(
            action=action,
            priority=priority if priority in Priority.ALL else Priority.MEDIUM,
            reason=_clean_text(data.get("reason") or data.get("rationale")),
        )


@dataclass(frozen=True)
class AIAnalysisAudit:
    """How an AI conclusion was produced.

    Never contains an API key, a prompt, or raw provider metadata beyond what
    is listed here.  It exists so a future analyst can ask "which model said
    this, about which version of the incident, under which prompt?".
    """

    analysis_id: str = ""
    provider: str = ""
    model: str = ""
    is_mock: bool = False
    prompt_version: str = ""
    schema_version: str = SCHEMA_VERSION
    incident_version: str = ""
    analyzed_at: str | None = None
    status: str = AnalysisStatus.OK
    confidence: float = 0.0
    cached: bool = False
    attempts: int = 0
    truncated: list[str] = field(default_factory=list)
    redactions: dict = field(default_factory=dict)
    error_kind: str | None = None

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "provider": self.provider,
            "model": self.model,
            "is_mock": self.is_mock,
            "prompt_version": self.prompt_version,
            "schema_version": self.schema_version,
            "incident_version": self.incident_version,
            "analyzed_at": self.analyzed_at,
            "status": self.status,
            "confidence": self.confidence,
            "cached": self.cached,
            "attempts": self.attempts,
            "truncated": list(self.truncated),
            "redactions": dict(self.redactions),
            "error_kind": self.error_kind,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "AIAnalysisAudit":
        data = data or {}
        return cls(
            analysis_id=str(data.get("analysis_id") or ""),
            provider=str(data.get("provider") or ""),
            model=str(data.get("model") or ""),
            is_mock=bool(data.get("is_mock")),
            prompt_version=str(data.get("prompt_version") or ""),
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            incident_version=str(data.get("incident_version") or ""),
            analyzed_at=data.get("analyzed_at"),
            status=data.get("status") or AnalysisStatus.OK,
            confidence=float(data.get("confidence") or 0.0),
            cached=bool(data.get("cached")),
            attempts=int(data.get("attempts") or 0),
            truncated=list(data.get("truncated") or []),
            redactions=dict(data.get("redactions") or {}),
            error_kind=data.get("error_kind"),
        )


@dataclass
class AIIncidentAnalysis:
    """A validated Tier-1 reading of one incident.

    The AI's own judgement (``assessment``, ``confidence``,
    ``severity_assessment``, ...) sits next to, and never replaces, the
    deterministic result (``deterministic_severity``, ``deterministic_score``).
    When the two disagree on severity, :attr:`severity_disagreement` says so
    instead of one silently winning.
    """

    incident_id: str
    status: str = AnalysisStatus.OK
    assessment: str = Assessment.INCONCLUSIVE
    confidence: float = 0.0
    summary: str = ""
    severity_assessment: str = Severity.MEDIUM
    attack_stage: str = AttackStage.UNKNOWN
    mitre_analysis: list[MitreAssessment] = field(default_factory=list)
    key_evidence: list[KeyEvidence] = field(default_factory=list)
    false_positive_indicators: list[str] = field(default_factory=list)
    investigation_steps: list[str] = field(default_factory=list)
    recommended_actions: list[RecommendedAction] = field(default_factory=list)
    reasoning: str = ""
    # -- deterministic context, supplied by the analyst, never by the model --
    deterministic_severity: str | None = None
    deterministic_score: int | None = None
    audit: AIAnalysisAudit = field(default_factory=AIAnalysisAudit)
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Whether a validated analysis was actually produced."""
        return self.status == AnalysisStatus.OK

    @property
    def severity_disagreement(self) -> bool:
        """Whether the AI's severity differs from the deterministic one."""
        if not self.ok or not self.deterministic_severity:
            return False
        return self.severity_assessment != self.deterministic_severity

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "assessment": self.assessment,
            "confidence": self.confidence,
            "summary": self.summary,
            "severity_assessment": self.severity_assessment,
            "deterministic_severity": self.deterministic_severity,
            "deterministic_score": self.deterministic_score,
            "severity_disagreement": self.severity_disagreement,
            "attack_stage": self.attack_stage,
            "mitre_analysis": [item.to_dict() for item in self.mitre_analysis],
            "key_evidence": [item.to_dict() for item in self.key_evidence],
            "false_positive_indicators": list(self.false_positive_indicators),
            "investigation_steps": list(self.investigation_steps),
            "recommended_actions": [item.to_dict() for item in self.recommended_actions],
            "reasoning": self.reasoning,
            "error": self.error,
            "audit": self.audit.to_dict(),
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "AIIncidentAnalysis":
        """Rebuild a stored analysis (e.g. from ``incident.ai_analysis``)."""
        return cls(
            incident_id=str(data.get("incident_id") or ""),
            status=data.get("status") or AnalysisStatus.OK,
            assessment=data.get("assessment") or Assessment.INCONCLUSIVE,
            confidence=float(data.get("confidence") or 0.0),
            summary=data.get("summary") or "",
            severity_assessment=data.get("severity_assessment") or Severity.MEDIUM,
            attack_stage=data.get("attack_stage") or AttackStage.UNKNOWN,
            mitre_analysis=[
                item
                for item in (MitreAssessment.parse(x) for x in data.get("mitre_analysis") or [])
                if item
            ],
            key_evidence=[
                item
                for item in (KeyEvidence.parse(x) for x in data.get("key_evidence") or [])
                if item
            ],
            false_positive_indicators=[
                _clean_text(x) for x in data.get("false_positive_indicators") or []
            ],
            investigation_steps=[_clean_text(x) for x in data.get("investigation_steps") or []],
            recommended_actions=[
                item
                for item in (
                    RecommendedAction.parse(x) for x in data.get("recommended_actions") or []
                )
                if item
            ],
            reasoning=data.get("reasoning") or "",
            deterministic_severity=data.get("deterministic_severity"),
            deterministic_score=data.get("deterministic_score"),
            audit=AIAnalysisAudit.from_dict(data.get("audit")),
            error=data.get("error"),
        )

    @classmethod
    def failed(
        cls,
        incident_id: str,
        error: str,
        audit: AIAnalysisAudit | None = None,
    ) -> "AIIncidentAnalysis":
        """A safe error state: explicitly *not* an analysis.

        Nothing is invented here -- no summary, no evidence, no confidence.
        Callers check :attr:`ok` (or ``status``) before believing anything.
        """
        audit = audit or AIAnalysisAudit()
        return cls(
            incident_id=incident_id,
            status=AnalysisStatus.FAILED,
            assessment=Assessment.UNAVAILABLE,
            confidence=0.0,
            summary="",
            error=error,
            audit=audit,
        )


def parse_analysis(payload: object, incident_id: str | None = None) -> AIIncidentAnalysis:
    """Validate a provider's decoded JSON into an :class:`AIIncidentAnalysis`.

    Args:
        payload: The decoded response object (already ``json.loads``-ed).
        incident_id: The incident actually being analyzed.  When given, it wins
            over whatever id the model echoed back: the model does not get to
            decide which incident its answer applies to.

    Raises:
        SchemaValidationError: for a non-object payload, a missing or unknown
            ``assessment`` / ``severity_assessment``, a missing or
            out-of-range ``confidence``, or an empty ``summary``.
    """
    if not isinstance(payload, dict):
        raise SchemaValidationError(
            f"expected a JSON object, got {type(payload).__name__}"
        )

    assessment = _normalize_enum(payload.get("assessment"))
    if not assessment:
        raise SchemaValidationError("missing required field 'assessment'")
    if assessment not in Assessment.ALL:
        raise SchemaValidationError(
            f"unknown assessment {assessment!r} (valid: {', '.join(Assessment.ALL)})"
        )

    if "confidence" not in payload or payload.get("confidence") is None:
        raise SchemaValidationError("missing required field 'confidence'")
    try:
        confidence = float(payload["confidence"])
    except (TypeError, ValueError):
        raise SchemaValidationError(
            f"confidence must be a number, got {payload['confidence']!r}"
        ) from None
    if confidence != confidence or not 0.0 <= confidence <= 1.0:  # NaN or out of range
        raise SchemaValidationError(
            f"confidence must be between 0.0 and 1.0, got {payload['confidence']!r}"
        )

    summary = _clean_text(payload.get("summary"), MAX_SUMMARY_CHARS)
    if not summary:
        raise SchemaValidationError("missing required field 'summary'")

    severity = _normalize_enum(payload.get("severity_assessment"))
    if not severity:
        raise SchemaValidationError("missing required field 'severity_assessment'")
    if severity not in Severity.ALL:
        raise SchemaValidationError(
            f"unknown severity_assessment {severity!r} (valid: {', '.join(Severity.ALL)})"
        )

    stage = _normalize_enum(payload.get("attack_stage"))
    if stage not in AttackStage.ALL:
        stage = AttackStage.UNKNOWN

    def _parsed(key: str, parser) -> list:
        items = []
        for raw in _as_list(payload.get(key))[:MAX_LIST_ITEMS]:
            parsed = parser(raw)
            if parsed is not None:
                items.append(parsed)
        return items

    return AIIncidentAnalysis(
        incident_id=str(incident_id or payload.get("incident_id") or ""),
        status=AnalysisStatus.OK,
        assessment=assessment,
        confidence=round(confidence, 4),
        summary=summary,
        severity_assessment=severity,
        attack_stage=stage,
        mitre_analysis=_parsed("mitre_analysis", MitreAssessment.parse),
        key_evidence=_parsed("key_evidence", KeyEvidence.parse),
        false_positive_indicators=[
            text
            for text in (
                _clean_text(item)
                for item in _as_list(payload.get("false_positive_indicators"))[:MAX_LIST_ITEMS]
            )
            if text
        ],
        investigation_steps=[
            text
            for text in (
                _clean_text(item)
                for item in _as_list(payload.get("investigation_steps"))[:MAX_LIST_ITEMS]
            )
            if text
        ],
        recommended_actions=_parsed("recommended_actions", RecommendedAction.parse),
        reasoning=_clean_text(payload.get("reasoning"), MAX_REASONING_CHARS),
    )


def parse_analysis_text(text: str, incident_id: str | None = None) -> AIIncidentAnalysis:
    """Decode a provider's raw text and validate it.

    Tolerates a JSON object wrapped in prose or a ``json`` code fence, which is
    the most common way a model deviates from "return only JSON".  Anything
    less recoverable than that is a validation failure.
    """
    payload = decode_json_object(text)
    return parse_analysis(payload, incident_id=incident_id)


def decode_json_object(text: str) -> dict:
    """Extract one JSON object from ``text``.

    Raises:
        SchemaValidationError: when no JSON object can be decoded.
    """
    if not isinstance(text, str) or not text.strip():
        raise SchemaValidationError("provider returned an empty response")
    candidate = text.strip()
    if candidate.startswith("```"):
        # ```json\n{...}\n```
        candidate = candidate.strip("`")
        if candidate.lower().startswith("json"):
            candidate = candidate[4:]
        candidate = candidate.strip()
    try:
        return json.loads(candidate)
    except ValueError:
        pass
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(candidate[start : end + 1])
        except ValueError as exc:
            raise SchemaValidationError(f"response is not valid JSON ({exc})") from None
    raise SchemaValidationError("response contains no JSON object")


def response_json_schema() -> dict:
    """The JSON Schema handed to providers that support structured output.

    Keeping the schema next to :func:`parse_analysis` is deliberate: the
    provider-side constraint and the local validation describe the same
    contract, and local validation runs either way.  A provider that honours
    the schema simply fails less often.
    """
    text = {"type": "string"}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "assessment",
            "confidence",
            "summary",
            "severity_assessment",
            "attack_stage",
            "mitre_analysis",
            "key_evidence",
            "false_positive_indicators",
            "investigation_steps",
            "recommended_actions",
            "reasoning",
        ],
        "properties": {
            "assessment": {"type": "string", "enum": list(Assessment.ALL)},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "summary": text,
            "severity_assessment": {"type": "string", "enum": list(Severity.ALL)},
            "attack_stage": {"type": "string", "enum": list(AttackStage.ALL)},
            "mitre_analysis": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["technique_id", "technique", "relevance", "rationale"],
                    "properties": {
                        "technique_id": text,
                        "technique": text,
                        "relevance": {"type": "string", "enum": list(Relevance.ALL)},
                        "rationale": text,
                    },
                },
            },
            "key_evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["observation", "significance"],
                    "properties": {"observation": text, "significance": text},
                },
            },
            "false_positive_indicators": {"type": "array", "items": text},
            "investigation_steps": {"type": "array", "items": text},
            "recommended_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["action", "priority", "reason"],
                    "properties": {
                        "action": text,
                        "priority": {"type": "string", "enum": list(Priority.ALL)},
                        "reason": text,
                    },
                },
            },
            "reasoning": text,
        },
    }
