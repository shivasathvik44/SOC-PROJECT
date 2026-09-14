"""AI SOC analyst layer (Phase 5).

An assistant on top of the deterministic pipeline, never a replacement for it::

    logs / eBPF -> events -> detection -> alerts -> correlation -> incident
                -> AI SOC analyst -> summary / evidence reading / next steps

The boundary is enforced by structure, not by policy: the provider interface
(:class:`~sentinelforge.ai.providers.LLMProvider`) has one method that takes two
strings and returns text.  There is no tool calling, no shell, no filesystem
access and no way for a model to change an incident.
"""

from .analyst import AISocAnalyst, AnalystConfig, attach_analysis
from .cache import AnalysisCache, FileAnalysisCache, MemoryAnalysisCache, cache_key
from .client import LLMClient, LLMConfig
from .prompts import PROMPT_VERSION, build_prompts
from .sanitizer import ContextLimits, IncidentContext, Sanitizer, build_incident_context, redact
from .schemas import (
    AIAnalysisAudit,
    AIIncidentAnalysis,
    AnalysisStatus,
    Assessment,
    AttackStage,
    SCHEMA_VERSION,
    SchemaValidationError,
    parse_analysis,
    parse_analysis_text,
)

__all__ = [
    "AIAnalysisAudit",
    "AIIncidentAnalysis",
    "AISocAnalyst",
    "AnalysisCache",
    "AnalysisStatus",
    "AnalystConfig",
    "Assessment",
    "AttackStage",
    "ContextLimits",
    "FileAnalysisCache",
    "IncidentContext",
    "LLMClient",
    "LLMConfig",
    "MemoryAnalysisCache",
    "PROMPT_VERSION",
    "SCHEMA_VERSION",
    "Sanitizer",
    "SchemaValidationError",
    "attach_analysis",
    "build_incident_context",
    "build_prompts",
    "cache_key",
    "parse_analysis",
    "parse_analysis_text",
    "redact",
]
