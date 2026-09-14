"""Phase 2: deterministic detection engine, rules and MITRE ATT&CK mapping.

Normalized Phase 1 events go in, security alerts come out:

    events -> Rule.evaluate() -> Detection -> risk scoring -> Alert

Nothing here executes, blocks, or changes anything -- detection only.
"""

from .engine import DetectionEngine, EngineConfig, EngineStats
from .mitre import MitreMapping, Tactic, Technique, mapping
from .risk import RiskAssessment, RiskFactor, assess_risk
from .rule import Detection, Rule

__all__ = [
    "Detection",
    "DetectionEngine",
    "EngineConfig",
    "EngineStats",
    "MitreMapping",
    "RiskAssessment",
    "RiskFactor",
    "Rule",
    "Tactic",
    "Technique",
    "assess_risk",
    "mapping",
]
