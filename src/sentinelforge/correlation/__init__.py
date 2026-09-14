"""Phase 3: correlation of alerts into incidents."""

from .chains import ATTACK_CHAINS, FUTURE_CHAINS, AttackChain, ChainStage, match_chains
from .engine import (
    DEFAULT_WINDOW_SECONDS,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationMatch,
    CorrelationStats,
    CorrelationStrength,
)
from .scoring import IncidentRisk, score_incident

__all__ = [
    "ATTACK_CHAINS",
    "DEFAULT_WINDOW_SECONDS",
    "FUTURE_CHAINS",
    "AttackChain",
    "ChainStage",
    "CorrelationConfig",
    "CorrelationEngine",
    "CorrelationMatch",
    "CorrelationStats",
    "CorrelationStrength",
    "IncidentRisk",
    "match_chains",
    "score_incident",
]
