"""Built-in detection rules.

Adding a detection means adding a module here and listing its class in
:data:`RULE_CLASSES` -- the engine and the CLI pick it up automatically.
"""

from __future__ import annotations

from ..rule import Rule
from .port_scan import PortScanRule
from .process_execution import (
    SuspiciousNetworkConnectionRule,
    SuspiciousProcessExecutionRule,
)
from .ssh_bruteforce import SshBruteForceRule, SshCompromiseSuspectedRule
from .suspicious_auth import (
    InvalidUserProbeRule,
    RemotePrivilegedLoginRule,
    RepeatedAuthFailureRule,
)
from .suspicious_sudo import SudoPattern, SuspiciousSudoRule

#: Every rule class shipped with SentinelForge, in reporting order.
RULE_CLASSES: tuple[type[Rule], ...] = (
    SshBruteForceRule,
    SshCompromiseSuspectedRule,
    SuspiciousSudoRule,
    InvalidUserProbeRule,
    RepeatedAuthFailureRule,
    RemotePrivilegedLoginRule,
    SuspiciousProcessExecutionRule,
    SuspiciousNetworkConnectionRule,
    PortScanRule,
)


def default_rules() -> list[Rule]:
    """Instantiate every built-in rule with its default configuration."""
    return [rule_class() for rule_class in RULE_CLASSES]


__all__ = [
    "InvalidUserProbeRule",
    "PortScanRule",
    "RULE_CLASSES",
    "RemotePrivilegedLoginRule",
    "RepeatedAuthFailureRule",
    "SuspiciousNetworkConnectionRule",
    "SuspiciousProcessExecutionRule",
    "SshBruteForceRule",
    "SshCompromiseSuspectedRule",
    "SudoPattern",
    "SuspiciousSudoRule",
    "default_rules",
]
