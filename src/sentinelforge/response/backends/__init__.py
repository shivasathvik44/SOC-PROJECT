"""Containment backends: the adapters between an action and a system mechanism.

Every backend is detected, never assumed.  ``detect_backends`` returns the set
this host can actually support, and an unsupported mechanism yields a backend
that refuses cleanly with a reason and a remedy rather than one that improvises.
"""

from .base import BackendError, BackendStatus
from .firewall import (
    RULE_PREFIX,
    FirewalldBackend,
    FirewallBackend,
    UnsupportedFirewallBackend,
    build_rich_rule,
    detect_firewall_backend,
    rule_action_id,
)
from .mock import MockFirewallBackend, MockProcessBackend, MockSessionBackend
from .process import LinuxProcessBackend, ProcessBackend, ProcessInfo
from .session import (
    LoginctlSessionBackend,
    SessionBackend,
    UnsupportedSessionBackend,
    detect_session_backend,
)

__all__ = [
    "BackendError",
    "BackendStatus",
    "FirewallBackend",
    "FirewalldBackend",
    "UnsupportedFirewallBackend",
    "detect_firewall_backend",
    "build_rich_rule",
    "rule_action_id",
    "RULE_PREFIX",
    "ProcessBackend",
    "LinuxProcessBackend",
    "ProcessInfo",
    "SessionBackend",
    "LoginctlSessionBackend",
    "UnsupportedSessionBackend",
    "detect_session_backend",
    "MockFirewallBackend",
    "MockProcessBackend",
    "MockSessionBackend",
]
