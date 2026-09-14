"""Response and containment (Phase 7).

SentinelForge observes (Phases 1-4), explains (Phase 5) and displays (Phase 6).
This package is the first one that can change the system it monitors, and it is
built so that a human is always the thing that decides::

    AI recommends  ->  human approves  ->  policy validates  ->  executor acts
                                                             ->  result verified
                                                             ->  everything audited

There is no path from a log line, a telemetry field, an AI sentence or an HTTP
body to a command.  Targets are *parsed* into typed values (an IP address, a
PID), commands are fixed argument arrays built from those typed values, and the
one module that can start a process
(:mod:`sentinelforge.response.executor`) runs an allowlist of two programs with
``shell=False``.

Nothing here escalates privileges.  When an action needs root, SentinelForge
says so and stops.
"""

from .actions import (
    ACTION_HANDLERS,
    BlockIpAction,
    HostIsolationAction,
    KillProcessAction,
    ResponseActionHandler,
    ResponseBackends,
    TerminateSessionAction,
    UnblockIpAction,
    get_handler,
)
from .audit import AuditEvent, AuditLog, AuditRecord
from .engine import (
    ApprovalRequired,
    PolicyRefused,
    PrivilegeRequired,
    ResponseEngine,
    ResponseError,
)
from .models import (
    ActionOutcome,
    ActionPreview,
    ActionStatus,
    ActionType,
    InvalidTransition,
    ResponseAction,
    format_action_id,
)
from .policy import PolicyConfig, PolicyDecision, ResponsePolicy
from .validators import ValidationError

__all__ = [
    "ACTION_HANDLERS",
    "ActionOutcome",
    "ActionPreview",
    "ActionStatus",
    "ActionType",
    "ApprovalRequired",
    "AuditEvent",
    "AuditLog",
    "AuditRecord",
    "BlockIpAction",
    "HostIsolationAction",
    "InvalidTransition",
    "KillProcessAction",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyRefused",
    "PrivilegeRequired",
    "ResponseAction",
    "ResponseActionHandler",
    "ResponseBackends",
    "ResponseEngine",
    "ResponseError",
    "ResponsePolicy",
    "TerminateSessionAction",
    "UnblockIpAction",
    "ValidationError",
    "format_action_id",
    "get_handler",
]
