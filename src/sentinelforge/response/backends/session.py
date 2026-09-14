"""Session containment backend (Phase 7).

Terminating a *session* is narrower than "disable this user", and that is the
whole point.  SentinelForge does not lock accounts, expire passwords, edit
``/etc/shadow`` or change anything about a user's ability to log in again: it
ends one specific systemd-logind session that an analyst has identified as
suspicious.  A broad "disable user" capability is deliberately absent, because
its blast radius (locking the only administrator out of the host mid-incident)
is far larger than what it buys during a Tier-1 response.

On Fedora, systemd-logind exposes exactly the mechanism this needs:
``loginctl terminate-session <id>`` ends one session and the processes in it.
Sessions are enumerable, attributable to a user, and identified by a short
opaque id -- so the action can be previewed, validated against a real session,
and verified afterwards.  Where logind is not present the backend reports
itself unavailable and the action is refused; there is no fallback that walks
the process table killing things that look like a login.

Two safety rules live here rather than in policy because they need session
facts: the analyst's *own* session is never a valid target (ending it would cut
the responder off mid-incident), and neither are the seat/manager sessions that
belong to the display stack rather than to a person.
"""

from __future__ import annotations

import logging
import os
import re
import time

from ..executor import CommandRunner, ExecutionError
from ..models import ActionOutcome
from ..validators import ValidationError, validate_session_id
from .base import BackendStatus

LOGGER = logging.getLogger(__name__)

#: ``loginctl show-session`` returns ``KEY=value`` lines; only these are read.
_INTERESTING_FIELDS = (
    "Id", "User", "Name", "State", "Type", "Class", "Remote", "RemoteHost",
    "Service", "TTY", "Display", "Leader", "Timestamp",
)

_KEY_VALUE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?P<value>.*)$")

#: Seconds an availability probe is reused; see the firewall backend.
STATUS_CACHE_SECONDS = 30.0


class SessionBackend:
    """Interface every session backend implements."""

    name = "session"

    def status(self) -> BackendStatus:  # pragma: no cover - abstract
        raise NotImplementedError

    def list_sessions(self) -> list[dict]:  # pragma: no cover - abstract
        raise NotImplementedError

    def get_session(self, session_id: str) -> dict | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def validate_target(self, session_id) -> dict:  # pragma: no cover - abstract
        raise NotImplementedError

    def terminate(self, session_id: str) -> ActionOutcome:  # pragma: no cover - abstract
        raise NotImplementedError

    def verify_terminated(self, session_id: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError


class LoginctlSessionBackend(SessionBackend):
    """Ends one systemd-logind session through ``loginctl``.

    Args:
        runner: The command runner; a disabled one makes this backend
            read-only.
        own_session: The caller's own session id.  Defaults to
            ``$XDG_SESSION_ID``, and is refused as a target.
    """

    name = "logind"

    def __init__(self, runner: CommandRunner | None = None, own_session: str | None = None) -> None:
        self.runner = runner or CommandRunner()
        self.own_session = own_session if own_session is not None else own_session_id()
        self._status: BackendStatus | None = None
        self._status_at: float = 0.0

    # -- availability ------------------------------------------------------
    def status(self) -> BackendStatus:
        """Whether logind can be used here (cached briefly, like the firewall)."""
        now = time.monotonic()
        if self._status is not None and (now - self._status_at) < STATUS_CACHE_SECONDS:
            return self._status
        self._status = self._probe()
        self._status_at = now
        return self._status

    def _probe(self) -> BackendStatus:
        if not self.runner.available("loginctl"):
            return BackendStatus(
                name=self.name,
                available=False,
                reason="loginctl was not found on this host",
                remedy="Session containment needs systemd-logind. Without it, end the "
                "session yourself and record the action here for the audit trail.",
            )
        try:
            result = self.runner.run(["loginctl", "--no-pager", "--no-legend", "list-sessions"])
        except ExecutionError as exc:
            return BackendStatus(
                name=self.name,
                available=False,
                reason=f"logind could not be queried: {exc}",
                remedy="Check that systemd-logind is running on this host.",
            )
        if not result.ok:
            return BackendStatus(
                name=self.name,
                available=False,
                reason="systemd-logind did not answer a session listing",
                remedy="Check that systemd-logind is running on this host.",
            )
        return BackendStatus(
            name=self.name,
            available=True,
            details={
                "own_session": self.own_session,
                "note": "ends one session only; SentinelForge never disables an account",
            },
        )

    # -- reads -------------------------------------------------------------
    def list_sessions(self) -> list[dict]:
        """Every session logind knows about, with the fields worth auditing."""
        try:
            result = self.runner.run(["loginctl", "--no-pager", "--no-legend", "list-sessions"])
        except ExecutionError as exc:
            LOGGER.debug("could not list sessions: %s", exc)
            return []
        if not result.ok:
            return []
        sessions = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            try:
                session_id = validate_session_id(fields[0])
            except ValidationError:
                continue
            session = self.get_session(session_id)
            if session:
                sessions.append(session)
        return sessions

    def get_session(self, session_id: str) -> dict | None:
        """One session's properties, or ``None`` if logind does not know it."""
        session_id = validate_session_id(session_id)
        try:
            result = self.runner.run(
                ["loginctl", "--no-pager", "show-session", session_id]
            )
        except ExecutionError as exc:
            LOGGER.debug("could not read session %s: %s", session_id, exc)
            return None
        if not result.ok:
            return None
        properties: dict = {}
        for line in result.stdout.splitlines():
            match = _KEY_VALUE.match(line.strip())
            if match and match.group("key") in _INTERESTING_FIELDS:
                properties[match.group("key").lower()] = match.group("value")
        if not properties.get("id"):
            return None
        properties["is_own_session"] = properties["id"] == (self.own_session or "")
        return properties

    def validate_target(self, session_id) -> dict:
        """Resolve a session id to a live session that may be terminated.

        Raises:
            ValidationError: The id is malformed, unknown, or refers to the
                caller's own session.
        """
        session_id = validate_session_id(session_id)
        session = self.get_session(session_id)
        if session is None:
            raise ValidationError(f"no session {session_id!r} is known to logind", "target")
        if session.get("is_own_session"):
            raise ValidationError(
                f"session {session_id} is this analyst's own session: terminating it "
                "would end the response you are running",
                "target",
            )
        if (session.get("class") or "").lower() == "manager":
            raise ValidationError(
                f"session {session_id} is a logind manager session, not a user login",
                "target",
            )
        return session

    def verify_terminated(self, session_id: str) -> bool:
        """Whether logind has stopped reporting this session as active."""
        session = self.get_session(session_id)
        if session is None:
            return True
        return (session.get("state") or "").lower() in ("closing", "closed")

    # -- mutation ----------------------------------------------------------
    def terminate(self, session_id: str) -> ActionOutcome:
        """End one session, then confirm with logind that it is gone."""
        session = self.validate_target(session_id)
        try:
            result = self.runner.run(
                ["loginctl", "terminate-session", session["id"]], mutating=True
            )
        except ExecutionError as exc:
            return ActionOutcome(
                ok=False, detail="the loginctl command could not be run", error=str(exc)
            )
        if not result.ok:
            error = (
                "logind refused the request for lack of privileges. Re-run the approved "
                "action with the necessary privileges."
                if result.permission_denied
                else result.describe()
            )
            return ActionOutcome(
                ok=False,
                detail="logind refused to terminate the session",
                data={"session": session, **result.to_dict()},
                error=error,
            )
        if not self.verify_terminated(session["id"]):
            return ActionOutcome(
                ok=False,
                detail="loginctl accepted the request but the session is still active",
                data={"session": session},
                error="verification failed: logind still reports this session as active",
            )
        return ActionOutcome(
            ok=True,
            detail=f"session {session['id']} ({session.get('name') or 'unknown user'}) was terminated",
            data={"session": session, "command": list(result.argv)},
        )


def own_session_id(proc_cgroup: str = "/proc/self/cgroup") -> str | None:
    """The logind session this process belongs to, if any.

    ``$XDG_SESSION_ID`` is set for login shells but not for every process that
    might run the CLI, so this falls back to the control group path, where a
    logind session appears as ``session-<id>.scope``.  A process running
    outside a login session (a systemd service, a terminal under the user
    manager) simply has no session id, and the backend then relies on logind's
    own listing to keep the analyst safe.
    """
    from_env = os.environ.get("XDG_SESSION_ID")
    if from_env:
        return from_env
    try:
        with open(proc_cgroup, "r", encoding="utf-8", errors="replace") as handle:
            match = re.search(r"/session-([A-Za-z0-9_-]{1,32})\.scope", handle.read())
    except OSError:  # pragma: no cover - not Linux
        return None
    return match.group(1) if match else None


class UnsupportedSessionBackend(SessionBackend):
    """Stands in when systemd-logind is not available.

    Refuses every request.  There is no substitute implementation: walking the
    process table to guess which processes constitute "a login" and killing
    them is precisely the unsafe workaround this phase is meant to avoid.
    """

    name = "unsupported"

    def __init__(self, reason: str, remedy: str | None = None) -> None:
        self.reason = reason
        self.remedy = remedy

    def status(self) -> BackendStatus:
        return BackendStatus(
            name=self.name, available=False, reason=self.reason, remedy=self.remedy
        )

    def list_sessions(self) -> list[dict]:
        return []

    def get_session(self, session_id: str) -> dict | None:
        return None

    def validate_target(self, session_id) -> dict:
        raise ValidationError(self.reason, "target")

    def verify_terminated(self, session_id: str) -> bool:
        return False

    def terminate(self, session_id: str) -> ActionOutcome:
        return ActionOutcome(ok=False, detail=self.reason, error=self.reason)


def detect_session_backend(runner: CommandRunner | None = None) -> SessionBackend:
    """Pick a session backend for this host."""
    runner = runner or CommandRunner()
    logind = LoginctlSessionBackend(runner=runner)
    status = logind.status()
    if status.available:
        return logind
    return UnsupportedSessionBackend(
        reason=status.reason or "no session backend", remedy=status.remedy
    )
