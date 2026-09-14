"""Turn raw log records into normalized :class:`SecurityEvent` objects.

Parsing is a simple ordered table of regular expressions.  The first rule that
matches a message wins, and anything unmatched becomes ``unknown`` -- it is
never dropped, because Phase 2+ may learn to understand it.

Adding a better parser later means appending a :class:`ParseRule` (or a whole
new rule table) -- no other module has to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from ..models.event import EventType, SecurityEvent, Severity, utc_now
from ..models.record import RawRecord

# Address shapes, as a plain string so rules can embed it.
_ADDR = r"\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}:[0-9a-fA-F:]{2,}"

# Matches an IPv4 address or a bracket-free IPv6-ish address.
_IP_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})"
)


@dataclass(frozen=True)
class ParseRule:
    """One classification rule.

    Attributes:
        name: Human-readable rule id, useful when debugging.
        pattern: Compiled regex; named groups ``user`` and ``ip`` are picked up
            automatically when present.
        event_type: Event type assigned on a match.
        severity: Severity assigned on a match.
        process: Optional process-name hint used when the log line itself does
            not name the program.
    """

    name: str
    pattern: re.Pattern
    event_type: str
    severity: str
    process: str | None = None


def _rule(name, pattern, event_type, severity, process=None) -> ParseRule:
    return ParseRule(name, re.compile(pattern, re.IGNORECASE), event_type, severity, process)


# Order matters: the first match wins, so put specific rules before generic ones.
RULES: tuple[ParseRule, ...] = (
    # ---- authentication failures -------------------------------------------
    _rule(
        "ssh_failed_password_invalid_user",
        r"Failed (?:password|publickey|keyboard-interactive/pam) for invalid user (?P<user>\S+) from (?P<ip>\S+)",
        EventType.AUTHENTICATION_FAILURE,
        Severity.HIGH,
        process="sshd",
    ),
    _rule(
        "ssh_failed_password",
        r"Failed (?:password|publickey|keyboard-interactive/pam|none) for (?P<user>\S+) from (?P<ip>\S+)",
        EventType.AUTHENTICATION_FAILURE,
        Severity.MEDIUM,
        process="sshd",
    ),
    _rule(
        "ssh_invalid_user",
        r"Invalid user (?P<user>\S+) from (?P<ip>\S+)",
        EventType.AUTHENTICATION_FAILURE,
        Severity.MEDIUM,
        process="sshd",
    ),
    _rule(
        "pam_auth_failure",
        r"authentication failure;.*?rhost=(?P<ip>\S*).*?user=(?P<user>\S+)",
        EventType.AUTHENTICATION_FAILURE,
        Severity.MEDIUM,
    ),
    _rule(
        # Deliberately specific: generic phrases such as "Permission denied"
        # appear in unrelated kernel/daemon messages and cause false positives.
        "pam_auth_failure_plain",
        r"authentication failure|authentication error|"
        r"(?:maximum|too many) authentication (?:attempts exceeded|failures)|"
        r"PAM: Authentication failure",
        EventType.AUTHENTICATION_FAILURE,
        Severity.MEDIUM,
    ),
    _rule(
        "ssh_preauth_close",
        r"Connection (?:closed|reset) by (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>\S+)",
        EventType.AUTHENTICATION_FAILURE,
        Severity.MEDIUM,
        process="sshd",
    ),
    # ---- authentication successes ------------------------------------------
    _rule(
        "ssh_accepted",
        r"Accepted (?:password|publickey|keyboard-interactive/pam|none|gssapi-with-mic) "
        r"for (?P<user>\S+) from (?P<ip>\S+)",
        EventType.AUTHENTICATION_SUCCESS,
        Severity.LOW,
        process="sshd",
    ),
    _rule(
        "pam_auth_success",
        r"pam_unix\([^)]*:auth\): (?:authentication success|session opened)",
        EventType.AUTHENTICATION_SUCCESS,
        Severity.LOW,
    ),
    _rule(
        "login_success",
        r"(?:New session \d+ of user (?P<user>\S+)|LOGIN ON \S+ BY (?P<user2>\S+))",
        EventType.AUTHENTICATION_SUCCESS,
        Severity.LOW,
    ),
    # ---- sudo ---------------------------------------------------------------
    _rule(
        "sudo_not_in_sudoers",
        r"(?P<user>\S+) : user NOT in sudoers",
        EventType.SUDO,
        Severity.HIGH,
        process="sudo",
    ),
    _rule(
        "sudo_command",
        r"^\s*(?P<user>[\w.\-$]+) : .*?COMMAND=",
        EventType.SUDO,
        Severity.MEDIUM,
        process="sudo",
    ),
    _rule(
        # A sudo session is sudo activity first and a session second, so this
        # has to be checked before the generic session rules below.
        "sudo_session",
        r"pam_unix\(sudo:session\): session (?:opened|closed) for user (?P<user>[^\s(]+)",
        EventType.SUDO,
        Severity.LOW,
        process="sudo",
    ),
    _rule(
        "sudo_generic",
        r"pam_unix\(sudo:|^sudo:|\bsudo\[\d+\]:",
        EventType.SUDO,
        Severity.MEDIUM,
        process="sudo",
    ),
    # ---- sessions -----------------------------------------------------------
    _rule(
        "session_opened",
        r"session opened for user (?P<user>[^\s(]+)",
        EventType.SESSION_OPEN,
        Severity.LOW,
    ),
    _rule(
        "session_closed",
        r"session closed for user (?P<user>[^\s(]+)",
        EventType.SESSION_CLOSE,
        Severity.INFO,
    ),
    # ---- ssh connection activity -------------------------------------------
    _rule(
        # The address is required to look like one: plain English phrases such
        # as "Connection reset by peer" are not SSH connection events.
        "ssh_connection",
        rf"Connection (?:from|closed by|reset by) (?:invalid user \S+ )?(?P<ip>{_ADDR})|"
        rf"Received disconnect from (?P<ip2>{_ADDR})|"
        rf"Disconnected from (?:(?:invalid )?user \S+ )?(?P<ip3>{_ADDR})",
        EventType.SSH_CONNECTION,
        Severity.INFO,
        process="sshd",
    ),
    # ---- process / unit start ----------------------------------------------
    _rule(
        "systemd_started",
        r"^(?:Started|Starting)\b",
        EventType.PROCESS_START,
        Severity.INFO,
        process="systemd",
    ),
    _rule(
        "exec_started",
        r"\bexecve\b|\bStarting new process\b",
        EventType.PROCESS_START,
        Severity.INFO,
    ),
)


def _group(match: re.Match, name: str) -> str | None:
    """Safely read a named group that a rule may or may not define."""
    if name not in match.re.groupindex:
        return None
    value = match.group(name)
    return value or None


def _strip_port(value: str | None) -> str | None:
    """Drop a trailing ``port NNN`` / ``:NNN`` decoration from an address."""
    if not value:
        return None
    value = value.strip().rstrip(",;")
    match = _IP_PATTERN.fullmatch(value)
    if match:
        return value
    match = _IP_PATTERN.search(value)
    return match.group("ip") if match else None


def classify(message: str, process: str | None = None) -> dict:
    """Classify a log message.

    Returns a dict with ``event_type``, ``severity``, ``user``, ``src_ip`` and
    ``rule`` keys.  Never raises: unparseable input becomes ``unknown``.
    """
    result = {
        "event_type": EventType.UNKNOWN,
        "severity": Severity.INFO,
        "user": None,
        "src_ip": None,
        "process": process,
        "rule": None,
    }
    if not isinstance(message, str) or not message.strip():
        return result

    for rule in RULES:
        match = rule.pattern.search(message)
        if not match:
            continue
        result["event_type"] = rule.event_type
        result["severity"] = rule.severity
        result["rule"] = rule.name
        user = _group(match, "user") or _group(match, "user2")
        ip = _group(match, "ip") or _group(match, "ip2") or _group(match, "ip3")
        if user:
            result["user"] = user.strip("(),;:")
        result["src_ip"] = _strip_port(ip)
        if not result["process"] and rule.process:
            result["process"] = rule.process
        break

    # Fallbacks: read values that are present in the text but that the matching
    # rule did not capture.  We only ever *extract*, never guess.
    if result["user"] is None:
        fallback_user = re.search(r"\buser=(?P<user>[^\s,;]+)", message)
        if fallback_user:
            result["user"] = fallback_user.group("user")
    if result["src_ip"] is None:
        fallback_ip = re.search(r"\b(?:rhost|from|src)[= ](?P<addr>[^\s,;]+)", message, re.I)
        if fallback_ip:
            result["src_ip"] = _strip_port(fallback_ip.group("addr"))
    return result


def normalize(record: RawRecord, host_default: str = "unknown") -> SecurityEvent:
    """Convert a :class:`RawRecord` into a :class:`SecurityEvent`."""
    if not isinstance(record, RawRecord):  # defensive: accept dict-shaped input too
        record = RawRecord(**dict(record))

    verdict = classify(record.message, record.process)
    return SecurityEvent(
        timestamp=record.timestamp or utc_now(),
        host=record.host or host_default,
        source=record.source,
        event_type=verdict["event_type"],
        severity=verdict["severity"],
        user=verdict["user"],
        src_ip=verdict["src_ip"],
        process=verdict["process"],
        message=record.message,
        raw=record.raw or record.message,
    )


def normalize_all(
    records: Iterable[RawRecord],
    host_default: str = "unknown",
    on_error: Callable[[Exception, object], None] | None = None,
) -> Iterator[SecurityEvent]:
    """Normalize a stream of records, skipping (not crashing on) bad ones."""
    for record in records:
        try:
            yield normalize(record, host_default=host_default)
        except Exception as exc:  # pragma: no cover - guardrail for odd input
            if on_error is not None:
                on_error(exc, record)
