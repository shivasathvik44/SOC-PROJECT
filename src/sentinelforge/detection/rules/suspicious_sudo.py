"""Suspicious sudo activity.

The rule inspects the ``COMMAND=`` text that sudo writes to the log.  It is a
**conservative pattern table**: routine administration (installing a package,
restarting a service, editing an ordinary file) must not raise an alert, so
each pattern targets a specific high-risk behaviour and says which ATT&CK
technique it maps to.

The command text is only ever matched against regular expressions.  It is never
executed, expanded, or passed to a shell.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from ...models.event import EventType, SecurityEvent, Severity
from ..mitre import MitreMapping, Tactic, mapping
from ..risk import RiskFactor
from ..rule import Detection, Rule

# sudo logs look like:
#   capslock : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/dnf update
_COMMAND = re.compile(r"COMMAND=(?P<command>.+?)\s*$", re.IGNORECASE)
_TARGET_USER = re.compile(r"\bUSER=(?P<user>[^\s;]+)")
_INVOKING_USER = re.compile(r"^\s*(?P<user>[\w.\-$]+)\s*:")


@dataclass(frozen=True)
class SudoPattern:
    """One suspicious-sudo signature.

    Attributes:
        pattern_id: Short id, also used for alert deduplication.
        name: Alert name shown to the analyst.
        description: What the pattern means, in one sentence.
        regex: Matched against the ``COMMAND=`` text (or the whole message when
            ``match_message`` is set).
        severity: Base severity for this specific behaviour.
        mitre: ATT&CK mapping for this specific behaviour.
        match_message: Match the full log message instead of just the command.
    """

    pattern_id: str
    name: str
    description: str
    regex: re.Pattern
    severity: str
    mitre: MitreMapping
    match_message: bool = False


def _pattern(pattern_id, name, description, regex, severity, mitre, match_message=False):
    return SudoPattern(
        pattern_id,
        name,
        description,
        re.compile(regex, re.IGNORECASE),
        severity,
        mitre,
        match_message,
    )


# Order matters: the first matching pattern wins, so the most specific and most
# serious behaviours are listed first.
SUDO_PATTERNS: tuple[SudoPattern, ...] = (
    _pattern(
        "unauthorized_sudo",
        "Unauthorized Sudo Attempt",
        "A user attempted to use sudo without permission.",
        r"user NOT in sudoers|\d+ incorrect password attempts",
        Severity.HIGH,
        mapping("T1548.003"),
        match_message=True,
    ),
    _pattern(
        "remote_content_execution",
        "Sudo Download-And-Execute",
        "Remote content was piped straight into a shell with root privileges.",
        r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:/usr/bin/|/bin/)?(?:ba|z|k|da)?sh\b",
        Severity.HIGH,
        mapping("T1105"),
    ),
    _pattern(
        "log_destruction",
        "Sudo Log Destruction",
        "System logs were deleted, truncated or vacuumed with root privileges.",
        r"(?:\brm\b[^|]*/var/log|\btruncate\b[^|]*/var/log|"
        r"journalctl\s+[^|]*--vacuum|\b(?:shred|wipe)\b[^|]*/var/log)",
        Severity.HIGH,
        mapping("T1070.002"),
    ),
    _pattern(
        "auth_file_modification",
        "Authentication Configuration Modified",
        "A file that controls authentication or privilege was modified via sudo.",
        r"\b(?:tee|sed\s+-i|vi|vim|nano|emacs|ed|cp|mv|rm|chmod|chown|dd)\b[^|]*"
        r"/etc/(?:shadow|passwd|group|gshadow|sudoers|pam\.d|ssh/sshd_config)",
        Severity.HIGH,
        mapping("T1556", Tactic.PERSISTENCE),
    ),
    _pattern(
        "privileged_group_change",
        "Privileged Group Membership Changed",
        "An account was added to a privileged group via sudo.",
        r"\b(?:usermod|gpasswd|adduser)\b[^|]*\b(?:wheel|sudo|adm|root)\b",
        Severity.HIGH,
        mapping("T1098"),
    ),
    _pattern(
        "security_service_disabled",
        "Security Service Disabled",
        "A security service or enforcement mechanism was disabled via sudo.",
        r"(?:systemctl\s+(?:stop|disable|mask)\s+[^|]*"
        r"(?:auditd|fail2ban|clamav|apparmor|selinux|sshd)\b"
        r"|\bsetenforce\s+0\b"
        r"|\bauditctl\s+-e\s*0\b"
        r"|\bsemanage\s+permissive\b)",
        Severity.HIGH,
        mapping("T1562.001"),
    ),
    _pattern(
        "firewall_disabled",
        "Firewall Disabled or Flushed",
        "The host firewall was stopped, disabled or flushed via sudo.",
        r"(?:systemctl\s+(?:stop|disable|mask)\s+[^|]*(?:firewalld|nftables|iptables)\b"
        r"|\biptables\b[^|]*\s-F\b|\bip6tables\b[^|]*\s-F\b"
        r"|\bnft\b[^|]*\bflush\s+ruleset\b"
        r"|\bufw\s+disable\b"
        r"|firewall-cmd\s+[^|]*--set-default-zone=trusted)",
        Severity.HIGH,
        mapping("T1562.004"),
    ),
    _pattern(
        "credential_file_access",
        "Credential File Accessed",
        "A password or shadow file was read via sudo.",
        r"\b(?:cat|less|more|head|tail|grep|strings|cp|base64|xxd)\b[^|]*"
        r"/etc/(?:shadow|gshadow)",
        Severity.MEDIUM,
        mapping("T1003.008"),
    ),
    _pattern(
        "account_management",
        "Account Created or Modified",
        "A user account was created, deleted or had its password changed via sudo.",
        r"\b(?:useradd|adduser|userdel|deluser|passwd)\b\s+\S",
        Severity.MEDIUM,
        mapping("T1098"),
    ),
    _pattern(
        "shell_command_string",
        "Root Shell Command String",
        "An interpreter was asked to execute an inline command string as root.",
        r"\b(?:(?:ba|z|k|da)?sh|python[23]?|perl|ruby|php)\s+-c\s+\S",
        Severity.MEDIUM,
        mapping("T1059.004"),
    ),
    _pattern(
        "interactive_root_shell",
        "Interactive Root Shell",
        "An interactive root shell was started via sudo.",
        r"^(?:/usr)?/?(?:bin/)?(?:bash|sh|zsh|ksh|dash|su)\s*(?:-\w*)?\s*$",
        Severity.LOW,
        mapping("T1059.004"),
    ),
    _pattern(
        # Only *changes* count; listing rules is read-only administration.
        "firewall_modified",
        "Firewall Rules Modified",
        "Host firewall rules were changed via sudo.",
        r"(?:\b(?:ip6?tables)\b[^|]*\s-(?:A|I|D|P|N|X|R)\b"
        r"|\bnft\b[^|]*\b(?:add|insert|delete|replace|create)\b"
        r"|firewall-cmd\b[^|]*--(?:add|remove|set|change)"
        r"|\bufw\s+(?:allow|deny|reject|delete|default|enable)\b)",
        Severity.LOW,
        mapping("T1562.004"),
    ),
)


class SuspiciousSudoRule(Rule):
    """Flag sudo events whose command matches a high-risk pattern.

    Ordinary administration does not match any pattern and produces no alert.

    Args:
        patterns: Override the built-in pattern table (useful for tests and for
            site-specific tuning).
    """

    rule_id = "SUSPICIOUS_SUDO"
    name = "Suspicious Sudo Activity"
    description = "Sudo was used to run a high-risk command."
    severity = Severity.MEDIUM
    mitre = mapping("T1548.003")

    def __init__(self, patterns: Sequence[SudoPattern] = SUDO_PATTERNS) -> None:
        self.patterns = tuple(patterns)

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        for event in events:
            if event.event_type != EventType.SUDO:
                continue
            detection = self._check(event)
            if detection is not None:
                yield detection

    def _check(self, event: SecurityEvent) -> Detection | None:
        message = event.message or ""
        command_match = _COMMAND.search(message)
        command = command_match.group("command").strip() if command_match else ""

        for pattern in self.patterns:
            haystack = message if pattern.match_message else command
            if not haystack or not pattern.regex.search(haystack):
                continue
            return self._detection(event, pattern, command, message)
        return None

    def _detection(
        self, event: SecurityEvent, pattern: SudoPattern, command: str, message: str
    ) -> Detection:
        invoking = event.user or self._invoking_user(message)
        target = self._target_user(message)

        factors = []
        if target and target.lower() == "root" and pattern.severity != Severity.HIGH:
            factors.append(RiskFactor(5, "the command was requested as the root account"))

        observed = command or message
        return Detection(
            dedup_key=f"{invoking or 'unknown'}|{pattern.pattern_id}",
            evidence=[event],
            description=f"{pattern.description} Command: {observed}",
            host=event.host,
            source_ip=event.src_ip,
            user=invoking,
            severity=pattern.severity,
            name=pattern.name,
            mitre=pattern.mitre,
            risk_factors=factors,
        )

    @staticmethod
    def _invoking_user(message: str) -> str | None:
        match = _INVOKING_USER.search(message)
        return match.group("user") if match else None

    @staticmethod
    def _target_user(message: str) -> str | None:
        match = _TARGET_USER.search(message)
        return match.group("user") if match else None
