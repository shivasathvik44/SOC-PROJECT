"""Suspicious authentication detections that are not SSH brute force.

Three deterministic rules:

* ``AUTH_INVALID_USER``        - one source probing several accounts that do not exist.
* ``AUTH_REPEATED_FAILURES``   - one account failing repeatedly across any service.
* ``AUTH_ROOT_LOGIN_REMOTE``   - a privileged account logging in from a remote address.

These overlap with ``SSH_BRUTE_FORCE`` on purpose: they look at the same events
from a different angle (account instead of address), which is normal for a SOC.
Each rule deduplicates independently.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Sequence

from ...models.event import EventType, SecurityEvent, Severity
from ..mitre import Tactic, mapping
from ..risk import RiskFactor
from ..rule import (
    Detection,
    Rule,
    find_bursts,
    group_by,
    is_external_address,
    most_common_value,
    timed,
)

#: sshd phrasing for an account that does not exist on the host.
_INVALID_USER = re.compile(r"\binvalid user\b|\billegal user\b", re.IGNORECASE)

#: Accounts whose remote logins are always worth reporting.
PRIVILEGED_USERS = ("root",)

def _is_remote(address: str | None) -> bool:
    """Return ``True`` for an address that is not this machine itself."""
    if not address:
        return False
    if address in ("localhost", "::1"):
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False  # hostnames and odd values: not enough evidence, stay quiet
    return not (parsed.is_loopback or parsed.is_unspecified)


class InvalidUserProbeRule(Rule):
    """One source trying to log in as several accounts that do not exist.

    Failing once for a mistyped username is normal; several different
    non-existent accounts from one address within a few minutes is account
    probing.

    Args:
        distinct_users: How many different non-existent accounts are needed.
        window_seconds: Sliding window length.
    """

    rule_id = "AUTH_INVALID_USER"
    name = "Login Attempts For Nonexistent Users"
    description = "Authentication attempted for accounts that do not exist on this host."
    severity = Severity.MEDIUM
    mitre = mapping("T1110.001")

    def __init__(self, distinct_users: int = 3, window_seconds: int = 300) -> None:
        self.distinct_users = int(distinct_users)
        self.window_seconds = int(window_seconds)

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        probes = [
            event
            for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE
            and event.src_ip
            and _INVALID_USER.search(event.message or "")
        ]

        for source_ip, ip_events in group_by(probes, lambda event: event.src_ip).items():
            # A burst of >= distinct_users attempts is a prerequisite; the real
            # test is how many *different* accounts it touched.
            for burst in find_bursts(ip_events, self.window_seconds, self.distinct_users):
                users = sorted({event.user for event in burst if event.user})
                if len(users) < self.distinct_users:
                    continue
                yield self._detection(source_ip, burst, users)

    def _detection(
        self, source_ip: str, burst: list[SecurityEvent], users: list[str]
    ) -> Detection:
        factors = []
        if len(users) >= self.distinct_users * 3:
            factors.append(
                RiskFactor(10, f"{len(users)} different nonexistent accounts were probed")
            )
        if is_external_address(source_ip):
            factors.append(RiskFactor(5, "the source address is outside internal network ranges"))

        shown = ", ".join(users[:5]) + ("..." if len(users) > 5 else "")
        return Detection(
            dedup_key=source_ip,
            evidence=burst,
            description=(
                f"{source_ip} attempted to authenticate as {len(users)} nonexistent "
                f"accounts ({shown}) in {self.window_seconds / 60:g} minutes."
            ),
            source_ip=source_ip,
            host=most_common_value(burst, "host"),
            user=None,  # many accounts were targeted; no single one applies
            risk_factors=factors,
        )


class RepeatedAuthFailureRule(Rule):
    """One account failing authentication repeatedly, on any service.

    This catches failures that ``SSH_BRUTE_FORCE`` cannot see: console logins,
    the display manager, ``su``, or an address-less PAM failure.

    Args:
        threshold: Failures needed to trigger (default 10).
        window_seconds: Sliding window length.
    """

    rule_id = "AUTH_REPEATED_FAILURES"
    name = "Repeated Authentication Failures"
    description = "One account failed authentication repeatedly in a short time."
    severity = Severity.MEDIUM
    mitre = mapping("T1110")

    def __init__(self, threshold: int = 10, window_seconds: int = 300) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        failures = [
            event
            for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE and event.user
        ]

        for user, user_events in group_by(failures, lambda event: event.user).items():
            for burst in find_bursts(user_events, self.window_seconds, self.threshold):
                yield self._detection(user, burst)

    def _detection(self, user: str, burst: list[SecurityEvent]) -> Detection:
        sources = sorted({event.src_ip for event in burst if event.src_ip})
        factors = []
        if len(sources) >= 3:
            factors.append(
                RiskFactor(
                    10,
                    f"failures came from {len(sources)} different source addresses, "
                    "which suggests a distributed attempt",
                )
            )
        if user.lower() in PRIVILEGED_USERS:
            factors.append(RiskFactor(10, f"the targeted account '{user}' is privileged"))

        where = f" from {', '.join(sources[:3])}" if sources else ""
        return Detection(
            dedup_key=user,
            evidence=burst,
            description=(
                f"{len(burst)} failed authentication attempts for account '{user}'"
                f"{where} within {self.window_seconds / 60:g} minutes."
            ),
            user=user,
            source_ip=sources[0] if len(sources) == 1 else None,
            host=most_common_value(burst, "host"),
            risk_factors=factors,
        )


class RemotePrivilegedLoginRule(Rule):
    """A privileged account authenticating successfully from a remote address.

    Direct remote root logins are disabled by default on Fedora, so a
    successful one is worth an analyst's attention even when it is legitimate.

    Args:
        users: Account names considered privileged.
    """

    rule_id = "AUTH_ROOT_LOGIN_REMOTE"
    name = "Remote Privileged Login"
    description = "A privileged account authenticated successfully from a remote address."
    severity = Severity.MEDIUM
    mitre = mapping("T1078.003", Tactic.INITIAL_ACCESS)

    def __init__(self, users: Sequence[str] = PRIVILEGED_USERS) -> None:
        self.users = tuple(name.lower() for name in users)

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        for moment, event in timed(events):
            if event.event_type != EventType.AUTHENTICATION_SUCCESS:
                continue
            if not event.user or event.user.lower() not in self.users:
                continue
            if not _is_remote(event.src_ip):
                continue

            factors = []
            if is_external_address(event.src_ip):
                factors.append(
                    RiskFactor(
                        10, "the source address is outside internal network ranges"
                    )
                )
            yield Detection(
                dedup_key=f"{event.user}|{event.src_ip}",
                evidence=[event],
                description=(
                    f"Privileged account '{event.user}' authenticated successfully "
                    f"from remote address {event.src_ip}."
                ),
                source_ip=event.src_ip,
                user=event.user,
                host=event.host,
                risk_factors=factors,
            )
