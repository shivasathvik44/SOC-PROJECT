"""SSH brute force and post-brute-force compromise detections.

Two deliberately separate rules:

* ``SSH_BRUTE_FORCE``          - many failed attempts from one source address.
* ``SSH_COMPROMISE_SUSPECTED`` - one of those attempts eventually succeeded.

Both correlate on **event type + source IP + timestamps**, never on a bare
count of authentication events.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Iterable, Sequence

from ...models.event import EventType, SecurityEvent, Severity
from ..mitre import Tactic, mapping
from ..risk import RiskFactor
from ..rule import (
    Detection,
    Rule,
    find_bursts,
    group_by,
    most_common_value,
    timed,
)

#: Events from these programs count as SSH authentication activity.  Events with
#: no process recorded are included too, so a source that does not populate the
#: field is not silently ignored.
SSH_PROCESSES = ("sshd",)


def _is_ssh(event: SecurityEvent, processes: Sequence[str]) -> bool:
    process = (event.process or "").lower()
    if not process:
        return True
    return any(name in process for name in processes)


def _ssh_events(
    events: Iterable[SecurityEvent], event_type: str, processes: Sequence[str]
) -> list[SecurityEvent]:
    """Select SSH events of one type that carry a source IP."""
    return [
        event
        for event in events
        if event.event_type == event_type and event.src_ip and _is_ssh(event, processes)
    ]


class SshBruteForceRule(Rule):
    """Many failed SSH authentications from one source address in a short window.

    Args:
        threshold: Failures needed to trigger (default 5).
        window_seconds: Length of the sliding window (default 300 = 5 minutes).
        processes: Program names that count as SSH.
    """

    rule_id = "SSH_BRUTE_FORCE"
    name = "SSH Brute Force"
    description = "Multiple failed SSH authentication attempts detected."
    severity = Severity.HIGH
    mitre = mapping("T1110.001")

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,
        processes: Sequence[str] = SSH_PROCESSES,
    ) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        self.processes = tuple(processes)

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        failures = _ssh_events(events, EventType.AUTHENTICATION_FAILURE, self.processes)

        # Correlate per source IP so two unrelated addresses never add up.
        for source_ip, ip_events in group_by(failures, lambda event: event.src_ip).items():
            for burst in find_bursts(ip_events, self.window_seconds, self.threshold):
                yield self._detection(source_ip, burst)

    def _detection(self, source_ip: str, burst: list[SecurityEvent]) -> Detection:
        users = sorted({event.user for event in burst if event.user})
        factors = []
        if len(burst) >= self.threshold * 3:
            factors.append(
                RiskFactor(
                    10,
                    f"{len(burst)} failed attempts is far above the threshold of "
                    f"{self.threshold}",
                )
            )
        if len(users) >= 3:
            factors.append(
                RiskFactor(5, f"attempts targeted {len(users)} different usernames")
            )

        target = ", ".join(users[:5]) if users else "unknown accounts"
        minutes = self.window_seconds / 60
        return Detection(
            dedup_key=source_ip,
            evidence=burst,
            description=(
                f"{len(burst)} failed SSH authentication attempts from {source_ip} "
                f"within {minutes:g} minutes (targets: {target})."
            ),
            source_ip=source_ip,
            user=most_common_value(burst, "user"),
            host=most_common_value(burst, "host"),
            risk_factors=factors,
        )


class SshCompromiseSuspectedRule(Rule):
    """A successful SSH login from an address that was just brute forcing.

    Failures alone are noise; a success right after them is the moment the
    attack may have worked, so this is a separate, higher-risk detection whose
    evidence contains both the failures and the successful login.

    Args:
        threshold: Failures that must precede the success (default 5).
        window_seconds: How far back to look from the successful login.
        processes: Program names that count as SSH.
    """

    rule_id = "SSH_COMPROMISE_SUSPECTED"
    name = "SSH Compromise Suspected"
    description = "Successful SSH authentication immediately after repeated failures."
    severity = Severity.HIGH
    mitre = mapping("T1078.003", Tactic.INITIAL_ACCESS)

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,
        processes: Sequence[str] = SSH_PROCESSES,
    ) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        self.processes = tuple(processes)

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        failures = _ssh_events(events, EventType.AUTHENTICATION_FAILURE, self.processes)
        successes = _ssh_events(events, EventType.AUTHENTICATION_SUCCESS, self.processes)

        failures_by_ip = group_by(failures, lambda event: event.src_ip)
        successes_by_ip = group_by(successes, lambda event: event.src_ip)
        window = timedelta(seconds=self.window_seconds)

        for source_ip, ip_successes in successes_by_ip.items():
            ip_failures = timed(failures_by_ip.get(source_ip, []))
            if not ip_failures:
                continue

            reported_at = None
            for moment, success in timed(ip_successes):
                # One alert per attack, not one per login while it is going on.
                if reported_at is not None and moment - reported_at <= window:
                    continue
                preceding = [
                    event
                    for failure_moment, event in ip_failures
                    if timedelta(0) <= moment - failure_moment <= window
                ]
                if len(preceding) < self.threshold:
                    continue
                reported_at = moment
                yield self._detection(source_ip, preceding, success)

    def _detection(
        self, source_ip: str, failures: list[SecurityEvent], success: SecurityEvent
    ) -> Detection:
        minutes = self.window_seconds / 60
        account = success.user or "an account"
        return Detection(
            dedup_key=f"{source_ip}|{success.user or ''}",
            evidence=failures + [success],
            description=(
                f"Successful SSH authentication for {account} from {source_ip} after "
                f"{len(failures)} failed attempts within {minutes:g} minutes - "
                "possible successful brute force."
            ),
            source_ip=source_ip,
            user=success.user,
            host=success.host,
            risk_factors=[
                RiskFactor(
                    15,
                    f"a successful login followed {len(failures)} failed attempts "
                    "from the same source address",
                )
            ],
        )
