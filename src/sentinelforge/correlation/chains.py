"""Attack-chain patterns.

A chain describes a *sequence* of behaviours that together mean more than their
parts: failed logins, then a success, then privilege escalation.  Each stage
matches either detection rule ids or ATT&CK technique ids, so a chain can be
written in terms of behaviour rather than the name of whichever rule caught it.

Only chains the available telemetry can actually support are defined here.
Phase 4 added eBPF process and network sensors, so the two chains Phase 3 listed
as future work -- privilege escalation followed by execution, and authentication
followed by execution followed by network activity -- are implemented now.
Patterns that still need telemetry SentinelForge does not collect stay in
:data:`FUTURE_CHAINS` rather than being faked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..models.alert import Alert


@dataclass(frozen=True)
class ChainStage:
    """One step of an attack chain.

    A stage matches an alert when the alert's rule id is in :attr:`rule_ids`,
    or when any of its ATT&CK technique ids is in :attr:`technique_ids`.
    """

    name: str
    rule_ids: frozenset[str] = frozenset()
    technique_ids: frozenset[str] = frozenset()

    def matches(self, alert: Alert) -> bool:
        if alert.rule_id in self.rule_ids:
            return True
        if not self.technique_ids:
            return False
        mitre = alert.mitre or {}
        ids = {mitre.get("technique_id"), mitre.get("sub_technique_id")} - {None}
        return bool(ids & self.technique_ids)


@dataclass(frozen=True)
class AttackChain:
    """A named sequence of stages that escalates an incident.

    Attributes:
        chain_id: Stable id, e.g. ``POSSIBLE_ACCOUNT_COMPROMISE``.
        title: Incident title used when this chain is the strongest match.
        description: What the chain means, in one sentence.
        stages: Stages that must all occur, in order, on distinct alerts.
        risk_bonus: Points added to the incident score when this chain matches.
    """

    chain_id: str
    title: str
    description: str
    stages: tuple[ChainStage, ...]
    risk_bonus: int

    def match(self, alerts: Sequence[Alert]) -> list[Alert] | None:
        """Return the alerts that satisfy the stages in order, or ``None``.

        ``alerts`` must be chronological.  Each stage consumes a later alert
        than the stage before it, so an out-of-order sequence does not match.
        """
        matched: list[Alert] = []
        index = 0
        for stage in self.stages:
            while index < len(alerts) and not stage.matches(alerts[index]):
                index += 1
            if index >= len(alerts):
                return None
            matched.append(alerts[index])
            index += 1
        return matched


# -- stage vocabulary ------------------------------------------------------
FAILED_AUTH = ChainStage(
    "failed authentication",
    rule_ids=frozenset({"SSH_BRUTE_FORCE", "AUTH_INVALID_USER", "AUTH_REPEATED_FAILURES"}),
)
SUCCESSFUL_AUTH = ChainStage(
    "successful authentication",
    rule_ids=frozenset({"SSH_COMPROMISE_SUSPECTED", "AUTH_ROOT_LOGIN_REMOTE"}),
)
PRIVILEGE_ESCALATION = ChainStage(
    "privilege escalation",
    rule_ids=frozenset({"SUSPICIOUS_SUDO"}),
    technique_ids=frozenset({"T1548", "T1548.003", "T1098", "T1556"}),
)
DEFENSE_EVASION = ChainStage(
    "defense evasion",
    technique_ids=frozenset({"T1562", "T1562.001", "T1562.004", "T1070", "T1070.002"}),
)
# Stages below need Phase 4 sensor telemetry (process / network events).
SUSPICIOUS_EXECUTION = ChainStage(
    "suspicious process execution",
    rule_ids=frozenset({"SUSPICIOUS_PROCESS_EXECUTION"}),
    technique_ids=frozenset({"T1059", "T1059.004"}),
)
NETWORK_ACTIVITY = ChainStage(
    "outbound network activity",
    rule_ids=frozenset({"SUSPICIOUS_NETWORK_CONNECTION", "PORT_SCAN"}),
    technique_ids=frozenset({"T1071", "T1046"}),
)

# Ordered most-specific first: the longest chain that matches wins the title.
ATTACK_CHAINS: tuple[AttackChain, ...] = (
    AttackChain(
        "AUTH_THEN_PROCESS_THEN_NETWORK",
        "Possible Post-Compromise Command And Control",
        "A successful login was followed by suspicious process execution and then "
        "by outbound network activity - the shape of a foothold calling home.",
        (SUCCESSFUL_AUTH, SUSPICIOUS_EXECUTION, NETWORK_ACTIVITY),
        risk_bonus=14,
    ),
    AttackChain(
        "POSSIBLE_ACCOUNT_COMPROMISE",
        "Possible SSH Account Compromise",
        "Repeated failed authentication was followed by a successful login and "
        "then by privileged activity from the same entity.",
        (FAILED_AUTH, SUCCESSFUL_AUTH, PRIVILEGE_ESCALATION),
        risk_bonus=12,
    ),
    AttackChain(
        "POST_COMPROMISE_DEFENSE_EVASION",
        "Possible Post-Compromise Defense Evasion",
        "A successful login was followed by tampering with security controls "
        "or logs.",
        (SUCCESSFUL_AUTH, DEFENSE_EVASION),
        risk_bonus=10,
    ),
    AttackChain(
        "PRIVILEGE_ESCALATION_THEN_EXECUTION",
        "Possible Privilege Escalation Followed By Execution",
        "Privileged activity was followed by a suspicious process execution.",
        (PRIVILEGE_ESCALATION, SUSPICIOUS_EXECUTION),
        risk_bonus=10,
    ),
    AttackChain(
        "BRUTE_FORCE_THEN_SUCCESS",
        "Possible Account Compromise",
        "Repeated authentication failures were followed by a successful "
        "authentication from the same entity.",
        (FAILED_AUTH, SUCCESSFUL_AUTH),
        risk_bonus=8,
    ),
    AttackChain(
        "POST_COMPROMISE_PRIVILEGE_ESCALATION",
        "Possible Post-Compromise Privilege Escalation",
        "A successful authentication was followed by suspicious privileged "
        "activity from the same entity.",
        (SUCCESSFUL_AUTH, PRIVILEGE_ESCALATION),
        risk_bonus=8,
    ),
)


#: Chains that need telemetry SentinelForge still does not collect.  They are
#: documented rather than implemented so nobody mistakes an empty result for
#: "this never happens".
FUTURE_CHAINS: tuple[dict[str, str], ...] = (
    {
        "chain_id": "INBOUND_SCAN_THEN_EXPLOIT",
        "description": "an inbound port scan followed by a service compromise",
        "requires": "inbound connection telemetry; the Phase 4 eBPF network sensor "
        "traces outbound connect() calls, not accepted or dropped connections",
    },
    {
        "chain_id": "LATERAL_MOVEMENT_BETWEEN_HOSTS",
        "description": "a compromise on one host followed by authentication to another",
        "requires": "events from more than one machine; SentinelForge is currently "
        "a single-host tool with no event forwarding",
    },
)


def match_chains(alerts: Sequence[Alert]) -> list[tuple[AttackChain, list[Alert]]]:
    """Return every chain that matches these alerts, strongest bonus first.

    Args:
        alerts: The incident's alerts in chronological order.
    """
    matches = []
    for chain in ATTACK_CHAINS:
        matched = chain.match(alerts)
        if matched:
            matches.append((chain, matched))
    matches.sort(key=lambda item: item[0].risk_bonus, reverse=True)
    return matches
