"""Scenario 1: SSH brute force (Phase 8).

Six failed SSH password authentications from one documentation address inside
two minutes.  Nothing is sent anywhere: the scenario produces the *normalized
events* that such an attack would leave in the journal, which is exactly what
``sentinelforge collect`` would hand to detection.

What a SOC should get out of it: one ``SSH_BRUTE_FORCE`` alert mapped to
T1110.001, one incident, and a source address an analyst could block.  What it
must **not** get is a compromise alert -- nothing succeeded here -- or the
account-oriented rules, whose thresholds this volume does not reach.  Both are
asserted.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import (
    ATTACKER_IP,
    Expectation,
    Scenario,
    ScenarioKind,
    ssh_failure,
)

#: Six attempts, twenty seconds apart: above the rule's threshold of five, and
#: comfortably inside its five-minute window.
ATTEMPTS = 6
INTERVAL_SECONDS = 20
TARGET_USER = "backup"


def build(base: datetime) -> list:
    return [
        ssh_failure(index * INTERVAL_SECONDS, base, ATTACKER_IP, TARGET_USER)
        for index in range(ATTEMPTS)
    ]


SCENARIO = Scenario(
    scenario_id="ssh-bruteforce",
    name="SSH Brute Force",
    description=(
        f"{ATTEMPTS} failed SSH password authentications for '{TARGET_USER}' from "
        f"{ATTACKER_IP} in {(ATTEMPTS - 1) * INTERVAL_SECONDS} seconds."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1110", "T1110.001"),
    build=build,
    tags=("authentication", "credential-access"),
    containment_target=("block_ip", ATTACKER_IP),
    expected=Expectation(
        events=ATTEMPTS,
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"SSH_BRUTE_FORCE"}),
        # A failure-only burst must not be reported as a compromise, and six
        # failures for one account is below the account rule's threshold of ten.
        forbidden_rule_ids=frozenset(
            {
                "SSH_COMPROMISE_SUSPECTED",
                "AUTH_REPEATED_FAILURES",
                "AUTH_INVALID_USER",
                "AUTH_ROOT_LOGIN_REMOTE",
            }
        ),
        severity="high",
        risk_range=(70, 80),
        techniques=frozenset({"T1110", "T1110.001"}),
        source_ips=frozenset({ATTACKER_IP}),
        users=frozenset({TARGET_USER}),
        response_options=frozenset({"block_ip"}),
        notes="Failures alone: high, not critical, and no compromise claimed.",
    ),
)
