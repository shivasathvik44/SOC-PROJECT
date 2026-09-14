"""Scenario 2: brute force followed by a successful login (Phase 8).

The same address that just failed five times succeeds on the sixth attempt.
That transition is the moment an attack may have worked, and it is what
separates this scenario from :mod:`.ssh_bruteforce`: the telemetry differs by a
single successful authentication, and the expected outcome differs by a whole
severity band.

Temporal correlation is the thing under test.  The success must be tied to the
failures *that preceded it from the same source*, both by the
``SSH_COMPROMISE_SUSPECTED`` rule and, one level up, by the correlation engine
folding both alerts into one incident with the ``BRUTE_FORCE_THEN_SUCCESS``
chain.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import (
    ATTACKER_IP,
    Expectation,
    Scenario,
    ScenarioKind,
    session_open,
    ssh_failure,
    ssh_success,
)

FAILURES = 5
INTERVAL_SECONDS = 30
SUCCESS_OFFSET = 150
TARGET_USER = "deploy"


def build(base: datetime) -> list:
    events = [
        ssh_failure(index * INTERVAL_SECONDS, base, ATTACKER_IP, TARGET_USER)
        for index in range(FAILURES)
    ]
    events.append(ssh_success(SUCCESS_OFFSET, base, ATTACKER_IP, TARGET_USER))
    events.append(session_open(SUCCESS_OFFSET + 2, base, TARGET_USER, ATTACKER_IP))
    return events


SCENARIO = Scenario(
    scenario_id="ssh-compromise",
    name="SSH Brute Force Followed By Successful Login",
    description=(
        f"{FAILURES} failed SSH authentications for '{TARGET_USER}' from {ATTACKER_IP}, "
        "then a successful authentication from the same address."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1110", "T1110.001", "T1078", "T1078.003"),
    build=build,
    tags=("authentication", "initial-access"),
    containment_target=("block_ip", ATTACKER_IP),
    expected=Expectation(
        events=FAILURES + 2,
        alerts=2,
        incidents=1,
        rule_ids=frozenset({"SSH_BRUTE_FORCE", "SSH_COMPROMISE_SUSPECTED"}),
        forbidden_rule_ids=frozenset(
            {"AUTH_ROOT_LOGIN_REMOTE", "SUSPICIOUS_SUDO", "PORT_SCAN"}
        ),
        severity="critical",
        risk_range=(95, 100),
        techniques=frozenset({"T1110", "T1110.001", "T1078", "T1078.003"}),
        attack_chains=frozenset({"BRUTE_FORCE_THEN_SUCCESS"}),
        source_ips=frozenset({ATTACKER_IP}),
        users=frozenset({TARGET_USER}),
        response_options=frozenset({"block_ip"}),
        notes=(
            "The success is correlated to the failures that preceded it from the "
            "same address; the two alerts become one incident, not two."
        ),
    ),
)
