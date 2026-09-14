"""Scenario 3: suspicious privilege escalation via sudo (Phase 8).

Three sudo invocations by one account: two that a SOC wants to hear about, and
one that it does not.  The third is there on purpose -- a scenario that only
contains suspicious activity cannot demonstrate that routine administration
stays quiet, and a rule that alerts on ``dnf install`` is worse than no rule.

Nothing here executes.  Each "command" is a string inside a synthetic sudo log
message; the detection rule matches it with regular expressions and never
expands, interprets or runs it.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import Expectation, Scenario, ScenarioKind, sudo_command

OPERATOR = "deploy"

#: Read a credential file: MEDIUM, T1003.008.
CREDENTIAL_READ = "/usr/bin/cat /etc/shadow"
#: Write a sudoers drop-in: HIGH, T1556 -- this one changes who may become root.
SUDOERS_WRITE = "/usr/bin/tee /etc/sudoers.d/99-deploy"
#: Routine administration that must not alert.
BENIGN_ADMIN = "/usr/bin/dnf install -y htop"


def build(base: datetime) -> list:
    return [
        sudo_command(0, base, CREDENTIAL_READ, OPERATOR),
        sudo_command(60, base, SUDOERS_WRITE, OPERATOR),
        sudo_command(120, base, BENIGN_ADMIN, OPERATOR),
    ]


SCENARIO = Scenario(
    scenario_id="suspicious-sudo",
    name="Suspicious Sudo Activity",
    description=(
        f"'{OPERATOR}' reads /etc/shadow and writes a sudoers drop-in via sudo, "
        "alongside one routine package installation that must stay quiet."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1003", "T1003.008", "T1556"),
    build=build,
    tags=("privilege-escalation", "credential-access", "persistence"),
    expected=Expectation(
        events=3,
        alerts=2,
        incidents=1,
        rule_ids=frozenset({"SUSPICIOUS_SUDO"}),
        forbidden_rule_ids=frozenset(
            {"SSH_BRUTE_FORCE", "SSH_COMPROMISE_SUSPECTED", "SUSPICIOUS_PROCESS_EXECUTION"}
        ),
        severity="high",
        risk_range=(75, 85),
        techniques=frozenset({"T1003", "T1003.008", "T1556"}),
        users=frozenset({OPERATOR}),
        # No source address and no PID: sudo log lines carry neither, so this
        # incident offers an analyst nothing to contain.  Saying so is the
        # honest result, and the runner checks it rather than glossing over it.
        response_options=frozenset(),
        notes=(
            "Two of three sudo commands alert.  'dnf install' does not, which is "
            "the false-positive half of this scenario."
        ),
    ),
)
