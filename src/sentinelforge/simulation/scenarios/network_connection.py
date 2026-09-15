"""Scenario 5: an outbound connection from a shell (Phase 8).

A login shell opens a TCP connection to an external address.  ``curl`` doing
that is its job; ``bash`` doing it is the shape of a reverse shell, and that
distinction -- which process, not which destination -- is what the rule keys on.

The scenario exists mainly to validate that network telemetry survives the
whole pipeline with its fields intact: the PID, the process name, the
destination address, the destination port, the protocol and the timestamp all
have to still be there when the dashboard renders the incident's network view.
No connection is opened; the event is a synthetic record.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import (
    C2_IP,
    Expectation,
    INTERNAL_IP,
    Scenario,
    ScenarioKind,
    network_connection,
    process_start,
)

OPERATOR = "deploy"
SHELL_PID = 4400
SSHD_PID = 1200
DESTINATION_PORT = 8443


def build(base: datetime) -> list:
    return [
        process_start(
            0, base, process="bash", pid=SHELL_PID, ppid=SSHD_PID, parent="sshd",
            command_line="-bash", user=OPERATOR, executable="/usr/bin/bash",
        ),
        network_connection(
            30, base, process="bash", pid=SHELL_PID, destination_ip=C2_IP,
            destination_port=DESTINATION_PORT, user=OPERATOR, source_ip=INTERNAL_IP,
        ),
    ]


SCENARIO = Scenario(
    scenario_id="network-connection",
    name="Outbound Connection From A Shell",
    description=(
        f"A login shell (pid {SHELL_PID}) opens a TCP connection to "
        f"{C2_IP}:{DESTINATION_PORT}."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1071",),
    build=build,
    tags=("command-and-control", "ebpf", "network"),
    containment_target=("block_ip", C2_IP),
    expected=Expectation(
        events=2,
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"SUSPICIOUS_NETWORK_CONNECTION"}),
        forbidden_rule_ids=frozenset({"SUSPICIOUS_PROCESS_EXECUTION", "PORT_SCAN"}),
        severity="medium",
        risk_range=(55, 65),
        techniques=frozenset({"T1071"}),
        source_ips=frozenset({C2_IP}),
        users=frozenset({OPERATOR}),
        response_options=frozenset({"block_ip", "kill_process"}),
        # Only the connecting process is evidence here; the execve that
        # created it did not alert, so it is not in the incident.
        process_tree_pids=frozenset({SHELL_PID}),
        process_tree_missing_pids=frozenset({SSHD_PID}),
        network_destinations=frozenset({f"{C2_IP}:{DESTINATION_PORT}"}),
        notes=(
            "One connection is not a port scan: PORT_SCAN needs ten distinct "
            "destination ports and must stay silent here."
        ),
    ),
)
