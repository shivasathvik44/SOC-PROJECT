"""Benign scenarios: the false-positive half of the validation (Phase 8).

A detection platform that alerts on everything detects nothing.  These
scenarios are ordinary Linux activity -- a login, a package update, an editor,
a database connection -- and every one of them expects **zero alerts and zero
incidents**.

They are run by exactly the same runner, against exactly the same rules, with
no special casing.  When one of them produces an alert, that is a false
positive, and Phase 8 reports it as a failure with the rule id and the evidence
that caused it.  The remedy is never to silence the rule in order to pass: it
is to look at why the rule considered ordinary work suspicious, and to say so
in the report if the behaviour turns out to be intended.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import (
    ADMIN_IP,
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

OPERATOR = "capslock"

#: Every rule that ships with SentinelForge.  A benign scenario forbids all of
#: them by name, so adding a new rule that misfires on ordinary activity shows
#: up here rather than in production.
ALL_RULE_IDS = frozenset(
    {
        "SSH_BRUTE_FORCE",
        "SSH_COMPROMISE_SUSPECTED",
        "SUSPICIOUS_SUDO",
        "AUTH_INVALID_USER",
        "AUTH_REPEATED_FAILURES",
        "AUTH_ROOT_LOGIN_REMOTE",
        "SUSPICIOUS_PROCESS_EXECUTION",
        "SUSPICIOUS_NETWORK_CONNECTION",
        "PORT_SCAN",
    }
)


def _quiet(events: int) -> Expectation:
    """The expectation every benign scenario shares: nothing fires."""
    return Expectation(
        events=events,
        alerts=0,
        incidents=0,
        rule_ids=frozenset(),
        forbidden_rule_ids=ALL_RULE_IDS,
        response_options=frozenset(),
    )


# -- 1. a normal login -----------------------------------------------------
def _build_login(base: datetime) -> list:
    return [
        ssh_success(0, base, ADMIN_IP, OPERATOR),
        session_open(2, base, OPERATOR, ADMIN_IP),
    ]


BENIGN_LOGIN = Scenario(
    scenario_id="benign-ssh-login",
    name="Normal SSH Login",
    description=f"One successful SSH login for '{OPERATOR}' from the admin subnet.",
    kind=ScenarioKind.BENIGN,
    mitre_techniques=(),
    build=_build_login,
    tags=("false-positive", "authentication"),
    expected=_quiet(2),
)


# -- 2. routine administration ---------------------------------------------
def _build_sudo(base: datetime) -> list:
    return [
        sudo_command(0, base, "/usr/bin/dnf upgrade --refresh -y", OPERATOR),
        sudo_command(120, base, "/usr/bin/systemctl restart nginx", OPERATOR),
        sudo_command(240, base, "/usr/bin/vim /etc/hosts", OPERATOR),
        sudo_command(300, base, "/usr/bin/journalctl -u sshd -n 100", OPERATOR),
        sudo_command(360, base, "/usr/sbin/firewall-cmd --list-all", OPERATOR),
    ]


BENIGN_SUDO = Scenario(
    scenario_id="benign-sudo",
    name="Routine Administration",
    description=(
        "Package upgrade, service restart, editing /etc/hosts, reading logs and "
        "listing firewall rules - all through sudo, none of it suspicious."
    ),
    kind=ScenarioKind.BENIGN,
    mitre_techniques=(),
    build=_build_sudo,
    tags=("false-positive", "sudo"),
    expected=_quiet(5),
)


# -- 3. an ordinary working session ----------------------------------------
def _build_process(base: datetime) -> list:
    return [
        process_start(
            0, base, process="bash", pid=5100, ppid=1200, parent="sshd",
            command_line="-bash", user=OPERATOR, executable="/usr/bin/bash",
        ),
        process_start(
            10, base, process="vim", pid=5110, ppid=5100, parent="bash",
            command_line="vim notes.md", user=OPERATOR, executable="/usr/bin/vim",
        ),
        process_start(
            20, base, process="git", pid=5120, ppid=5100, parent="bash",
            command_line="git status", user=OPERATOR, executable="/usr/bin/git",
        ),
        process_start(
            30, base, process="python3", pid=5130, ppid=5100, parent="bash",
            command_line="python3 manage.py check", user=OPERATOR,
            executable="/usr/bin/python3",
        ),
    ]


BENIGN_PROCESS = Scenario(
    scenario_id="benign-process",
    name="Normal Shell Activity",
    description=(
        "A login shell running an editor, git and a Python script. A shell "
        "spawned by sshd is a login, not an intrusion."
    ),
    kind=ScenarioKind.BENIGN,
    mitre_techniques=(),
    build=_build_process,
    tags=("false-positive", "ebpf", "process"),
    expected=_quiet(4),
)


# -- 4. ordinary network traffic -------------------------------------------
def _build_network(base: datetime) -> list:
    return [
        process_start(
            0, base, process="curl", pid=5200, ppid=5100, parent="bash",
            command_line="curl -sS https://mirror.example.net/repodata",
            user=OPERATOR, executable="/usr/bin/curl",
        ),
        # curl talking to the internet is what curl is for.
        network_connection(
            5, base, process="curl", pid=5200, destination_ip="198.51.100.20",
            destination_port=443, user=OPERATOR, source_ip=INTERNAL_IP,
        ),
        # An interpreter talking to an *internal* database is normal too.
        network_connection(
            20, base, process="python3", pid=5130, destination_ip="10.10.0.5",
            destination_port=5432, user=OPERATOR, source_ip=INTERNAL_IP,
        ),
    ]


BENIGN_NETWORK = Scenario(
    scenario_id="benign-network",
    name="Normal Outbound Traffic",
    description=(
        "curl fetching repository metadata, and a Python service connecting to "
        "an internal PostgreSQL instance."
    ),
    kind=ScenarioKind.BENIGN,
    mitre_techniques=(),
    build=_build_network,
    tags=("false-positive", "ebpf", "network"),
    expected=_quiet(3),
)


# -- 5. a whole ordinary morning -------------------------------------------
def _build_admin_day(base: datetime) -> list:
    return [
        # One mistyped password, then a successful login: the most common
        # benign pattern there is, and the one nearest to a real detection.
        ssh_failure(0, base, ADMIN_IP, OPERATOR),
        ssh_success(15, base, ADMIN_IP, OPERATOR),
        session_open(17, base, OPERATOR, ADMIN_IP),
        process_start(
            25, base, process="bash", pid=5300, ppid=1200, parent="sshd",
            command_line="-bash", user=OPERATOR, executable="/usr/bin/bash",
        ),
        sudo_command(60, base, "/usr/bin/dnf install -y tmux", OPERATOR),
        process_start(
            90, base, process="tmux", pid=5310, ppid=5300, parent="bash",
            command_line="tmux new -s work", user=OPERATOR, executable="/usr/bin/tmux",
        ),
        network_connection(
            120, base, process="curl", pid=5320, destination_ip="198.51.100.20",
            destination_port=443, user=OPERATOR, source_ip=INTERNAL_IP,
        ),
    ]


BENIGN_ADMIN_DAY = Scenario(
    scenario_id="benign-admin-day",
    name="An Ordinary Administrator's Morning",
    description=(
        "A mistyped password, a successful login, a package installation, a "
        "terminal multiplexer and one repository fetch."
    ),
    kind=ScenarioKind.BENIGN,
    mitre_techniques=(),
    build=_build_admin_day,
    tags=("false-positive", "mixed"),
    expected=_quiet(7),
)


BENIGN_SCENARIOS = (
    BENIGN_LOGIN,
    BENIGN_SUDO,
    BENIGN_PROCESS,
    BENIGN_NETWORK,
    BENIGN_ADMIN_DAY,
)
