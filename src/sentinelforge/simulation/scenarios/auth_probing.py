"""Scenarios for the account-oriented authentication rules (Phase 8).

``SSH_BRUTE_FORCE`` reasons about a source *address*.  Three other rules look
at the same authentication events from a different angle, and each needs its
own scenario or it is shipped untested:

* ``AUTH_INVALID_USER``      - one source probing accounts that do not exist.
* ``AUTH_REPEATED_FAILURES`` - one account failing repeatedly, from anywhere.
* ``AUTH_ROOT_LOGIN_REMOTE`` - a privileged account succeeding from off-host.

Each scenario is tuned to stay *below* the neighbouring rules' thresholds, so
what fires is the rule under test and nothing else.  That is asserted rather
than assumed: every one forbids the rules it is designed not to trigger.
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
    ssh_invalid_user,
    ssh_success,
)

PROBE_IP = "203.0.113.30"
ROOT_LOGIN_IP = "203.0.113.40"

#: Accounts that do not exist on the host, in sshd's "invalid user" phrasing.
PROBED_ACCOUNTS = ("oracle", "postgres", "jenkins", "ubuntu")

#: Four attempts is below SSH_BRUTE_FORCE's threshold of five on purpose: what
#: makes this an incident is the number of distinct nonexistent accounts, not
#: the volume.
def _build_invalid_user(base: datetime) -> list:
    return [
        ssh_invalid_user(index * 25, base, PROBE_IP, account)
        for index, account in enumerate(PROBED_ACCOUNTS)
    ]


INVALID_USER = Scenario(
    scenario_id="auth-invalid-user",
    name="Account Probing For Nonexistent Users",
    description=(
        f"{PROBE_IP} attempts to authenticate as {len(PROBED_ACCOUNTS)} accounts that "
        "do not exist on this host, staying below the brute-force threshold."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1110", "T1110.001"),
    build=_build_invalid_user,
    tags=("authentication", "reconnaissance"),
    containment_target=("block_ip", PROBE_IP),
    expected=Expectation(
        events=len(PROBED_ACCOUNTS),
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"AUTH_INVALID_USER"}),
        # Four failures is under the five SSH_BRUTE_FORCE needs, and four
        # failures spread over four accounts is under the ten one account needs.
        forbidden_rule_ids=frozenset(
            {"SSH_BRUTE_FORCE", "AUTH_REPEATED_FAILURES", "SSH_COMPROMISE_SUSPECTED"}
        ),
        severity="medium",
        risk_range=(50, 60),
        techniques=frozenset({"T1110", "T1110.001"}),
        source_ips=frozenset({PROBE_IP}),
        response_options=frozenset({"block_ip"}),
        notes=(
            "The alert names no single account, because several were targeted; "
            "the incident therefore records a source address and no user."
        ),
    ),
)


# -- repeated failures for one account, from several addresses --------------
SERVICE_ACCOUNT = "svc-backup"
FAILURE_SOURCES = (ATTACKER_IP, "203.0.113.51", "203.0.113.52")


def _build_repeated_failures(base: datetime) -> list:
    # Ten failures for one account in under five minutes, deliberately split
    # across three addresses so no single address reaches the brute-force
    # threshold of five.  Only the account-oriented rule can see this.
    pattern = (0, 0, 0, 0, 1, 1, 1, 2, 2, 2)
    return [
        ssh_failure(index * 25, base, FAILURE_SOURCES[source], SERVICE_ACCOUNT)
        for index, source in enumerate(pattern)
    ]


REPEATED_FAILURES = Scenario(
    scenario_id="auth-repeated-failures",
    name="Repeated Authentication Failures For One Account",
    description=(
        f"Ten failed authentications for '{SERVICE_ACCOUNT}' in under five minutes, "
        f"spread across {len(FAILURE_SOURCES)} addresses so that no single one "
        "reaches the brute-force threshold."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1110",),
    build=_build_repeated_failures,
    tags=("authentication", "credential-access", "distributed"),
    expected=Expectation(
        events=10,
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"AUTH_REPEATED_FAILURES"}),
        forbidden_rule_ids=frozenset(
            {"SSH_BRUTE_FORCE", "AUTH_INVALID_USER", "SSH_COMPROMISE_SUSPECTED"}
        ),
        severity="medium",
        risk_range=(55, 65),
        techniques=frozenset({"T1110"}),
        users=frozenset({SERVICE_ACCOUNT}),
        # The alert names no single source, because three were involved, so the
        # incident offers no address to block.  Recording that honestly is the
        # point: a distributed attempt is harder to contain, and the platform
        # should not pretend otherwise.
        response_options=frozenset(),
        notes=(
            "A distributed attempt against one account. The incident has a user "
            "and no source address, so no containment target is offered."
        ),
    ),
)


# -- a privileged account logging in from off-host -------------------------
def _build_root_login(base: datetime) -> list:
    return [
        ssh_success(0, base, ROOT_LOGIN_IP, "root"),
        session_open(2, base, "root", ROOT_LOGIN_IP),
    ]


REMOTE_ROOT_LOGIN = Scenario(
    scenario_id="remote-root-login",
    name="Remote Privileged Login",
    description=(
        f"The root account authenticates successfully from {ROOT_LOGIN_IP}, with no "
        "failed attempts before it."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1078", "T1078.003"),
    build=_build_root_login,
    tags=("authentication", "initial-access"),
    containment_target=("block_ip", ROOT_LOGIN_IP),
    expected=Expectation(
        events=2,
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"AUTH_ROOT_LOGIN_REMOTE"}),
        # Nothing failed, so nothing may be reported as a compromise.
        forbidden_rule_ids=frozenset(
            {"SSH_BRUTE_FORCE", "SSH_COMPROMISE_SUSPECTED", "AUTH_REPEATED_FAILURES"}
        ),
        severity="medium",
        risk_range=(55, 65),
        techniques=frozenset({"T1078", "T1078.003"}),
        source_ips=frozenset({ROOT_LOGIN_IP}),
        users=frozenset({"root"}),
        response_options=frozenset({"block_ip"}),
        notes=(
            "A successful privileged login is worth an analyst's attention even "
            "when it is legitimate; it is reported as medium, not critical."
        ),
    ),
)
