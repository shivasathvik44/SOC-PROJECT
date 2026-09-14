"""Phase 7: containment backends.

The real backend classes are exercised here with a *scripted* command runner:
it returns canned output and records the argv it was given, and never starts a
process.  So these tests prove what SentinelForge would run against firewalld
and logind without running any of it, and the developer's own firewall is never
touched.
"""

import pytest

from sentinelforge.response.backends.firewall import (
    RULE_PREFIX,
    FirewalldBackend,
    UnsupportedFirewallBackend,
    build_rich_rule,
    detect_firewall_backend,
    rule_action_id,
)
from sentinelforge.response.backends.mock import (
    FAIL_BACKEND,
    FAIL_PERMISSION,
    FAIL_SURVIVES,
    FAIL_VERIFY,
    MockFirewallBackend,
    MockProcessBackend,
    MockSessionBackend,
)
from sentinelforge.response.backends.process import LinuxProcessBackend
from sentinelforge.response.backends.session import (
    LoginctlSessionBackend,
    UnsupportedSessionBackend,
    detect_session_backend,
    own_session_id,
)
from sentinelforge.response.executor import CommandResult, CommandRunner, ExecutionError
from sentinelforge.response.validators import ValidationError

RULE = build_rich_rule("203.0.113.50", "ACTION-00001")


class ScriptedRunner(CommandRunner):
    """A runner that answers from a script and never starts a process."""

    def __init__(self, responses=None, available_programs=("firewall-cmd", "loginctl")):
        super().__init__()
        self.responses = list(responses or [])
        self.available_programs = set(available_programs)
        self.calls = []

    def available(self, name):
        return name in self.available_programs

    def run(self, argv, timeout=None, mutating=False):
        if argv[0] not in self.available_programs:
            raise ExecutionError(f"{argv[0]} is not installed on this host")
        self.calls.append((tuple(argv), mutating))
        if not self.responses:
            return CommandResult(argv=tuple(argv), returncode=0, stdout="")
        nextval = self.responses.pop(0)
        if isinstance(nextval, Exception):
            raise nextval
        stdout, returncode = nextval if isinstance(nextval, tuple) else (nextval, 0)
        return CommandResult(argv=tuple(argv), returncode=returncode, stdout=stdout)


def firewalld(responses=None, **kwargs):
    return FirewalldBackend(runner=ScriptedRunner(responses), zone="public", **kwargs)


class TestRichRules:
    def test_a_rule_carries_the_address_and_the_action_id(self):
        assert 'source address="203.0.113.50"' in RULE
        assert f"{RULE_PREFIX}ACTION-00001" in RULE
        assert RULE.endswith("drop")

    def test_ipv6_gets_the_right_family(self):
        assert 'family="ipv6"' in build_rich_rule("2001:db8::1", "ACTION-00002")

    def test_the_rule_is_rendered_from_typed_values_not_the_input_string(self):
        """A hostile target cannot reach the rule text: it fails to parse."""
        with pytest.raises(ValidationError):
            build_rich_rule('203.0.113.50" accept; rule family="ipv4', "ACTION-00001")

    def test_a_hostile_action_id_is_refused(self):
        with pytest.raises(ValueError):
            build_rich_rule("203.0.113.50", 'X" accept "')

    def test_an_action_id_can_be_read_back_off_a_rule(self):
        assert rule_action_id(RULE) == "ACTION-00001"

    def test_a_foreign_rule_has_no_action_id(self):
        assert rule_action_id('rule family="ipv4" source address="10.0.0.1" drop') is None


class TestFirewalldAvailability:
    def test_a_running_daemon_is_available(self):
        assert firewalld(["running"]).status().available

    def test_a_stopped_daemon_is_unavailable_with_a_remedy(self):
        status = firewalld([("not running", 252)]).status()
        assert not status.available
        assert "not running" in status.reason
        assert "never starts, stops or reconfigures" in status.remedy

    def test_a_missing_firewall_cmd_is_unavailable(self):
        backend = FirewalldBackend(runner=ScriptedRunner(available_programs=()))
        status = backend.status()
        assert not status.available
        assert "not found" in status.reason

    def test_availability_is_cached(self):
        backend = firewalld(["running"])
        backend.status()
        backend.status()
        assert len(backend.runner.calls) == 1

    def test_detection_falls_back_to_the_unsupported_backend(self):
        backend = detect_firewall_backend(ScriptedRunner(available_programs=()))
        assert isinstance(backend, UnsupportedFirewallBackend)
        assert "nftables" in backend.status().remedy


class TestFirewalldBlocking:
    def test_a_block_uses_an_argument_array_with_no_shell(self):
        backend = firewalld(["no", "", "yes"])
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001", 900)
        assert outcome.ok
        add = [call for call, mutating in backend.runner.calls if mutating][0]
        assert add[0] == "firewall-cmd"
        assert "--add-rich-rule" in add
        assert "--timeout=900s" in add
        assert "--permanent" not in add

    def test_a_block_is_verified_by_re_querying_the_rule(self):
        backend = firewalld(["no", "", "no"])
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001")
        assert not outcome.ok
        assert "not present" in outcome.detail

    def test_a_refused_command_reports_the_privilege_remedy(self):
        backend = firewalld(["no", ("Error: Authorization failed.", 1)])
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001")
        assert not outcome.ok
        assert "privileges" in outcome.error

    def test_an_already_present_rule_is_not_added_twice(self):
        backend = firewalld(["yes"])
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001")
        assert outcome.ok
        assert not [call for call, mutating in backend.runner.calls if mutating]

    def test_the_rollback_data_names_the_exact_rule(self):
        backend = firewalld(["no", "", "yes"])
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001")
        assert outcome.rollback_data["rich_rule"] == RULE
        assert outcome.rollback_data["zone"] == "public"


class TestFirewalldUnblocking:
    def test_removal_targets_the_recorded_rule(self):
        backend = firewalld(["yes", "", "no"])
        outcome = backend.unblock_ip({"rich_rule": RULE, "zone": "public"})
        assert outcome.ok
        remove = [call for call, mutating in backend.runner.calls if mutating][0]
        assert "--remove-rich-rule" in remove
        assert RULE in remove

    def test_a_rule_sentinelforge_did_not_create_is_refused(self):
        backend = firewalld()
        outcome = backend.unblock_ip(
            {"rich_rule": 'rule family="ipv4" source address="10.0.0.1" drop', "zone": "public"}
        )
        assert not outcome.ok
        assert "did not create" in outcome.detail
        assert not backend.runner.calls

    def test_empty_rollback_data_is_refused(self):
        assert not firewalld().unblock_ip({}).ok

    def test_a_rule_that_already_lapsed_counts_as_removed(self):
        outcome = firewalld(["no"]).unblock_ip({"rich_rule": RULE, "zone": "public"})
        assert outcome.ok
        assert "already gone" in outcome.detail

    def test_a_bad_zone_name_is_refused(self):
        outcome = firewalld().unblock_ip({"rich_rule": RULE, "zone": "public; reboot"})
        assert not outcome.ok


class TestFirewalldListing:
    def test_only_sentinelforge_rules_are_listed(self):
        listing = (
            f'{RULE}\n'
            'rule family="ipv4" source address="10.0.0.1" drop\n'
        )
        backend = firewalld([listing])
        rules = backend.managed_rules()
        assert len(rules) == 1
        assert rules[0]["address"] == "203.0.113.50"
        assert rules[0]["action_id"] == "ACTION-00001"

    def test_blocked_addresses_map_to_their_action(self):
        assert firewalld([RULE]).blocked_addresses() == {"203.0.113.50": "ACTION-00001"}


class TestUnsupportedFirewall:
    def test_every_mutation_is_refused_with_the_reason(self):
        backend = UnsupportedFirewallBackend("no firewalld here", "install it")
        assert not backend.is_available()
        assert not backend.block_ip("203.0.113.50", "ACTION-00001").ok
        assert not backend.unblock_ip({"rich_rule": RULE}).ok
        assert backend.managed_rules() == []
        assert backend.preview_block("203.0.113.50", "ACTION-00001")["unavailable_reason"]


class TestLinuxProcessBackend:
    def test_it_reads_this_process_from_proc(self):
        import os

        info = LinuxProcessBackend().get_process(os.getpid())
        assert info.pid == os.getpid()
        assert info.start_ticks is not None
        assert info.command_line

    def test_a_command_line_is_flattened_to_one_readable_line(self, tmp_path):
        proc = tmp_path / "4242"
        proc.mkdir()
        (proc / "stat").write_text("4242 (weird name) S 1 " + " ".join(["0"] * 18) + " 999")
        (proc / "status").write_text("Name:\tweird name\nUid:\t1000\t1000\t1000\t1000\n")
        (proc / "cmdline").write_bytes(b"python3\x00-c\x00import socket\nimport os\x00")
        info = LinuxProcessBackend(proc=str(tmp_path)).get_process(4242)
        assert "\n" not in info.command_line
        assert info.name == "weird name"
        assert info.uid == 1000

    def test_a_missing_process_is_none(self):
        assert LinuxProcessBackend().get_process(999999) is None

    def test_validate_target_raises_for_a_missing_process(self):
        with pytest.raises(ValidationError, match="no process"):
            LinuxProcessBackend().validate_target(999999)

    def test_verification_uses_the_start_time_to_defeat_pid_reuse(self):
        import os

        backend = LinuxProcessBackend()
        info = backend.get_process(os.getpid())
        assert backend.verify_terminated(os.getpid(), info.start_ticks) is False
        # A different start time means the PID now belongs to another process.
        assert backend.verify_terminated(os.getpid(), info.start_ticks + 1) is True

    def test_a_missing_pid_verifies_as_terminated(self):
        assert LinuxProcessBackend().verify_terminated(999999) is True

    def test_termination_sends_sigterm_and_never_sigkill(self):
        import signal

        sent = []
        backend = LinuxProcessBackend(signal_sender=lambda pid, sig: sent.append((pid, sig)))
        import os

        backend.terminate(os.getpid(), grace_seconds=0)
        assert sent == [(os.getpid(), signal.SIGTERM)]

    def test_a_surviving_process_is_reported_not_escalated(self):
        import os

        backend = LinuxProcessBackend(signal_sender=lambda pid, sig: None)
        outcome = backend.terminate(os.getpid(), grace_seconds=0)
        assert not outcome.ok
        assert "does not escalate" in outcome.error
        assert outcome.data["escalated"] is False

    def test_permission_denied_explains_the_privilege_requirement(self):
        import os

        def deny(pid, sig):
            raise PermissionError(1, "Operation not permitted")

        outcome = LinuxProcessBackend(signal_sender=deny).terminate(os.getpid())
        assert not outcome.ok
        assert "requires root" in outcome.error

    def test_a_process_that_exits_first_is_not_a_failure(self):
        import os

        def gone(pid, sig):
            raise ProcessLookupError()

        outcome = LinuxProcessBackend(signal_sender=gone).terminate(os.getpid())
        assert outcome.ok

    def test_a_read_only_backend_refuses_to_signal(self):
        import os

        backend = LinuxProcessBackend(allow_mutation=False, signal_sender=lambda *a: None)
        outcome = backend.terminate(os.getpid())
        assert not outcome.ok
        assert "not permitted" in outcome.detail


class TestLoginctlSessionBackend:
    def test_sessions_are_listed_from_logind(self):
        runner = ScriptedRunner(
            ["7 1000 capslock seat0 tty2\n", "Id=7\nName=capslock\nState=active\nClass=user\n"]
        )
        sessions = LoginctlSessionBackend(runner=runner, own_session="2").list_sessions()
        assert sessions[0]["id"] == "7"
        assert sessions[0]["is_own_session"] is False

    def test_the_analysts_own_session_is_refused_as_a_target(self):
        runner = ScriptedRunner(["Id=2\nName=capslock\nState=active\nClass=user\n"])
        backend = LoginctlSessionBackend(runner=runner, own_session="2")
        with pytest.raises(ValidationError, match="own session"):
            backend.validate_target("2")

    def test_a_manager_session_is_refused(self):
        runner = ScriptedRunner(["Id=3\nName=capslock\nState=active\nClass=manager\n"])
        backend = LoginctlSessionBackend(runner=runner, own_session="2")
        with pytest.raises(ValidationError, match="manager session"):
            backend.validate_target("3")

    def test_an_unknown_session_is_refused(self):
        backend = LoginctlSessionBackend(runner=ScriptedRunner([("", 1)]), own_session="2")
        with pytest.raises(ValidationError, match="no session"):
            backend.validate_target("9")

    def test_termination_uses_an_argument_array_and_verifies(self):
        runner = ScriptedRunner(
            [
                "Id=7\nName=intruder\nState=active\nClass=user\n",  # validate
                "",                                                  # terminate
                ("", 1),                                             # verify: gone
            ]
        )
        outcome = LoginctlSessionBackend(runner=runner, own_session="2").terminate("7")
        assert outcome.ok
        terminate = [call for call, mutating in runner.calls if mutating][0]
        assert terminate == ("loginctl", "terminate-session", "7")

    def test_a_session_that_survives_is_a_failure(self):
        runner = ScriptedRunner(
            [
                "Id=7\nName=intruder\nState=active\nClass=user\n",
                "",
                "Id=7\nName=intruder\nState=active\nClass=user\n",
            ]
        )
        outcome = LoginctlSessionBackend(runner=runner, own_session="2").terminate("7")
        assert not outcome.ok
        assert "still reports this session as active" in outcome.error

    def test_a_missing_loginctl_yields_the_unsupported_backend(self):
        backend = detect_session_backend(ScriptedRunner(available_programs=()))
        assert isinstance(backend, UnsupportedSessionBackend)
        with pytest.raises(ValidationError):
            backend.validate_target("7")
        assert not backend.terminate("7").ok

    def test_the_own_session_id_is_read_from_the_cgroup_when_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("XDG_SESSION_ID", raising=False)
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("0::/user.slice/user-1000.slice/session-7.scope\n")
        assert own_session_id(str(cgroup)) == "7"

    def test_no_session_scope_means_no_own_session(self, tmp_path, monkeypatch):
        monkeypatch.delenv("XDG_SESSION_ID", raising=False)
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("0::/user.slice/user-1000.slice/app.slice/terminal.scope\n")
        assert own_session_id(str(cgroup)) is None


class TestMockBackends:
    def test_the_mock_firewall_keeps_rules_in_memory_only(self):
        backend = MockFirewallBackend()
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001", 900)
        assert outcome.ok
        assert backend.blocked_addresses() == {"203.0.113.50": "ACTION-00001"}
        assert backend.unblock_ip(outcome.rollback_data).ok
        assert backend.rules == {}

    @pytest.mark.parametrize(
        "mode,marker",
        [(FAIL_PERMISSION, "permission denied"), (FAIL_BACKEND, "mock backend failure"),
         (FAIL_VERIFY, "verification failed")],
    )
    def test_failure_modes_are_injectable(self, mode, marker):
        backend = MockFirewallBackend(fail=mode)
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001")
        assert not outcome.ok
        assert marker in outcome.error

    def test_the_mock_process_backend_never_signals_anything(self):
        backend = MockProcessBackend()
        backend.add(4242)
        assert backend.terminate(4242).ok
        assert backend.terminated == [4242]
        assert backend.verify_terminated(4242)

    def test_a_mock_process_can_survive_sigterm(self):
        backend = MockProcessBackend(fail=FAIL_SURVIVES)
        backend.add(4242)
        outcome = backend.terminate(4242)
        assert not outcome.ok
        assert backend.terminated == []

    def test_a_missing_mock_process_is_reported(self):
        assert not MockProcessBackend().terminate(4242).ok

    def test_the_mock_session_backend_refuses_the_own_session(self):
        backend = MockSessionBackend()
        backend.add("2", is_own_session=True)
        with pytest.raises(ValidationError):
            backend.validate_target("2")

    def test_mock_backends_report_a_status(self):
        for backend in (MockFirewallBackend(), MockProcessBackend(), MockSessionBackend()):
            assert backend.status().available
        assert not MockFirewallBackend(available=False).status().available
