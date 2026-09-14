"""Tests for the ``sentinelforge response`` commands (Phase 7).

Every command runs against a temporary database and the in-memory containment
backends installed by ``conftest.no_real_containment``: no test writes a
firewall rule or signals a process.
"""

import io
import json

import pytest

from sentinelforge.cli import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_POLICY_REFUSED,
    EXIT_PRIVILEGE_REQUIRED,
    build_parser,
    main,
    run_response,
)


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "sentinelforge.db")


def run(db, *argv, stdout=None):
    """Parse and dispatch one ``response`` command; return (exit code, output)."""
    stream = stdout or io.StringIO()
    args = build_parser().parse_args(["response", *argv, "--db", db])
    code = run_response(args, stream)
    return code, stream.getvalue()


def request_block(db, target="203.0.113.50", *extra):
    code, output = run(db, "block-ip", target, "--incident", "INC-000001",
                       "--reason", "brute force", *extra)
    assert code == EXIT_OK, output
    return output


class TestParser:
    def test_the_response_namespace_exists(self):
        args = build_parser().parse_args(["response", "list"])
        assert args.command == "response"
        assert args.response_command == "list"

    def test_every_action_has_its_own_command(self):
        for command in ("block-ip", "unblock-ip", "kill-process", "terminate-session"):
            args = build_parser().parse_args(["response", command, "x"])
            assert args.response_command == command

    def test_approval_and_execution_are_separate_commands(self):
        assert build_parser().parse_args(
            ["response", "approve", "ACTION-00001"]
        ).response_command == "approve"
        assert build_parser().parse_args(
            ["response", "execute", "ACTION-00001"]
        ).response_command == "execute"

    def test_an_unknown_action_command_is_rejected_by_argparse(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["response", "exfiltrate", "x"])

    def test_preview_only_accepts_known_action_types(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["response", "preview", "rm-rf", "/"])


class TestCapabilities:
    def test_it_reports_each_action_and_the_guarantees(self, db):
        code, output = run(db, "capabilities")
        assert code == EXIT_OK
        assert "block_ip" in output and "isolate_host" in output
        assert "approval required:    True" in output
        assert "automatic execution:  False" in output

    def test_json_output_is_machine_readable(self, db):
        code, output = run(db, "capabilities", "--json")
        assert code == EXIT_OK
        assert json.loads(output)["approval_required"] is True


class TestPreview:
    def test_a_preview_describes_the_action_and_records_nothing(self, db):
        code, output = run(db, "preview", "block-ip", "203.0.113.50", "--ttl", "900")
        assert code == EXIT_OK
        assert "RESPONSE ACTION (preview" in output
        assert "203.0.113.50" in output
        assert "nothing was recorded and nothing was changed" in output
        assert run(db, "list")[1].strip() == "No response actions recorded."

    def test_a_preview_of_a_refused_target_exits_with_the_policy_code(self, db):
        code, output = run(db, "preview", "block-ip", "127.0.0.1")
        assert code == EXIT_POLICY_REFUSED
        assert "REFUSED" in output

    def test_a_malformed_target_is_an_error(self, db):
        code, _ = run(db, "preview", "block-ip", "203.0.113.50; rm -rf /")
        assert code == EXIT_ERROR


class TestDryRun:
    def test_a_dry_run_says_so_and_changes_nothing(self, db):
        code, output = run(db, "block-ip", "203.0.113.50", "--dry-run", "--ttl", "900")
        assert code == EXIT_OK
        assert "DRY RUN" in output
        assert "No system change was made" in output

    def test_a_dry_run_is_recorded_for_the_audit_trail(self, db):
        run(db, "block-ip", "203.0.113.50", "--dry-run")
        listing = run(db, "list")[1]
        assert "ACTION-00001" in listing and "dry_run" in listing
        assert "DRY-RUN" in run(db, "audit")[1]

    def test_a_dry_run_of_a_kill_names_the_process(self, db):
        code, output = run(db, "kill-process", "4250", "--dry-run")
        assert code == EXIT_OK
        assert "4250" in output
        assert "NOT POSSIBLE" in output  # no rollback for a terminated process


class TestApprovalWorkflow:
    def test_a_request_explains_the_next_step_and_executes_nothing(self, db):
        output = request_block(db)
        assert "AWAITING_APPROVAL" in output
        assert "a human must approve it first" in output
        assert "sentinelforge response approve ACTION-00001" in output

    def test_execution_before_approval_fails(self, db, caplog):
        request_block(db)
        code, _ = run(db, "execute", "ACTION-00001", "--yes")
        assert code == EXIT_ERROR
        assert "has not been approved" in caplog.text

    def test_approval_does_not_execute(self, db):
        request_block(db)
        code, output = run(db, "approve", "ACTION-00001")
        assert code == EXIT_OK
        assert "Nothing has been executed yet" in output

    def test_the_full_approve_then_execute_flow_completes(self, db):
        request_block(db)
        run(db, "approve", "ACTION-00001")
        code, output = run(db, "execute", "ACTION-00001", "--yes")
        assert code == EXIT_OK
        assert "COMPLETED" in output
        assert "rollback ACTION-00001" in output

    def test_an_executed_block_can_be_rolled_back(self, db):
        request_block(db)
        run(db, "approve", "ACTION-00001")
        run(db, "execute", "ACTION-00001", "--yes")
        code, output = run(db, "rollback", "ACTION-00001", "--reason", "false positive")
        assert code == EXIT_OK
        assert "ROLLED_BACK" in output

    def test_a_rejected_action_cannot_be_executed(self, db, caplog):
        request_block(db)
        run(db, "reject", "ACTION-00001", "--reason", "false positive")
        assert run(db, "execute", "ACTION-00001", "--yes")[0] == EXIT_ERROR

    def test_a_cancelled_action_cannot_be_executed(self, db):
        request_block(db)
        run(db, "cancel", "ACTION-00001")
        assert run(db, "execute", "ACTION-00001", "--yes")[0] == EXIT_ERROR

    def test_executing_an_unknown_action_is_an_error(self, db, caplog):
        assert run(db, "execute", "ACTION-99999", "--yes")[0] == EXIT_ERROR
        assert "no such response action" in caplog.text

    def test_a_disabled_engine_reports_the_privilege_exit_code(self, db, monkeypatch):
        """A process that may not change the system says so and stops."""
        from sentinelforge.response.engine import ResponseEngine

        request_block(db)
        run(db, "approve", "ACTION-00001")
        original = ResponseEngine.__init__

        def disabled(self, *args, **kwargs):
            kwargs["execution_enabled"] = False
            original(self, *args, **kwargs)

        monkeypatch.setattr(ResponseEngine, "__init__", disabled)
        code, output = run(db, "execute", "ACTION-00001", "--yes")
        assert code == EXIT_PRIVILEGE_REQUIRED
        assert "response execution is disabled" in output


class TestPolicyRefusals:
    @pytest.mark.parametrize("target", ["127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1"])
    def test_unsafe_addresses_are_refused_with_their_own_exit_code(self, db, target):
        code, output = run(db, "block-ip", target)
        assert code == EXIT_POLICY_REFUSED
        assert "REFUSED BY POLICY" in output

    def test_a_refusal_is_recorded(self, db):
        run(db, "block-ip", "127.0.0.1")
        assert "rejected" in run(db, "list")[1]
        assert "policy_denied" in run(db, "audit")[1]

    def test_a_protected_process_needs_an_explicit_override(self, db, mock_backends, monkeypatch):
        from sentinelforge.response.actions import ResponseBackends

        mock_backends.process.add(4300, name="sshd", command_line="/usr/sbin/sshd -D")
        monkeypatch.setattr(
            ResponseBackends, "detect", classmethod(lambda cls, **kwargs: mock_backends)
        )
        assert run(db, "kill-process", "4300")[0] == EXIT_POLICY_REFUSED
        code, output = run(db, "kill-process", "4300", "--override-protected",
                           "--reason", "confirmed compromised")
        assert code == EXIT_OK
        assert "OVERRIDE" in output

    def test_host_isolation_is_refused_as_planned_only(self, db):
        code, output = run(db, "isolate-host", "localhost")
        assert code == EXIT_POLICY_REFUSED
        assert "capability dependent" in output


class TestListingAndShow:
    def test_an_empty_store_says_so(self, db):
        assert "No response actions recorded" in run(db, "list")[1]

    def test_listing_shows_one_line_per_action(self, db):
        request_block(db)
        request_block(db, "198.51.100.25")
        output = run(db, "list")[1]
        assert "ACTION-00001" in output and "ACTION-00002" in output
        assert "2 action(s)" in output

    def test_listing_can_be_filtered(self, db):
        request_block(db)
        run(db, "block-ip", "198.51.100.25", "--dry-run")
        assert "ACTION-00002" not in run(db, "list", "--status", "awaiting_approval")[1]
        assert "ACTION-00001" not in run(db, "list", "--status", "dry_run")[1]

    def test_show_renders_the_action_and_its_audit_trail(self, db):
        request_block(db)
        output = run(db, "show", "ACTION-00001")[1]
        assert "Audit trail:" in output
        assert "requested" in output
        assert "brute force" in output

    def test_show_reports_an_unknown_action(self, db, caplog):
        assert run(db, "show", "ACTION-99999")[0] == EXIT_ERROR

    def test_json_output_round_trips(self, db):
        request_block(db)
        payload = json.loads(run(db, "show", "ACTION-00001", "--json")[1])
        assert payload["action"]["action_id"] == "ACTION-00001"
        assert payload["audit"]


class TestAudit:
    def test_every_step_appears_in_the_trail(self, db):
        request_block(db)
        run(db, "approve", "ACTION-00001")
        run(db, "execute", "ACTION-00001", "--yes")
        output = run(db, "audit")[1]
        for event in ("requested", "approved", "execution_started", "executed"):
            assert event in output

    def test_the_chain_can_be_verified(self, db):
        request_block(db)
        code, output = run(db, "audit", "--verify")
        assert code == EXIT_OK
        assert "Audit chain: OK" in output

    def test_the_trail_can_be_filtered_by_action(self, db):
        request_block(db)
        request_block(db, "198.51.100.25")
        output = run(db, "audit", "--action", "ACTION-00001")[1]
        assert "ACTION-00002" not in output

    def test_audit_json_includes_the_chain_hashes(self, db):
        request_block(db)
        records = json.loads(run(db, "audit", "--json")[1])
        assert records[0]["entry_hash"]


class TestMainDispatch:
    def test_main_routes_the_response_command(self, db, capsys):
        assert main(["response", "list", "--db", db]) == EXIT_OK
        assert "No response actions recorded" in capsys.readouterr().out

    def test_response_without_a_subcommand_prints_help(self, db, capsys):
        with pytest.raises(SystemExit):
            main(["response"])
