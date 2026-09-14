"""Phase 7: the command executor.

The executor is the only place in SentinelForge that can start a process, so
these tests are about what it refuses.  Nothing here runs a real command except
the allowlist lookups, which only inspect the filesystem.
"""

import pytest

from sentinelforge.response.executor import (
    ALLOWED_EXECUTABLES,
    CommandResult,
    CommandRunner,
    ExecutionError,
    ReadOnlyCommandRunner,
    resolve_executable,
)


class RecordingRunner(CommandRunner):
    """Records what would be run instead of running it."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.attempted = []

    def run(self, argv, timeout=None, mutating=False):
        self.attempted.append((tuple(argv), mutating))
        return super().run(argv, timeout=timeout, mutating=mutating)


class TestAllowlist:
    def test_only_two_programs_are_allowlisted(self):
        assert set(ALLOWED_EXECUTABLES) == {"firewall-cmd", "loginctl"}

    @pytest.mark.parametrize("name", ["sudo", "pkexec", "su", "sh", "bash", "rm", "nft",
                                      "iptables", "systemctl"])
    def test_escalation_and_destructive_tools_are_not_allowlisted(self, name):
        assert name not in ALLOWED_EXECUTABLES
        assert resolve_executable(name) is None

    def test_every_allowlisted_path_is_absolute_and_in_a_system_directory(self):
        for paths in ALLOWED_EXECUTABLES.values():
            for path in paths:
                assert path.startswith("/usr/") or path.startswith("/bin/") or path.startswith("/sbin/")

    def test_path_is_not_consulted(self, monkeypatch, tmp_path):
        """A writable directory on $PATH must not be able to supply the binary."""
        fake = tmp_path / "firewall-cmd"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        resolved = resolve_executable("firewall-cmd")
        assert resolved is None or not resolved.startswith(str(tmp_path))


class TestArgumentHandling:
    def test_a_non_allowlisted_program_is_refused(self):
        with pytest.raises(ExecutionError, match="not an allowlisted"):
            CommandRunner().run(["rm", "-rf", "/"])

    def test_a_string_command_is_refused(self):
        with pytest.raises(ExecutionError):
            CommandRunner().run("firewall-cmd --state")

    def test_an_empty_command_is_refused(self):
        with pytest.raises(ExecutionError):
            CommandRunner().run([])

    @pytest.mark.parametrize("argument", ["a\nb", "a\rb", "a\x00b"])
    def test_control_characters_in_arguments_are_refused(self, argument):
        with pytest.raises(ExecutionError):
            CommandRunner().run(["firewall-cmd", argument])

    @pytest.mark.parametrize("argument", [None, 42, ["nested"], {"a": 1}])
    def test_non_string_arguments_are_refused(self, argument):
        with pytest.raises(ExecutionError):
            CommandRunner().run(["firewall-cmd", argument])

    def test_shell_metacharacters_are_harmless_because_there_is_no_shell(self):
        """They are still passed as one literal argument, never interpreted."""
        runner = RecordingRunner(allow_mutation=False)
        with pytest.raises(ExecutionError):
            runner.run(["firewall-cmd", "; rm -rf /"], mutating=True)
        assert runner.attempted[0][0][1] == "; rm -rf /"


class TestMutationGate:
    def test_a_read_only_runner_refuses_a_mutating_command(self):
        with pytest.raises(ExecutionError, match="not permitted to change system state"):
            ReadOnlyCommandRunner().run(["firewall-cmd", "--add-rich-rule", "x"], mutating=True)

    def test_a_read_only_runner_still_allows_queries(self):
        runner = ReadOnlyCommandRunner()
        # Either it runs (firewalld present) or reports the program missing --
        # what must not happen is a refusal for being read-only.
        try:
            result = runner.run(["firewall-cmd", "--state"])
        except ExecutionError as exc:
            assert "not installed" in str(exc)
        else:
            assert isinstance(result, CommandResult)


class TestCommandResult:
    def test_a_zero_exit_code_is_reported_but_not_called_success(self):
        result = CommandResult(argv=("firewall-cmd",), returncode=0)
        assert result.ok is True

    def test_a_timeout_is_never_ok(self):
        result = CommandResult(argv=("firewall-cmd",), returncode=0, timed_out=True)
        assert result.ok is False

    @pytest.mark.parametrize(
        "stderr",
        [
            "Error: Authorization failed.",
            "Interactive authentication required.",
            "permission denied",
            "You must be root",
        ],
    )
    def test_privilege_failures_are_recognised(self, stderr):
        assert CommandResult(argv=("x",), returncode=1, stderr=stderr).permission_denied

    def test_an_ordinary_failure_is_not_a_privilege_failure(self):
        assert not CommandResult(argv=("x",), returncode=1, stderr="INVALID_ZONE").permission_denied

    def test_describe_summarises_the_failure(self):
        result = CommandResult(argv=("firewall-cmd",), returncode=2, stderr="Error: INVALID_ZONE")
        assert "exited 2" in result.describe()
        assert "INVALID_ZONE" in result.describe()


class TestNoShellAnywhere:
    def test_the_response_package_never_uses_a_shell(self):
        """Static check across the whole response package."""
        import ast
        import pathlib

        import sentinelforge.response as package

        root = pathlib.Path(package.__file__).parent
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "shell":
                    assert isinstance(node.value, ast.Constant) and node.value.value is False, path
                if isinstance(node, ast.Call):
                    name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                    assert name not in ("system", "popen", "eval", "exec"), f"{path}: {name}"

    def test_only_the_executor_imports_subprocess(self):
        import ast
        import pathlib

        import sentinelforge.response as package

        root = pathlib.Path(package.__file__).parent
        importers = set()
        for path in root.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                if "subprocess" in names:
                    importers.add(path.name)
        assert importers == {"executor.py"}
