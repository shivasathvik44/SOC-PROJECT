"""Phase 9.3: systemd unit file correctness.

Every check here is static - parsing and pattern-matching the shipped unit
files as text - so the whole module runs with no systemd, no root, and no
container, exactly as Phase 9.3 requires of the automated suite. The one
exception is class:`TestRealSystemdVerification`, which shells out to
``systemd-analyze verify`` *only when that binary exists on the machine
running pytest* and is skipped otherwise - never a hard requirement.

These files were found to have three real defects during Phase 9.3's own
manual verification in a genuine systemd container (not caught by writing
them carefully, only by running ``systemd-analyze verify`` for real):
``StartLimitIntervalSec``/``StartLimitBurst`` belong in ``[Unit]``, not
``[Service]``; a multi-word ``Environment=`` value needs the whole
``KEY=VALUE`` assignment quoted, not just the value; and systemd does not
expand environment variables in the *executable* position of ``ExecStart=``
(only in the arguments that follow it), so the sentinelforge binary path must
be a literal, fixed string there. This module exists so none of the three can
silently come back.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import pathlib

import pytest

PACKAGING_DIR = pathlib.Path(__file__).resolve().parent.parent / "packaging" / "systemd"
INSTALL_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "install-systemd-service.sh"

SERVICE_FILES = sorted(PACKAGING_DIR.glob("*.service"))
TIMER_FILES = sorted(PACKAGING_DIR.glob("*.timer"))
ALL_UNIT_FILES = SERVICE_FILES + TIMER_FILES

#: [Service]-section directives that are actually [Unit]-section directives.
#: Systemd accepts them silently (with a warning) in the wrong section and
#: simply ignores them there, which is worse than an error - the setting
#: quietly does nothing. This is exactly the first bug Phase 9.3 found.
UNIT_SECTION_ONLY_IN_SERVICE = ("StartLimitIntervalSec", "StartLimitBurst")

#: Real capability names a service unit might legitimately request. Used to
#: sanity-check AmbientCapabilities=/CapabilityBoundingSet= values rather than
#: assert they are empty everywhere (the eBPF units need CAP_BPF/CAP_PERFMON).
KNOWN_CAPABILITIES = {"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN", "CAP_NET_ADMIN"}

#: Networks/hosts/paths that must never appear in a shipped unit or example
#: file - anything here would be this developer's own machine leaking into a
#: file every SentinelForge deployer receives verbatim.
FORBIDDEN_SUBSTRINGS = (
    "capslock",
    "/home/",
    "192.168.",
    "10.0.2.",
    "posanishiva6",
    "shivasathvik44",
)


def _sections(text: str) -> dict[str, list[str]]:
    """Split a unit file into {section_name: [lines]}, comments/blanks kept out.

    Handles the backslash line-continuation systemd unit files use for long
    ExecStart= commands by joining continued lines back into one logical line
    before splitting into section buckets.
    """
    logical_lines: list[str] = []
    buffer = ""
    for raw_line in text.splitlines():
        stripped = raw_line.rstrip("\n")
        if buffer:
            buffer += "\n" + stripped
        else:
            buffer = stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1]
            continue
        logical_lines.append(buffer)
        buffer = ""
    if buffer:
        logical_lines.append(buffer)

    sections: dict[str, list[str]] = {}
    current = None
    for line in logical_lines:
        content = line.strip()
        if not content or content.startswith("#") or content.startswith(";"):
            continue
        match = re.match(r"^\[([A-Za-z]+)\]$", content)
        if match:
            current = match.group(1)
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(content)
    return sections


def _directive_values(lines: list[str], key: str) -> list[str]:
    """Every value assigned to ``key=`` in these lines, in order."""
    values = []
    for line in lines:
        if "=" not in line:
            continue
        found_key, _, value = line.partition("=")
        if found_key.strip() == key:
            values.append(value.strip())
    return values


class TestEveryUnitFileParses:
    """Baseline sanity: every shipped unit file is well-formed INI-like text."""

    @pytest.mark.parametrize("path", ALL_UNIT_FILES, ids=lambda p: p.name)
    def test_the_file_has_at_least_one_recognized_section(self, path):
        sections = _sections(path.read_text())
        assert sections, f"{path.name} has no [Section] headers at all"

    @pytest.mark.parametrize("path", ALL_UNIT_FILES, ids=lambda p: p.name)
    def test_every_directive_line_has_an_equals_sign(self, path):
        for section, lines in _sections(path.read_text()).items():
            for line in lines:
                assert "=" in line, f"{path.name} [{section}]: {line!r} is not KEY=VALUE"

    @pytest.mark.parametrize("path", ALL_UNIT_FILES, ids=lambda p: p.name)
    def test_quotes_are_balanced(self, path):
        text = path.read_text()
        assert text.count('"') % 2 == 0, f"{path.name} has an unbalanced double quote"
        assert text.count("'") % 2 == 0, f"{path.name} has an unbalanced single quote"


class TestStartLimitPlacement:
    """Regression test for the first bug Phase 9.3 found: wrong section."""

    @pytest.mark.parametrize("path", SERVICE_FILES, ids=lambda p: p.name)
    def test_start_limit_directives_are_not_in_the_service_section(self, path):
        sections = _sections(path.read_text())
        service_lines = sections.get("Service", [])
        for directive in UNIT_SECTION_ONLY_IN_SERVICE:
            assert not _directive_values(service_lines, directive), (
                f"{path.name}: {directive}= belongs in [Unit], not [Service] - "
                "systemd silently ignores it here"
            )

    @pytest.mark.parametrize(
        "path",
        [p for p in SERVICE_FILES if "Restart=" in p.read_text()],
        ids=lambda p: p.name,
    )
    def test_a_restarting_service_declares_a_start_limit_somewhere(self, path):
        """A service that restarts on failure needs a bound on how often."""
        sections = _sections(path.read_text())
        unit_lines = sections.get("Unit", [])
        assert _directive_values(unit_lines, "StartLimitIntervalSec"), (
            f"{path.name} restarts on failure but sets no StartLimitIntervalSec= "
            "in [Unit] - a persistent misconfiguration could restart forever"
        )
        assert _directive_values(unit_lines, "StartLimitBurst")


class TestEnvironmentAssignmentSyntax:
    """Regression test for the second bug: unquoted multi-word values."""

    @pytest.mark.parametrize("path", SERVICE_FILES, ids=lambda p: p.name)
    def test_multi_word_environment_values_quote_the_whole_assignment(self, path):
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if not stripped.startswith("Environment="):
                continue
            assignment = stripped[len("Environment="):]
            if assignment.startswith('"') or assignment.startswith("'"):
                continue  # already quotes the whole KEY=VALUE - correct form
            _, _, value = assignment.partition("=")
            assert " " not in value, (
                f"{path.name}: {stripped!r} has an unquoted multi-word value - "
                'systemd requires Environment="KEY=the whole value", not '
                "Environment=KEY=the whole value"
            )


class TestExecStartExecutablePosition:
    """Regression test for the third bug: systemd does not expand ${VARS} in
    the executable position of ExecStart=, only in later arguments."""

    @pytest.mark.parametrize("path", SERVICE_FILES, ids=lambda p: p.name)
    def test_the_executable_position_is_a_literal_path_not_a_variable(self, path):
        sections = _sections(path.read_text())
        for line in sections.get("Service", []):
            if not line.startswith("ExecStart="):
                continue
            command = line[len("ExecStart="):].strip()
            # A bare '/bin/bash -c ...' wrapper is the one documented, safe
            # exception (sentinelforge-scan.service): the *shell* is the
            # literal executable, and the sentinelforge paths inside its -c
            # string are checked separately below.
            executable = command.split()[0] if command else ""
            assert not executable.startswith("$"), (
                f"{path.name}: ExecStart='s executable ({executable!r}) is an "
                "environment variable - systemd does not expand variables "
                "there, only in the arguments after it, so this would fail "
                "with 'Unable to locate executable' at runtime"
            )
            assert executable.startswith("/"), (
                f"{path.name}: ExecStart='s executable ({executable!r}) is not "
                "an absolute path"
            )

    @pytest.mark.parametrize("path", SERVICE_FILES, ids=lambda p: p.name)
    def test_every_invocation_of_sentinelforge_itself_is_an_absolute_path(self, path):
        """Whether called directly or piped together inside a bash -c string
        (sentinelforge-scan.service does both) - every place the lowercase
        command name 'sentinelforge' appears as a word inside an ExecStart=
        line must be immediately preceded by its known absolute path, never
        called bare (which would depend on $PATH, unset for services)."""
        # Only real command invocations, i.e. 'sentinelforge <subcommand>' -
        # not every mention of the word (it also names paths like
        # /var/lib/sentinelforge/incidents.db and SyslogIdentifier=).
        subcommands = "|".join(
            ("collect", "sources", "detect", "rules", "correlate", "incident",
             "incidents", "sensor", "ai", "dashboard", "response", "simulate",
             "benchmark")
        )
        invocation = re.compile(rf"\bsentinelforge\s+(?:{subcommands})\b")

        sections = _sections(path.read_text())
        for line in sections.get("Service", []):
            if not line.startswith("ExecStart="):
                continue
            for match in invocation.finditer(line):
                prefix = line[:match.start()]
                assert prefix.endswith("/usr/local/bin/"), (
                    f"{path.name}: {line[max(0, match.start()-20):match.start()+20]!r} "
                    "calls 'sentinelforge' without its absolute path - this "
                    "would depend on $PATH, which systemd services do not "
                    "reliably inherit"
                )


class TestPrivilegeSeparation:
    """The dashboard and scan units must not run as root; the eBPF units'
    privilege must be exactly CAP_BPF + CAP_PERFMON, never broader by default."""

    @pytest.mark.parametrize(
        "path",
        [p for p in SERVICE_FILES if "ebpf" not in p.name],
        ids=lambda p: p.name,
    )
    def test_the_dashboard_and_scan_units_do_not_run_as_root(self, path):
        sections = _sections(path.read_text())
        users = _directive_values(sections.get("Service", []), "User")
        assert users, f"{path.name} does not set User= at all"
        assert users == ["sentinelforge"], (
            f"{path.name} sets User={users}, expected the dedicated "
            "'sentinelforge' account, not root"
        )

    @pytest.mark.parametrize(
        "path",
        [p for p in SERVICE_FILES if "ebpf" not in p.name],
        ids=lambda p: p.name,
    )
    def test_the_dashboard_and_scan_units_grant_no_capabilities(self, path):
        sections = _sections(path.read_text())
        bounding = _directive_values(sections.get("Service", []), "CapabilityBoundingSet")
        ambient = _directive_values(sections.get("Service", []), "AmbientCapabilities")
        # Empty CapabilityBoundingSet=/AmbientCapabilities= lines are how
        # systemd spells "grant nothing" - the directive must be present and
        # blank, not merely absent (absent inherits the compiled-in default,
        # which is broader).
        assert bounding == [""], (
            f"{path.name}: CapabilityBoundingSet= must be present and empty"
        )
        assert ambient == [""], (
            f"{path.name}: AmbientCapabilities= must be present and empty"
        )

    @pytest.mark.parametrize(
        "path",
        [p for p in SERVICE_FILES if "ebpf" in p.name],
        ids=lambda p: p.name,
    )
    def test_ebpf_units_request_exactly_cap_bpf_and_cap_perfmon_by_default(self, path):
        """The narrowest privilege the code's own check accepts - not root."""
        text = path.read_text()
        active_ambient = [
            line for line in text.splitlines()
            if line.strip().startswith("AmbientCapabilities=") and not line.strip().startswith("#")
        ]
        assert len(active_ambient) == 1, (
            f"{path.name}: expected exactly one active (uncommented) "
            f"AmbientCapabilities= line, found {len(active_ambient)}"
        )
        granted = set(active_ambient[0].split("=", 1)[1].split())
        assert granted == {"CAP_BPF", "CAP_PERFMON"}, (
            f"{path.name} grants {granted or 'nothing'} by default; the "
            "code's own has_bpf_privileges() check "
            "(sensors/ebpf/loader.py) accepts CAP_BPF + CAP_PERFMON as an "
            "alternative to root - granting anything broader by default "
            "(root included) is not the minimal privilege the code supports"
        )
        assert granted <= KNOWN_CAPABILITIES

    @pytest.mark.parametrize("path", [p for p in SERVICE_FILES if "ebpf" in p.name], ids=lambda p: p.name)
    def test_the_root_fallback_is_present_but_commented_out(self, path):
        """Older-kernel fallback must exist, and must not be the default."""
        text = path.read_text()
        assert "#User=root" in text.replace(" ", ""), (
            f"{path.name} should document a commented-out root fallback for "
            "older kernels without CAP_BPF/CAP_PERFMON support"
        )
        active_user_lines = [
            line for line in text.splitlines()
            if re.match(r"^\s*User=", line) and not line.strip().startswith("#")
        ]
        assert active_user_lines == ["User=sentinelforge"], (
            f"{path.name}: the active (uncommented) User= must be the "
            "unprivileged account by default, with root only as a "
            "commented-out fallback"
        )


class TestNoResponseOrAiUnit:
    """The security requirement stated directly in the Phase 9.3 prompt:
    response actions must never gain an automatic, unattended trigger."""

    def test_no_shipped_unit_invokes_the_response_command(self):
        """The word 'response' is fine in prose (this class's own docstring
        uses it); an actual ``sentinelforge response ...`` invocation is not."""
        pattern = re.compile(r"sentinelforge(?:-[a-z]+)?\s+response\b")
        for path in ALL_UNIT_FILES:
            assert not pattern.search(path.read_text()), (
                f"{path.name} invokes the response command - response actions "
                "must remain a manual, human-invoked action, never something "
                "a systemd unit runs automatically"
            )

    def test_no_shipped_unit_invokes_ai_analysis(self):
        pattern = re.compile(r"sentinelforge\s+ai\s+analyze\b")
        for path in ALL_UNIT_FILES:
            assert not pattern.search(path.read_text()), (
                f"{path.name} invokes AI analysis - this should remain a "
                "manual, on-demand, cost-aware action"
            )


class TestNoSecretsOrPersonalData:
    """Task 12: no API keys, passwords, personal paths or dev identities."""

    ALL_SHIPPED_FILES = ALL_UNIT_FILES + [
        PACKAGING_DIR / "sentinelforge.env.example",
        PACKAGING_DIR / "README.md",
        INSTALL_SCRIPT,
    ]

    @pytest.mark.parametrize("path", ALL_SHIPPED_FILES, ids=lambda p: p.name)
    def test_no_forbidden_substring_appears(self, path):
        text = path.read_text().lower()
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden.lower() not in text, (
                f"{path.name} contains {forbidden!r}, which looks like "
                "developer-machine-specific data that must not ship"
            )

    def test_the_example_env_file_sets_no_real_values(self):
        """Every line that could carry a secret must be commented out."""
        text = (PACKAGING_DIR / "sentinelforge.env.example").read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            pytest.fail(
                f"sentinelforge.env.example has an active (uncommented) "
                f"assignment: {stripped!r} - every example value must be "
                "commented out so nothing is set by copying this file as-is"
            )

    def test_no_shipped_file_contains_an_actual_looking_api_key(self):
        # A real OpenAI-style key, a generic 32+ char hex/base64 secret, or a
        # private-key PEM header - not the word "key" in prose, which is fine.
        patterns = (
            re.compile(r"sk-[A-Za-z0-9]{16,}"),
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        )
        for path in self.ALL_SHIPPED_FILES:
            text = path.read_text()
            for pattern in patterns:
                assert not pattern.search(text), f"{path.name} matches {pattern.pattern}"


class TestInstallScriptSafety:
    """Task 8's constraints on the install helper, checked statically."""

    def test_the_script_never_uses_a_bare_eval(self):
        text = INSTALL_SCRIPT.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert not re.match(r"^\s*eval\b", stripped), (
                f"install script uses eval: {stripped!r}"
            )

    def test_the_script_requires_confirmation_before_writing_anything(self):
        text = INSTALL_SCRIPT.read_text()
        assert "read -r -p" in text, "no interactive confirmation prompt found"
        assert "--yes" in text, "no way to see a documented opt-out for scripted use"
        # The prompt must appear (in the file's source order) before the
        # first line that actually installs a system file.
        prompt_pos = text.index("read -r -p")
        apply_pos = text.index('echo\necho "--- applying ---"')
        assert prompt_pos < apply_pos, (
            "the confirmation prompt must come before the 'applying' section"
        )

    def test_the_script_never_enables_or_starts_a_unit_itself(self):
        text = INSTALL_SCRIPT.read_text()
        # Split off the final "Next steps" text the script only *prints* -
        # everything the script actually *executes* is above that marker.
        executable_part = text.split('echo "Nothing was enabled or started.')[0]
        assert "systemctl enable" not in executable_part
        assert "systemctl start" not in executable_part
        assert "systemctl daemon-reload" in text, "should still reload systemd's unit cache"

    def test_the_script_never_touches_selinux_or_the_firewall(self):
        text = INSTALL_SCRIPT.read_text().lower()
        for forbidden in ("setenforce", "semanage", "firewall-cmd", "iptables", "nft "):
            assert forbidden not in text, f"install script references {forbidden!r}"

    def test_the_script_creates_a_locked_no_login_account(self):
        text = INSTALL_SCRIPT.read_text()
        assert "--shell /usr/sbin/nologin" in text
        assert "passwd -l" in text, "the account should be explicitly password-locked"
        # useradd's own '-p ENCRYPTED_PASSWORD' flag, not bash's unrelated
        # `read -p "prompt text"` (a prompt string, never a password value) -
        # isolate just the useradd invocation before checking for '-p'.
        useradd_call = re.search(r"useradd\b[^\n]*(?:\n\s+[^\n]*)*", text)
        assert useradd_call, "could not find the useradd invocation to check"
        assert not re.search(r"(?<!\w)-p\b", useradd_call.group(0)), (
            "useradd should never be passed an explicit -p password hash"
        )

    def test_the_script_contains_no_hardcoded_password(self):
        text = INSTALL_SCRIPT.read_text().lower()
        for forbidden in ("password=", "passwd=", "secret="):
            assert forbidden not in text


class TestDocumentationConsistency:
    """The unit files and the README must agree with each other."""

    def test_every_service_and_timer_file_is_mentioned_in_the_packaging_readme(self):
        readme = (PACKAGING_DIR / "README.md").read_text()
        for path in ALL_UNIT_FILES:
            assert path.name in readme, f"{path.name} is not mentioned in packaging/systemd/README.md"

    def test_the_main_readme_documents_the_systemd_service(self):
        main_readme = (
            pathlib.Path(__file__).resolve().parent.parent / "README.md"
        ).read_text()
        assert "sentinelforge-dashboard.service" in main_readme
        assert "install-systemd-service.sh" in main_readme
        for verb in ("Starting", "Stopping", "status", "logs", "Uninstalling"):
            assert verb.lower() in main_readme.lower()


class TestRealSystemdVerification:
    """Only runs if this machine actually has systemd-analyze - never a hard
    requirement for the suite (task 11), but a real check when available."""

    requires_systemd_analyze = pytest.mark.skipif(
        shutil.which("systemd-analyze") is None,
        reason="systemd-analyze is not installed on this machine",
    )

    @requires_systemd_analyze
    @pytest.mark.parametrize("path", ALL_UNIT_FILES, ids=lambda p: p.name)
    def test_systemd_analyze_verify_accepts_the_unit(self, path, tmp_path):
        """Copy the unit alongside its siblings so cross-references resolve,
        then ask systemd itself whether the file is well-formed. This never
        loads, starts, or enables anything - `verify` only parses."""
        work_dir = tmp_path / "units"
        work_dir.mkdir()
        for unit_file in ALL_UNIT_FILES:
            (work_dir / unit_file.name).write_text(unit_file.read_text())

        result = subprocess.run(
            ["systemd-analyze", "verify", "--recursive-errors=no", str(work_dir / path.name)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # 'Unknown key'/'Invalid environment assignment' are the exact two
        # warning classes Phase 9.3 found and fixed; a clean pass has none.
        combined = result.stdout + result.stderr
        assert "Unknown key" not in combined, combined
        assert "Invalid environment assignment" not in combined, combined
