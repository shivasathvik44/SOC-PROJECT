"""Phase 9.2: optional dependencies must fail safely, never crash.

SentinelForge ships three dependency tiers:

* the core (stdlib only) - always available;
* Flask, for the dashboard (``pip install "sentinelforge[dashboard]"``);
* the ``openai`` SDK, for a hosted AI provider (``pip install
  "sentinelforge[llm]"``) - the offline mock provider needs neither.

A missing optional dependency must produce one clear, actionable line and a
non-zero exit code - never a raw traceback, and never a silent, wrong result.
This module simulates each dependency being absent by blocking its import at
the ``sys.meta_path`` level (real venvs test the same property by simply not
installing the package; this reaches the same code path deterministically,
without needing three separate venvs in CI).

Found by the Phase 9.2 fresh-install validation script
(``scripts/validate-deployment.sh``): before this module existed, running
``sentinelforge dashboard`` with Flask absent raised
``ModuleNotFoundError: No module named 'flask'`` all the way out of ``main()``.
"""

from __future__ import annotations

import contextlib
import io
import signal
import sys
from importlib.abc import MetaPathFinder

import pytest


class _BlockImport(MetaPathFinder):
    """Make ``import <name>`` (and any submodule of it) fail as if uninstalled."""

    def __init__(self, blocked_prefix: str) -> None:
        self.blocked_prefix = blocked_prefix

    def find_spec(self, name, path=None, target=None):
        if name == self.blocked_prefix or name.startswith(self.blocked_prefix + "."):
            raise ImportError(f"No module named {self.blocked_prefix!r}")
        return None


#: sentinelforge modules that import the named optional dependency at module
#: load time (a plain top-level ``from flask import ...``), rather than lazily
#: inside a function.  Blocking ``flask`` after one of these has already been
#: imported by an earlier test does nothing on its own: the module object is
#: cached in ``sys.modules`` with a real, working Flask already bound to it,
#: so a later ``from .dashboard.app import run_dashboard`` returns that cached
#: module and happily starts a REAL, unbounded Flask development server
#: instead of raising - which is exactly how this was found: it hung the
#: whole suite by doing precisely that. Evicting these too, alongside the
#: blocked dependency itself, forces the next import to genuinely re-run the
#: module's top-level ``import`` and hit the block.
_EAGER_IMPORTERS = {
    "flask": ("sentinelforge.dashboard",),
}


@contextlib.contextmanager
def _blocked(module_name: str):
    """Block a module for the duration of the ``with`` block, and undo it after.

    Evicts anything under ``module_name`` already cached in ``sys.modules``
    (a previous test's normal import of flask, say) and anything under
    :data:`_EAGER_IMPORTERS` for it, so the block actually bites regardless of
    what earlier tests in the same process already imported.
    """
    finder = _BlockImport(module_name)
    sys.meta_path.insert(0, finder)
    prefixes = (module_name,) + _EAGER_IMPORTERS.get(module_name, ())
    evicted = {
        name: mod
        for name, mod in list(sys.modules.items())
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)
    }
    for name in evicted:
        del sys.modules[name]
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        sys.modules.update(evicted)


class _StillRunning(AssertionError):
    """Raised when a bounded test outran its wall-clock budget."""


@contextlib.contextmanager
def _bounded(seconds: float, message: str):
    """Fail a test after ``seconds`` instead of letting it hang forever.

    A ``dashboard`` command that is supposed to fail fast has no business
    running longer than this; if it does, something (like the exact bug this
    module found once already - see ``_EAGER_IMPORTERS`` above) started a real
    server instead of raising. ``SIGALRM`` is POSIX-only, which matches this
    project's Linux-only scope.
    """

    def _raise(signum, frame):
        raise _StillRunning(message)

    previous = signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI's main() and capture (exit_code, stdout, stderr).

    ``--version`` and ``--help`` use argparse's own ``action="version"``/
    ``"help"``, which exit via ``SystemExit`` rather than returning - handled
    here the same way a real process invocation would see it.
    """
    from sentinelforge.cli import main

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 0
    return code, out.getvalue(), err.getvalue()


class TestDashboardWithoutFlask:
    """The dashboard command must fail cleanly when Flask is not installed."""

    def test_dashboard_command_fails_cleanly_not_with_a_traceback(self):
        with _bounded(10, "dashboard command did not fail fast - it may have started "
                          "a real server instead of raising ImportError"):
            with _blocked("flask"):
                code, _out, err = _run_cli(["dashboard"])
        assert code != 0
        assert "Traceback" not in err
        assert "ModuleNotFoundError" not in err

    def test_dashboard_command_names_the_extra_to_install(self):
        with _bounded(10, "dashboard command did not fail fast"):
            with _blocked("flask"):
                code, _out, err = _run_cli(["dashboard"])
        assert code != 0
        assert "sentinelforge[dashboard]" in err

    def test_demo_mode_also_fails_cleanly_without_flask(self):
        """--demo builds synthetic data (which needs no Flask) before serving it."""
        with _bounded(10, "dashboard --demo did not fail fast"):
            with _blocked("flask"):
                code, _out, err = _run_cli(["dashboard", "--demo"])
        assert code != 0
        assert "Traceback" not in err

    def test_every_non_dashboard_command_is_unaffected_by_a_missing_flask(self):
        with _blocked("flask"):
            for argv in (
                ["--version"],
                ["rules"],
                ["sources"],
                ["sensor", "list"],
                ["sensor", "check"],
                ["ai", "providers"],
                ["response", "capabilities"],
                ["simulate", "list"],
                ["simulate", "ssh-bruteforce"],
                ["simulate", "all"],
            ):
                code, _out, err = _run_cli(argv)
                assert "Traceback" not in err, f"{argv} raised: {err}"
                assert "flask" not in err.lower() or "extra" in err.lower(), (
                    f"{argv} unexpectedly mentions flask: {err}"
                )

    def test_importing_the_dashboard_package_itself_does_not_need_flask(self):
        """Phase 9.1's lazy-import fix: the package imports; only create_app needs Flask."""
        with _blocked("flask"):
            for name in list(sys.modules):
                if name == "sentinelforge.dashboard" or name.startswith(
                    "sentinelforge.dashboard."
                ):
                    del sys.modules[name]
            import sentinelforge.dashboard as dashboard  # noqa: F401

            with pytest.raises(ImportError):
                dashboard.create_app()


class TestAIWithoutOpenAISdk:
    """The offline mock provider must work with no [llm] extra installed."""

    def test_ai_providers_command_works_without_the_openai_sdk(self):
        with _blocked("openai"):
            code, out, err = _run_cli(["ai", "providers"])
        assert code == 0
        assert "Traceback" not in err
        assert "mock" in out

    def test_mock_provider_analysis_works_end_to_end_without_the_openai_sdk(self, tmp_path):
        db_path = str(tmp_path / "incidents.db")
        with _blocked("openai"):
            code, _out, err = _run_cli(
                ["simulate", "ssh-bruteforce", "--db", db_path]
            )
            assert code == 0, err
            code, out, err = _run_cli(["incidents", "--db", db_path])
        assert code == 0
        assert "Traceback" not in err
        assert "INC-000001" in out

    def test_requesting_the_openai_provider_explicitly_fails_cleanly_when_absent(
        self, monkeypatch, tmp_path
    ):
        db_path = str(tmp_path / "incidents.db")
        with _blocked("openai"):
            code, _out, _err = _run_cli(["simulate", "ssh-bruteforce", "--db", db_path])
            assert code == 0
            monkeypatch.delenv("OPENAI_API_KEY", raising=False)
            code, _out, err = _run_cli(
                ["ai", "analyze", "INC-000001", "--db", db_path, "--provider", "openai"]
            )
        assert code != 0
        assert "Traceback" not in err


class TestSimulationNeverNeedsAnOptionalDependency:
    """Phase 8's simulator is the primary evaluation path; it must always work."""

    def test_simulate_all_needs_neither_flask_nor_openai(self):
        with _blocked("flask"), _blocked("openai"):
            code, out, err = _run_cli(["simulate", "all"])
        assert code == 0, err
        assert "Traceback" not in err
        assert "scenarios passed" in out
