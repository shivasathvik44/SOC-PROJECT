# Changelog

All notable changes to SentinelForge are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/) with
[PEP 440](https://peps.python.org/pep-0440/) pre-release identifiers
(`1.0.0rc1` sorts before `1.0.0`).

This file starts detailed at Phase 9, where release engineering began. Phases
1-8 are summarized from the README's own phase-by-phase description rather
than reconstructed from commit history, since that history predates this file
and was not recorded per-phase; the README remains the source of truth for
what each phase actually does.

## [1.0.0rc1] - Phase 9: deployment and release preparation

A release candidate for v1.0.0. **No detection rule, correlation behavior, AI
prompt, response policy, or dashboard view changed in Phase 9.** Everything
here is packaging, installation, documentation, and one narrow bug fix found
by actually installing the package rather than by inspection.

### Fixed

- **Critical**: the dashboard's Jinja2 templates and static CSS/JS were
  missing from any built wheel or sdist (`setuptools` packages only `.py`
  files by default; no `package-data` config existed). Every dashboard route
  returned `500 TemplateNotFound` on a real, non-editable install -
  `pip install -e .` masked this because it imports straight from the source
  tree. Added `[tool.setuptools.package-data]` in `pyproject.toml`; verified
  by building a real wheel, installing it into a throwaway venv, and hitting
  every route.
- `sentinelforge dashboard` raised a raw `ModuleNotFoundError: No module named
  'flask'` traceback when the optional `dashboard` extra was not installed,
  instead of the one-line, actionable error every other optional-dependency
  path in the CLI already gives. Found by the Phase 9.2 fresh-install
  validation script, not by inspection. Fixed to name the missing extra and
  the install command, matching the existing `SensorUnavailableError` /
  `ProviderError` pattern elsewhere in `cli.py`.
- Two commands in the README (`sentinelforge detect ... -f ...` and
  `sentinelforge collect --hours 1`) used flags the CLI does not have (`-f`
  is `collect`-only; the time-window flag is `--since`, not `--hours`).
  Corrected. Every `sentinelforge ...` invocation in the README's fenced code
  blocks (108 unique command lines) is now checked to parse against the real
  `argparse` parser as part of this phase's validation.

### Added

- `LICENSE` (MIT). `pyproject.toml` declared `license = {text = "MIT"}` since
  Phase 1, but no LICENSE file existed until Phase 9.1.
- `scripts/validate-deployment.sh`: a maintainer script (not part of the
  installed package) that builds a distribution, installs it non-editably
  into a fresh venv, and checks CLI, dashboard, demo mode, optional-dependency
  degradation, privilege independence, and response approval-gating. Used to
  produce the Phase 9.2 validation evidence, and safe to re-run before any
  future release.
- `tests/test_optional_dependency_degradation.py`: regression coverage for
  the Flask-missing crash above, plus the equivalent property for a missing
  `openai` SDK, so this class of bug fails a normal `pytest` run in future.
- This file.

### Changed

- Version: `0.8.0` -> `1.0.0rc1`.
- `pyproject.toml` optional dependencies now carry upper bounds
  (`flask>=3.0,<4.0`, `openai>=1.0,<4.0`, `pytest>=7.0,<10.0`) instead of a
  bare floor. Each ceiling was chosen from a version actually installed and
  exercised during Phase 9.2 (Flask 3.1.3 against every dashboard route,
  pytest 9.1.1 against the whole suite, the real `openai` SDK 3.13.0
  constructed and its exact call shape proven accepted end to end), one major
  version above the highest one tested - not an arbitrary guess.
- `.gitignore`: the `reports/` exclusion previously only matched `*.json`
  inside it, which contradicted its own comment about committing evidence
  "only deliberately" - a routine `git add .` could have picked up a
  machine-specific `.md` report. Now the whole directory is ignored.
- README: added a full "Installation" section (supported platform,
  prerequisites, the install matrix for each extra, demo/simulation mode,
  dashboard startup, real sensor requirements, privileged operations, and
  security limitations to read before deploying) replacing the previous
  15-line version; added "What must be completed before v1.0" and updated
  "How SentinelForge was tested" and the phase table for Phase 9.

### Verified, not changed

Phase 9.2 confirmed the following by actually running them - inside a fresh,
unmodified Fedora 44 container as a non-root user, not merely inspecting the
source - rather than changing anything:

- the core pipeline (`collect`/`detect`/`correlate`/`simulate`/`benchmark`)
  needs no privilege and no optional dependency;
- the dashboard, `ai`, and `sensor` commands degrade to a clear message and a
  non-zero exit, never a traceback, when Flask, the `openai` SDK, or BCC are
  absent;
- `response` commands remain approval-gated: execution without an explicit
  `approve` step is refused in every Phase 8 scenario, checked again in this
  phase against a container with no `firewalld` and no `systemd-logind`
  installed at all.

### Phase 9.3: Linux service deployment

Makes SentinelForge deployable as a native systemd service. **No detection,
correlation, AI, simulation, or response logic changed.** Three privilege
tiers, not one process running as root: the dashboard and the periodic scan
run as a dedicated, unprivileged, no-login system account with zero
capabilities; the two optional eBPF sensor units run with `CAP_BPF` +
`CAP_PERFMON` only (the exact pair `sensors/ebpf/loader.py`'s own privilege
check accepts as an alternative to root); there is no unit for
`response execute` or `ai analyze` at all - both remain manual, human-invoked
actions, by design.

#### Added

- `packaging/systemd/`: four unit files
  (`sentinelforge-dashboard.service`, `sentinelforge-scan.service` +
  `.timer`, `sentinelforge-ebpf-process.service`,
  `sentinelforge-ebpf-network.service`), an environment file template with no
  real values, and a short README - none of it installed automatically, none
  of it shipped in the wheel (`setuptools` only packages `src/`).
- `scripts/install-systemd-service.sh`: an opt-in installer that creates the
  dedicated system account (locked, no login shell, no password), copies the
  requested unit files into `/etc/systemd/system`, and reloads systemd - and
  stops there. It never enables, starts, or touches firewalld/SELinux; it
  prompts for confirmation before changing anything (`--yes`/`--dry-run` for
  scripted use).
- `tests/test_systemd_units.py`: 67 tests, all static (no systemd or root
  required) plus one class that shells out to `systemd-analyze verify` only
  when that binary exists on the machine running pytest.

#### Fixed

Three real defects `systemd-analyze verify` found in the first draft of these
unit files, invisible to careful reading alone:

- `StartLimitIntervalSec=`/`StartLimitBurst=` belong in `[Unit]`, not
  `[Service]` - systemd accepts them silently in the wrong section and simply
  ignores them there.
- A multi-word `Environment=` value needs the *whole* `KEY=VALUE` assignment
  quoted (`Environment="KEY=a b c"`), not just the value
  (`Environment=KEY="a b c"` is a syntax error).
- systemd does not expand environment variables in the *executable* position
  of `ExecStart=`, only in the arguments that follow it - `ExecStart=${BIN}
  dashboard` fails with "Unable to locate executable '${BIN}'" even though
  the variable is set correctly. The binary path is now a literal, documented
  string in each unit file (the installer rewrites it automatically if
  `sentinelforge` is found somewhere other than the documented default).

All three are now regression-tested in `tests/test_systemd_units.py`.

#### Verified

Built and installed via the real installer inside a genuine systemd instance
(PID 1, not a shell) in a fresh Fedora 44 container: the dashboard served
HTTP 200 as the unprivileged account, `StateDirectory=`/`CacheDirectory=`/
`LogsDirectory=` were auto-created with correct ownership, the scan timer
fired on its own and ran the pipeline, `systemctl enable`/`start`/`stop`/
`restart`/`status`, `journalctl -u`, and a full disable-and-remove uninstall
all worked as documented, and no unit was left enabled unless explicitly
told to be. **Not verified**: the two eBPF units against a real, privileged
kernel - this project's validation sandbox has no privileged eBPF-capable
host, the same limitation noted throughout Phase 9.

### Phase 9.4: real eBPF validation and a test-harness fix

**No detection, correlation, AI, simulation, response, or eBPF sensor
*behavior* changed.** This phase closed the one gap Phase 9.3 explicitly
could not (a privileged eBPF-capable host was not available to that sandbox),
and fixed a latent test-import inconsistency found while reproducing the
suite's own documented pass count.

#### Fixed

- `sensors/ebpf/process.py`: real execution on a privileged Fedora 44 host
  showed BCC's dynamic `.event()` decoding cannot handle a
  `char argv[MAX_ARGS][ARGSIZE]` field. Replaced with a fixed-layout
  `ExecEvent` ctypes structure and `decode_exec_record()`, decoded against a
  known struct size instead of BCC's runtime type introspection. `--no-args`
  continues to compile argument capture out of the BPF program entirely
  rather than merely redact it afterward.
- `sensors/ebpf/network.py`: added the missing `#include <linux/sched.h>`
  the `sock:inet_sock_set_state` tracepoint program needs to compile.
- `tests/test_correlation_accuracy.py` and `tests/test_response_security.py`
  imported a test helper module with an absolute `from tests.conftest
  import ...` / `from tests.test_response_backends import ...`. That import
  only resolves under `python -m pytest`, whose `-m` flag incidentally
  prepends the repository root to `sys.path`; the `pytest` console-script
  entry point does not do this, so a plain `pytest` invocation failed both
  files with `ModuleNotFoundError: No module named 'tests'`. Changed both to
  the plain `from conftest import ...` / `from test_response_backends import
  ...` form every other test module already uses (`tests/` itself, not the
  repository root, is what pytest puts on `sys.path` for a directory with no
  `__init__.py`). No test was removed or weakened; `pytest` and
  `python -m pytest` now collect and pass the identical 1,936 tests.

#### Verified

- **Real process eBPF telemetry**, on a real Fedora 44 host (kernel
  `7.1.13-200.fc44.x86_64`, BCC 0.35.0, BTF and `bpffs` present, `CAP_BPF` +
  `CAP_PERFMON` granted): `sentinelforge sensor start ebpf-process` compiled,
  attached, and produced real process-execution events. The
  `sentinelforge-ebpf-process.service` unit installs correctly and stays
  disabled/inactive by default, exactly as designed.
- **Real network eBPF telemetry**, same host: `sentinelforge sensor start
  ebpf-network` produced real IPv4 and IPv6 outbound-connection events. This
  run is also what confirmed `/sys/kernel/tracing` is `0700 root:root` on
  Fedora 44 with no `gid=` mount option, so `CAP_BPF`/`CAP_PERFMON` cannot
  substitute for root there; the network sensor deliberately remains a
  manual, root-invoked command rather than a systemd unit in v1 (see the
  README's "Why network eBPF is manual, not a service").
- **A real telemetry-to-dashboard chain, observed live, not constructed**:
  on that same host, the installed `sentinelforge-scan.timer` runs
  `collect | detect | correlate` against the real system journal on its own
  schedule, and the running `sentinelforge-dashboard` serves what it writes;
  `/api/incidents` returned a real, previously-created incident
  (`INC-000001`, rule `SUSPICIOUS_SUDO`) built from real journal telemetry.
  Collection and detection were re-run directly in this phase against a
  real two-day journal window (22,348 events, 0 skipped, 0 new alerts -
  correctly, since no rule-matching activity occurred in that window).
  **Not performed**: manufacturing a new alert for this report - `sshd` is
  not running on this host, and starting it, or otherwise staging an attack
  outside its own architecture, was out of scope.
- Full suite re-run after the fixes above: `1,936 passed` via both `pytest`
  and `python -m pytest`, from the repository root and from an unrelated
  working directory.

### Phase 9.5: GitHub clone-and-run installer

**No detection, correlation, AI, response, dashboard, or eBPF sensor behavior
changed.** Closes the remaining gap for a GitHub user with no prior context on
this project: there was no single, obvious "clone it and install it" command,
and two documentation examples hardcoded a maintainer's own
`/opt/sentinelforge/venv-ebpf` path where a generic one belonged.

#### Added

- `install.sh`: a repository-root installer for `git clone -> ./install.sh`.
  Checks the platform is Linux and Python is 3.9+, creates (or reuses)
  `.venv/`, installs SentinelForge plus the `dashboard` extra into it by
  default, and prints the exact next commands. Options: `--extras`
  (`dashboard`/`llm`/`dev`/`none`), `--editable`, `--link [DIR]` (opt-in
  symlink into `~/.local/bin`), `--systemd-units LIST` (opt-in hand-off to
  `scripts/install-systemd-service.sh`), `--python`, `--recreate`,
  `--dry-run`. Touches nothing outside the checkout (and `~/.local/bin` only
  with `--link`), never modifies a shell profile, and never requests root
  unless `--systemd-units` is passed - which itself hands off to the
  already-reviewed installer that prompts before changing anything.
- README: a "Quick start" section right after the phase summary, showing the
  complete `git clone` -> `./install.sh` -> first-commands path with no prior
  context assumed; the "Installing" section now leads with `./install.sh`
  and keeps the manual `pip install -e .` steps as the documented
  alternative for anyone who wants more control.

#### Fixed

- Two documentation examples (the README's "Why network eBPF is manual, not
  a service" and `packaging/systemd/README.md`'s equivalent section)
  hardcoded `/opt/sentinelforge/venv-ebpf/bin/sentinelforge` - a path from
  the maintainer's own validation host, not something a GitHub clone
  reproduces. Replaced with `"$(pwd)/.venv/bin/sentinelforge"`, with a note
  explaining *why* an absolute path is needed here at all (`sudo` resets
  `$PATH` by default, so it will not see an activated venv).

#### Verified

- `./install.sh` run against a clean copy of this checkout (all git-ignored
  build state and `.venv/` removed, standing in for a fresh `git clone`):
  default install, `--dry-run`, re-run for idempotency, `--link`, and
  `--extras none --editable` all completed correctly, including the
  optional-dependency degradation message when Flask is absent.
- Post-install CLI smoke test from the installed (non-editable) command:
  `--version`, `--help`, `sources`, `rules`, `sensor list`, `sensor check`,
  `simulate list`, and `simulate all --report` (15/15 scenarios, 528/528
  checks passed).
- `sentinelforge dashboard --demo` from the installed command served `/`,
  `/static/css/sentinelforge.css`, and `/static/js/app.js` at `200`.
- Installing directly from the built wheel (`pip install
  'sentinelforge-1.0.0rc1-py3-none-any.whl[dashboard]'`, no editable
  checkout involved) produced a working `sentinelforge` command with the
  dashboard templates and static assets present, confirming the packaging
  fix from Phase 9.1 still holds.
- Full suite: `1,936 passed`, unchanged. `python -m build` still produces a
  wheel and sdist; `git diff --check` is clean.

## Phases 1-8 (summary)

Detailed in the README rather than here; version numbers below were assigned
retroactively and were not tagged releases at the time.

- **Phase 1 - Collection.** Linux security logs (journald, `/var/log/secure`,
  `/var/log/auth.log`) normalized into one `SecurityEvent` JSON shape.
- **Phase 2 - Detection.** Deterministic rules over normalized events, ATT&CK
  mapping, explainable risk scoring.
- **Phase 3 - Correlation.** Related alerts grouped into incidents with attack
  chains, timelines, and persistence in SQLite.
- **Phase 4 - eBPF telemetry.** Process execution and outbound network
  connections traced in the kernel via BCC, feeding the same pipeline.
- **Phase 5 - AI SOC analyst.** An incident reader (never a detector) that
  produces a Tier-1 summary; offline mock provider by default, an
  OpenAI-compatible provider optionally.
- **Phase 6 - Local SOC dashboard.** A loopback-only, read-only Flask console
  over the incident store, with a live event stream.
- **Phase 7 - Response and containment.** Human-approved, policy-gated,
  verified, and audited firewall/process/session containment - the only part
  of SentinelForge that can change the host, and only after an explicit
  approval step.
- **Phase 8 - Attack simulator and purple-team validation.** Safe synthetic
  attack scenarios run through the real pipeline end to end, with
  expected-vs-observed checks, false-positive/negative testing, benchmarking,
  and generated validation reports (`sentinelforge simulate`,
  `sentinelforge benchmark`).

Version `0.8.0` corresponds to the end of Phase 8.
