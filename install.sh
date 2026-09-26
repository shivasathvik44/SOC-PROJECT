#!/usr/bin/env bash
# SentinelForge local installer.
#
# This is the "git clone -> ./install.sh -> run it" path for a user who has
# never seen this project: it creates an isolated virtual environment in
# this checkout and installs SentinelForge and (by default) its dashboard
# extra into it, then prints the exact commands to run next. It does not
# install SentinelForge system-wide, does not touch anything outside this
# checkout and $HOME/.local/bin (and only the latter if you pass --link),
# and never requests root unless you explicitly ask it to install the
# optional systemd units (--systemd-units below), in which case it hands off
# to scripts/install-systemd-service.sh - which itself prompts before
# changing anything and only ever asks for root, never SELinux/firewalld/
# sudoers/kernel state.
#
# What this script does, in order:
#   1. Check the platform is Linux and Python is new enough (>=3.9).
#   2. Create a virtual environment at --venv (default: .venv), reusing one
#      that already exists - safe to re-run.
#   3. `pip install` SentinelForge (and, by default, the 'dashboard' extra)
#      into it from this checkout.
#   4. Print the installed CLI's location and, optionally (--link), place a
#      symlink to it in ~/.local/bin so 'sentinelforge' works without
#      activating the venv - only if you ask for it.
#   5. Optionally (--systemd-units LIST) hand off to
#      scripts/install-systemd-service.sh for the systemd deployment path.
#
# It deliberately does NOT:
#   - modify SELinux policy, firewalld policy, sudoers, or kernel settings;
#   - install or configure eBPF prerequisites (BCC is a distro package, not
#     pip-installable - see the README's "Fedora eBPF Setup" section);
#   - enable or start any systemd unit;
#   - modify your shell profile (.bashrc/.zshrc/...) - --link only creates
#     one symlink, in the directory you name, nothing else;
#   - use shell=True-equivalent constructs anywhere.
#
# Usage:
#   ./install.sh [options]
#
#   --venv DIR          virtual environment location (default: .venv)
#   --extras LIST        comma-separated extras to install: dashboard, llm,
#                        dev, or 'none' (default: dashboard)
#   --editable           install with 'pip install -e' instead of a regular
#                        install (useful if you intend to edit the source and
#                        have 'git pull' take effect without reinstalling)
#   --link [DIR]         symlink the installed 'sentinelforge' command into
#                        DIR (default: ~/.local/bin) so it works without
#                        activating the venv - only done if you pass this
#   --systemd-units LIST  after installing, also run
#                        scripts/install-systemd-service.sh --units LIST via
#                        sudo (prompts for confirmation itself; see that
#                        script's own header comment)
#   --python PATH        python interpreter to use (default: first of
#                        python3.12, python3.11, python3.10, python3.9, python3)
#   --recreate           delete and recreate the venv instead of reusing it
#   --dry-run            print the plan and exit without changing anything
#   -h, --help           show this help and exit
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_ROOT/.venv"
EXTRAS="dashboard"
EDITABLE=0
LINK=0
LINK_DIR="$HOME/.local/bin"
SYSTEMD_UNITS=""
PYTHON_BIN=""
RECREATE=0
DRY_RUN=0

usage() {
    grep '^#' "${BASH_SOURCE[0]}" | sed -n '/^# Usage:/,/-h, --help/p' | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --venv) VENV_DIR="$2"; shift 2 ;;
        --extras) EXTRAS="$2"; shift 2 ;;
        --editable) EDITABLE=1; shift ;;
        --link)
            LINK=1
            if [ $# -ge 2 ] && [[ "$2" != --* ]]; then LINK_DIR="$2"; shift 2; else shift; fi
            ;;
        --systemd-units) SYSTEMD_UNITS="$2"; shift 2 ;;
        --python) PYTHON_BIN="$2"; shift 2 ;;
        --recreate) RECREATE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

echo "SentinelForge installer"
echo "========================"
echo

# ---------------------------------------------------------------------------
# 1. Platform and Python checks.
# ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Linux" ]; then
    echo "ERROR: SentinelForge is a Linux-native tool (journald/eBPF/firewalld" >&2
    echo "integration). '$(uname -s)' is not supported. Windows support is a" >&2
    echo "separate, later effort - see the README." >&2
    exit 1
fi
echo "PASS  platform is Linux ($(uname -r))"

if [ -z "$PYTHON_BIN" ]; then
    for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PYTHON_BIN="$candidate"
            break
        fi
    done
fi
if [ -z "$PYTHON_BIN" ] || ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: no python3 interpreter found on \$PATH." >&2
    echo "Install one first, e.g.:" >&2
    echo "  sudo dnf install -y python3 python3-pip           # Fedora/RHEL" >&2
    echo "  sudo apt install -y python3 python3-venv python3-pip  # Debian/Ubuntu" >&2
    exit 1
fi

if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "ERROR: $PYTHON_BIN is $("$PYTHON_BIN" -V 2>&1), but SentinelForge needs" >&2
    echo "Python 3.9 or newer. Install a newer python3 and re-run with --python." >&2
    exit 1
fi
echo "PASS  $PYTHON_BIN is $("$PYTHON_BIN" -V 2>&1)"

if ! "$PYTHON_BIN" -c 'import venv' 2>/dev/null; then
    echo "ERROR: the 'venv' module is not available for $PYTHON_BIN." >&2
    echo "On Debian/Ubuntu this is a separate package:" >&2
    echo "  sudo apt install -y python3-venv" >&2
    exit 1
fi
echo "PASS  the 'venv' module is available"

case ",$EXTRAS," in
    ,none,) PIP_TARGET="." ;;
    *) PIP_TARGET=".[$EXTRAS]" ;;
esac

echo
echo "Plan:"
echo "  1. $( [ -d "$VENV_DIR" ] && [ "$RECREATE" -eq 0 ] && echo "Reuse" || echo "Create" ) a virtual environment at: $VENV_DIR"
echo "  2. Install SentinelForge into it: pip install $( [ "$EDITABLE" -eq 1 ] && echo "-e " )'$PIP_TARGET' (from $REPO_ROOT)"
if [ "$LINK" -eq 1 ]; then
    echo "  3. Symlink $VENV_DIR/bin/sentinelforge -> $LINK_DIR/sentinelforge"
fi
if [ -n "$SYSTEMD_UNITS" ]; then
    echo "  4. Hand off to 'sudo scripts/install-systemd-service.sh --units $SYSTEMD_UNITS'"
    echo "     (that script prompts for its own confirmation and never enables/starts a unit)"
fi
echo
echo "This script will NOT touch SELinux, firewalld, sudoers, kernel settings,"
echo "or your shell profile, and will not request root unless --systemd-units"
echo "was passed."
echo

if [ "$DRY_RUN" -eq 1 ]; then
    echo "--dry-run: stopping here. Nothing was changed."
    exit 0
fi

# ---------------------------------------------------------------------------
# 2. Create (or reuse) the virtual environment.
# ---------------------------------------------------------------------------
echo "--- applying ---"
if [ "$RECREATE" -eq 1 ] && [ -d "$VENV_DIR" ]; then
    echo "removing existing venv at $VENV_DIR (--recreate)..."
    rm -rf "$VENV_DIR"
fi
if [ -d "$VENV_DIR" ]; then
    echo "reusing existing virtual environment at $VENV_DIR"
else
    echo "creating virtual environment at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

echo "upgrading pip inside the venv..."
"$VENV_PY" -m pip install -q --upgrade pip

# ---------------------------------------------------------------------------
# 3. Install SentinelForge.
# ---------------------------------------------------------------------------
echo "installing SentinelForge ($PIP_TARGET)..."
if [ "$EDITABLE" -eq 1 ]; then
    (cd "$REPO_ROOT" && "$VENV_PIP" install -e "$PIP_TARGET")
else
    (cd "$REPO_ROOT" && "$VENV_PIP" install "$PIP_TARGET")
fi

SF_BIN="$VENV_DIR/bin/sentinelforge"
if [ ! -x "$SF_BIN" ]; then
    echo "ERROR: install finished but $SF_BIN was not created." >&2
    exit 1
fi

echo
echo "verifying the installed command..."
"$SF_BIN" --version

# ---------------------------------------------------------------------------
# 4. Optional convenience symlink (never automatic).
# ---------------------------------------------------------------------------
if [ "$LINK" -eq 1 ]; then
    mkdir -p "$LINK_DIR"
    ln -sf "$SF_BIN" "$LINK_DIR/sentinelforge"
    echo "linked $LINK_DIR/sentinelforge -> $SF_BIN"
    case ":$PATH:" in
        *":$LINK_DIR:"*) ;;
        *) echo "NOTE: $LINK_DIR is not on your \$PATH yet - add it in your shell profile," \
                "or run 'sentinelforge' by its full path shown above." ;;
    esac
fi

# ---------------------------------------------------------------------------
# 5. Optional systemd units (explicit opt-in; hands off to the reviewed
#    installer, which itself confirms before changing anything).
# ---------------------------------------------------------------------------
if [ -n "$SYSTEMD_UNITS" ]; then
    echo
    echo "--- systemd units (--systemd-units $SYSTEMD_UNITS) ---"
    echo "This step needs root and will run:"
    echo "  sudo $REPO_ROOT/scripts/install-systemd-service.sh --units $SYSTEMD_UNITS --bin $SF_BIN"
    echo "It will show its own plan and ask to confirm before changing anything."
    sudo "$REPO_ROOT/scripts/install-systemd-service.sh" --units "$SYSTEMD_UNITS" --bin "$SF_BIN"
fi

echo
echo "============================================================"
echo "SentinelForge is installed."
echo "============================================================"
echo
echo "Run it with the full path (works from anywhere, no activation needed):"
echo "  $SF_BIN --help"
echo "  $SF_BIN sources"
echo "  $SF_BIN simulate all --report"
echo "  $SF_BIN dashboard --demo      # http://127.0.0.1:8080, synthetic data"
echo
echo "...or activate the venv first and use the bare command:"
echo "  source $VENV_DIR/bin/activate"
echo "  sentinelforge --help"
echo
if [ "$LINK" -ne 1 ]; then
    echo "Prefer typing 'sentinelforge' with no venv activation? Re-run with --link"
    echo "to symlink it into ~/.local/bin (or --link DIR for another directory)."
    echo
fi
echo "Optional next steps (none of these are required to use SentinelForge):"
echo "  - Real eBPF telemetry:  see the README's 'Fedora eBPF Setup' section,"
echo "    then run: $SF_BIN sensor check"
echo "  - Real firewall/session containment: see 'Fedora requirements for"
echo "    response' in the README."
echo "  - Systemd deployment (dashboard + periodic scan as services):"
echo "    sudo scripts/install-systemd-service.sh --units dashboard,scan --bin $SF_BIN"
echo "  - Hosted AI provider: pip install \"sentinelforge[llm]\" and see"
echo "    'Configuring a provider' in the README (the offline mock provider"
echo "    works with no key and is the default)."
