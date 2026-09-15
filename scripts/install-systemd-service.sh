#!/usr/bin/env bash
# Phase 9.3 - installs SentinelForge's systemd units onto this machine.
#
# This script is maintainer/operator tooling, not part of the installed
# Python package: it is not imported by SentinelForge and not shipped in the
# wheel (setuptools only packages src/). Its entire job is to turn the manual
# steps in packaging/systemd/README.md into one reviewable, confirmed action,
# nothing more:
#
#   1. create a dedicated, unprivileged, no-login system user/group
#      ('sentinelforge') if one does not already exist;
#   2. create /etc/sentinelforge (mode 0750) for the optional environment
#      file, owned by that group;
#   3. copy the requested unit files from packaging/systemd/ into
#      /etc/systemd/system/;
#   4. run `systemctl daemon-reload` so systemd notices them.
#
# It deliberately does NOT:
#   - enable or start any unit (that is always a separate, explicit step -
#     see the "Next steps" this script prints at the end);
#   - touch firewalld, SELinux, or any kernel security setting;
#   - set, prompt for, or store a password anywhere (the system account this
#     creates is locked and has no login shell - see the useradd call below);
#   - use shell=True-equivalent constructs: every external command below is
#     an argv list, never a string handed to a shell for interpolation, and
#     nothing this script reads from the user ever reaches a shell as code.
#
# Usage:
#   sudo scripts/install-systemd-service.sh [--units dashboard,scan] [--yes]
#
#   --units LIST   comma-separated subset of: dashboard,scan,ebpf-process,
#                  ebpf-network (default: dashboard,scan - the two units
#                  that need no elevated privilege at all)
#   --bin PATH     the installed 'sentinelforge' console script
#                  (default: the first one found on this PATH)
#   --yes          skip the confirmation prompt (for scripted installs;
#                  the plan is still printed first either way)
#   --dry-run      print the plan and exit without changing anything
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="$REPO_ROOT/packaging/systemd"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/sentinelforge"
SERVICE_USER="sentinelforge"
SERVICE_GROUP="sentinelforge"

UNITS="dashboard,scan"
BIN_PATH="$(command -v sentinelforge || true)"
ASSUME_YES=0
DRY_RUN=0

usage() {
    grep '^#' "${BASH_SOURCE[0]}" | sed -n '/^# Usage:/,/--dry-run/p' | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --units) UNITS="$2"; shift 2 ;;
        --bin) BIN_PATH="$2"; shift 2 ;;
        --yes) ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "This installs system-wide files and must run as root (sudo)." >&2
    echo "Re-run with --dry-run first if you only want to see the plan." >&2
    exit 1
fi

declare -A UNIT_FILES=(
    [dashboard]="sentinelforge-dashboard.service"
    [scan]="sentinelforge-scan.service sentinelforge-scan.timer"
    [ebpf-process]="sentinelforge-ebpf-process.service"
    [ebpf-network]="sentinelforge-ebpf-network.service"
)

SELECTED_FILES=()
IFS=',' read -r -a REQUESTED <<< "$UNITS"
for name in "${REQUESTED[@]}"; do
    files="${UNIT_FILES[$name]:-}"
    if [ -z "$files" ]; then
        echo "unknown unit group: '$name' (expected one of: ${!UNIT_FILES[*]})" >&2
        exit 2
    fi
    for f in $files; do
        SELECTED_FILES+=("$f")
    done
done

echo "SentinelForge systemd installer"
echo "================================"
echo
echo "Plan:"
echo "  1. Ensure a locked, no-login system account exists:"
echo "       user:  $SERVICE_USER"
echo "       group: $SERVICE_GROUP"
echo "       home:  none (StateDirectory= in the units provides /var/lib/sentinelforge)"
echo "       shell: /usr/sbin/nologin"
echo "  2. Create $CONFIG_DIR (mode 0750, group $SERVICE_GROUP) for the optional"
echo "     environment file - nothing is written into it by this script."
echo "  3. Copy these unit files into $SYSTEMD_DIR:"
for f in "${SELECTED_FILES[@]}"; do
    echo "       - $f"
done
echo "  4. Run 'systemctl daemon-reload'."
echo
echo "This script will NOT enable or start any unit, touch firewalld or"
echo "SELinux, or set a password. Those remain separate, explicit steps -"
echo "printed again at the end."
echo

DEFAULT_BIN="/usr/local/bin/sentinelforge"
if [ -z "$BIN_PATH" ]; then
    echo "WARNING: no 'sentinelforge' executable was found on this PATH."
    echo "The unit files hardcode $DEFAULT_BIN as the command to run (systemd"
    echo "does not expand environment variables in that position - see each"
    echo "unit file's header comment) - they will be installed as-is, and you"
    echo "must edit ExecStart= in /etc/systemd/system yourself if that path is"
    echo "wrong for this host, then 'sudo systemctl daemon-reload'."
    echo
    BIN_PATH="$DEFAULT_BIN"
elif [ "$BIN_PATH" != "$DEFAULT_BIN" ]; then
    echo "Detected sentinelforge at: $BIN_PATH (not the unit files' built-in"
    echo "default of $DEFAULT_BIN) - this script will rewrite each copied"
    echo "unit's ExecStart= to use the path it detected."
    echo
else
    echo "Detected sentinelforge at: $BIN_PATH (matches the unit files' default)"
    echo
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "--dry-run: stopping here. Nothing was changed."
    exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
    read -r -p "Proceed with the plan above? [y/N] " reply
    case "$reply" in
        [yY][eE][sS]|[yY]) ;;
        *) echo "Aborted; nothing was changed."; exit 1 ;;
    esac
fi

echo
echo "--- applying ---"

if ! getent passwd "$SERVICE_USER" >/dev/null; then
    echo "creating system user '$SERVICE_USER'..."
    useradd \
        --system \
        --user-group \
        --no-create-home \
        --home-dir /var/lib/sentinelforge \
        --shell /usr/sbin/nologin \
        --comment "SentinelForge SOC service account" \
        "$SERVICE_USER"
    # Explicit, in addition to --system's own default: no password can ever
    # authenticate this account.
    passwd -l "$SERVICE_USER" >/dev/null
else
    echo "system user '$SERVICE_USER' already exists; leaving it as is."
fi

echo "creating $CONFIG_DIR..."
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR"
if [ ! -e "$CONFIG_DIR/sentinelforge.env" ]; then
    install -m 0640 -o root -g "$SERVICE_GROUP" \
        "$UNIT_DIR/sentinelforge.env.example" \
        "$CONFIG_DIR/sentinelforge.env.example"
    echo "  placed sentinelforge.env.example there - copy it to sentinelforge.env"
    echo "  and edit it if you need to override any default (see that file)."
fi

echo "copying unit files into $SYSTEMD_DIR..."
for f in "${SELECTED_FILES[@]}"; do
    if [ "$BIN_PATH" != "$DEFAULT_BIN" ]; then
        # A plain, fixed-string substitution of one known path for another -
        # not evaluated as a pattern, and never touches anything but this one
        # line, which is exactly why this is a `sed` replacement rather than
        # a shell eval of anything: what goes in is a filesystem path this
        # script itself just resolved with `command -v`, never operator- or
        # telemetry-supplied text.
        sed "s|$DEFAULT_BIN|$BIN_PATH|g" \
            "$UNIT_DIR/$f" > "$SYSTEMD_DIR/$f"
        chmod 0644 "$SYSTEMD_DIR/$f"
        chown root:root "$SYSTEMD_DIR/$f"
    else
        install -m 0644 -o root -g root "$UNIT_DIR/$f" "$SYSTEMD_DIR/$f"
    fi
    echo "  installed $f"
done

echo "reloading systemd..."
systemctl daemon-reload

echo
echo "--- done ---"
echo
echo "Nothing was enabled or started. Next steps, run by you, explicitly:"
echo
if [[ " ${SELECTED_FILES[*]} " == *" sentinelforge-dashboard.service "* ]]; then
    echo "  # Read the dashboard's needs first - it requires the 'dashboard' extra:"
    echo "  #   pip install \"sentinelforge[dashboard]\""
    echo "  sudo systemctl enable --now sentinelforge-dashboard.service"
    echo "  sudo systemctl status sentinelforge-dashboard.service"
fi
if [[ " ${SELECTED_FILES[*]} " == *" sentinelforge-scan.timer "* ]]; then
    echo "  sudo systemctl enable --now sentinelforge-scan.timer"
    echo "  sudo systemctl list-timers sentinelforge-scan.timer"
fi
if [[ " ${SELECTED_FILES[*]} " == *" sentinelforge-ebpf-process.service "* ]] || \
   [[ " ${SELECTED_FILES[*]} " == *" sentinelforge-ebpf-network.service "* ]]; then
    echo "  # Advanced/privileged - read that unit file's header comment first,"
    echo "  # and run 'sentinelforge sensor check' as this host's real kernel"
    echo "  # before enabling either eBPF unit:"
    echo "  sudo -u $SERVICE_USER sentinelforge sensor check"
fi
echo
echo "  journalctl -u sentinelforge-dashboard.service -f    # follow logs"
echo
echo "See the README's 'Running SentinelForge as a systemd service' section"
echo "for uninstall instructions."
