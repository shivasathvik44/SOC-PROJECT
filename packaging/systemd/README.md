# SentinelForge systemd units (Phase 9.3)

Nothing in this directory is installed automatically. It is packaging
material shipped alongside the source tree, not part of the installed Python
package (`setuptools.packages.find` only looks under `src/`, so none of this
ends up in the wheel either) - copying it into `/etc/systemd/system` is a
deliberate, manual step, or one run through
`scripts/install-systemd-service.sh` after reading what that script does.

See the main [README.md](../../README.md)'s "Running SentinelForge as a
systemd service" section for the full walkthrough: installation, starting,
stopping, checking status, viewing logs, uninstalling, and exactly which
privileges each unit needs and why.

## What is here

| File | What it runs | Privilege |
| --- | --- | --- |
| `sentinelforge-dashboard.service` | `sentinelforge dashboard` | none (dedicated unprivileged user) |
| `sentinelforge-scan.service` | `collect \| detect \| correlate`, one run | none beyond `systemd-journal` group membership |
| `sentinelforge-scan.timer` | triggers `sentinelforge-scan.service` on a schedule | none - only reads the clock |
| `sentinelforge-ebpf-process.service` | `sentinelforge sensor start ebpf-process` | `CAP_BPF` + `CAP_PERFMON` (optional, advanced, disabled by default) - validated on a real Fedora 44 kernel |
| `sentinelforge-ebpf-network.service` | `sentinelforge sensor start ebpf-network` | `CAP_BPF` + `CAP_PERFMON` in principle, but usually **root in practice** - see below. Shipped as packaging material only; not installed or enabled in v1 |
| `sentinelforge.env.example` | shared, optional environment file | n/a - contains no real values |

### Why the network unit is not installed in v1

The process sensor's `CAP_BPF` + `CAP_PERFMON` model has been validated end to
end on a real Fedora 44 kernel. The network sensor attaches to a tracepoint
instead of a kprobe, and BCC needs to read that tracepoint's `format` file
under `/sys/kernel/tracing/events/` to compile against it. On Fedora 44 that
whole directory is `0700 root:root`, so the capability pair - which governs
BPF operations, not filesystem access - does not help; only root can read it.
This unit does carry a commented-out `User=root` fallback for exactly that
case, but v1 does not uncomment it and enable this as a standing root
service: every other privileged operation in this deployment is either
capability-scoped or a one-off command a human runs with `sudo`, never an
unattended root daemon, and this unit would be the only exception. Instead,
run the network sensor manually when you need it:

```bash
# 'sudo' resets $PATH, so give it the full path to your installed venv's
# 'sentinelforge' rather than relying on an activated venv being visible to it:
sudo "$(pwd)/.venv/bin/sentinelforge" sensor start ebpf-network --limit 5
```

Network telemetry is therefore not continuous in this deployment - only the
process sensor is meant to run as an always-on unit. See the main
[README.md](../../README.md)'s "Why network eBPF is manual, not a service"
section for the full reasoning.

## What is deliberately not here

There is no systemd unit for `sentinelforge response *` and none for
`sentinelforge ai analyze`. Both remain manual, on-demand commands a human
runs:

- **Response** actions require an explicit human `approve` step before
  `execute` can do anything, by construction (see
  `response/models.py` - there is no state transition from
  `awaiting_approval` directly to `executing`). A systemd unit that ran
  `response execute` on a timer would not bypass that gate, but building one
  at all would suggest containment is meant to run unattended, which it is
  not and never will be in this project. If you need response actions
  scripted, invoke them yourself, deliberately, with `sudo` when the action
  needs it.
- **AI analysis** costs money against a real provider and is not something a
  service should trigger on its own schedule without the operator asking.
