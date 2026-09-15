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
| `sentinelforge-ebpf-process.service` | `sentinelforge sensor start ebpf-process` | `CAP_BPF` + `CAP_PERFMON` (optional, advanced, disabled by default) |
| `sentinelforge-ebpf-network.service` | `sentinelforge sensor start ebpf-network` | `CAP_BPF` + `CAP_PERFMON` (optional, advanced, disabled by default) |
| `sentinelforge.env.example` | shared, optional environment file | n/a - contains no real values |

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
