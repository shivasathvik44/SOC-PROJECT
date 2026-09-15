"""SentinelForge - a Linux-native SOC / threat detection and response platform.

Phase 1 implements the log collection and event normalization layer: read Linux
security logs and turn them into a single normalized JSON event shape.

Phase 2 adds a deterministic, rule-based detection engine on top: it raises
alerts carrying their evidence, maps them to MITRE ATT&CK and scores their risk.

Phase 3 correlates related alerts into incidents with attack chains, timelines
and an explained risk score, stored in a local SQLite file.

Phase 4 adds eBPF sensors for process execution and outbound network
connections, feeding the same pipeline with telemetry that never reaches a log
file.

Phase 5 adds an AI SOC analyst that reads a finished incident and produces a
Tier-1 reading of it: a summary, the evidence it rests on, possible benign
explanations, and what to investigate next.  The AI is an assistant, never the
detector: detection, correlation and scoring stay deterministic, and the AI
layer has no shell, no tools and no ability to change anything.

Phase 6 adds a local SOC dashboard: a loopback-bound web console that renders
what the pipeline produced, with a live event stream.

Phase 7 adds response and containment -- the first part of SentinelForge that
can change the system it monitors, and the part most carefully fenced in.  An
analyst requests an action, approves it in a separate step, and executes it in
another; policy validates it before and after; the result is verified against
the system and written to an append-only audit trail.  Nothing is automatic,
and nothing that came from a log line, a telemetry field or an AI answer can
cause anything to be executed.

Phase 8 adds the validation layer: safe synthetic attack scenarios, a
purple-team runner that compares what the platform *should* conclude against
what it actually concluded, false-positive and boundary testing, performance
benchmarking, security boundary probes, and generated validation reports.  It
adds no detection capability -- its whole job is to measure the ones that are
already there, and to expose the places where they fall short.

Phases 1-6 are strictly read-only.  Phase 7 acts only when a human says so.
Phase 8 is synthetic throughout: it sends nothing, executes nothing, and drives
containment against in-memory backends only.

This is a v1.0.0 release candidate: Phase 9 audits and hardens packaging,
installation and documentation for a first stable release on Linux.  It adds
no pipeline stage and changes no detection, correlation, AI or response
behavior -- see the "Deployment and installation" section of the README for
what changed and why.
"""

__version__ = "1.0.0rc1"

__all__ = ["__version__"]
