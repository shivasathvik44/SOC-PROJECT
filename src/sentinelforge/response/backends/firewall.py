"""Firewall containment backend (Phase 7).

The only firewall operation SentinelForge performs is: *add one rule that drops
traffic from one address, and later remove that exact rule*.  There is no
method here to flush rules, reset a zone, change the default zone, stop
firewalld, or run an arbitrary ``firewall-cmd`` invocation -- not because
callers are trusted not to ask, but because the vocabulary to ask does not
exist.

Design decisions worth knowing before reading the code:

**firewalld, detected rather than assumed.**  Fedora ships firewalld, but this
module still checks that ``firewall-cmd`` exists *and* that the daemon answers
``--state`` before claiming the backend is usable.  If it is not running, the
backend is unavailable and the action is refused -- SentinelForge does not fall
back to raw ``nft`` or ``iptables`` rules behind firewalld's back, because a
rule the system's own firewall manager does not know about is a rule nobody
will ever find again.

**Runtime rules, not permanent ones.**  Blocks are added to the running
configuration only.  Two consequences, both deliberate: a block disappears on
``firewall-cmd --reload`` or a reboot (containment is temporary by default and
fails *open* rather than silently outliving the investigation), and firewalld's
native ``--timeout=`` becomes available, which is how TTLs are implemented here
without a background thread editing the firewall on its own.

**Rules carry their action id.**  Every rule logs with the prefix
``sentinelforge-block-<action_id>``, rate-limited to one line a minute.  That
makes the rule identifiable in ``firewall-cmd --list-rich-rules``, ties a
packet drop in the journal back to the analyst who approved it, and -- because
the rule text is stored verbatim in the action's ``rollback_data`` -- lets the
unblock remove exactly that rule and nothing else.
"""

from __future__ import annotations

import logging
import re
import time

from ..executor import CommandRunner, ExecutionError, is_root
from ..models import ActionOutcome
from ..validators import validate_ip
from .base import BackendStatus

LOGGER = logging.getLogger(__name__)

#: Prefix of every rule this backend creates.  Also the marker used to tell
#: SentinelForge's rules apart from everyone else's.
RULE_PREFIX = "sentinelforge-block-"

#: Matches the log prefix inside a rich rule, so a rule can be attributed.
_PREFIX_PATTERN = re.compile(re.escape(RULE_PREFIX) + r"(?P<action_id>[A-Za-z0-9-]+)")

#: firewalld zone names are restricted; anything else is not a zone we will use.
_ZONE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

#: Seconds an availability probe is reused.  Asking the daemon whether it is
#: running costs a process launch, and the answer does not change between two
#: page loads -- the same reasoning as the dashboard's sensor cache.  Rule
#: *state* is never cached: verification always asks.
STATUS_CACHE_SECONDS = 30.0


def build_rich_rule(address, action_id: str) -> str:
    """Compose the exact rich rule for one block.

    Both inputs are re-rendered from validated, typed values -- the address
    from an :mod:`ipaddress` object and the action id from a ``^[A-Za-z0-9-]+$``
    check -- so the returned string cannot contain anything the caller smuggled
    in.  That matters because this string is what the unblock later matches on.
    """
    parsed = validate_ip(address)
    if not re.match(r"^[A-Za-z0-9-]{1,40}$", action_id or ""):
        raise ValueError(f"unusable action id for a firewall rule: {action_id!r}")
    family = "ipv4" if parsed.version == 4 else "ipv6"
    return (
        f'rule family="{family}" source address="{parsed}" '
        f'log prefix="{RULE_PREFIX}{action_id} " level="info" limit value="1/m" drop'
    )


def rule_action_id(rich_rule: str) -> str | None:
    """Extract the SentinelForge action id from a rich rule, if it has one."""
    match = _PREFIX_PATTERN.search(rich_rule or "")
    return match.group("action_id") if match else None


class FirewallBackend:
    """Interface every firewall backend implements."""

    name = "firewall"

    def status(self) -> BackendStatus:  # pragma: no cover - abstract
        raise NotImplementedError

    def is_available(self) -> bool:
        return self.status().available

    def validate_target(self, address) -> dict:  # pragma: no cover - abstract
        raise NotImplementedError

    def preview_block(self, address, action_id: str, ttl: int | None = None) -> dict:  # pragma: no cover - abstract
        raise NotImplementedError

    def block_ip(self, address, action_id: str, ttl: int | None = None) -> ActionOutcome:  # pragma: no cover - abstract
        raise NotImplementedError

    def unblock_ip(self, rollback_data: dict) -> ActionOutcome:  # pragma: no cover - abstract
        raise NotImplementedError

    def get_rule_state(self, rich_rule: str, zone: str | None = None) -> bool | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def managed_rules(self) -> list[dict]:  # pragma: no cover - abstract
        raise NotImplementedError


class FirewalldBackend(FirewallBackend):
    """Containment through ``firewall-cmd`` rich rules.

    Args:
        runner: The command runner.  Pass a
            :class:`~sentinelforge.response.executor.ReadOnlyCommandRunner` to
            build a backend that can describe blocks but never make one.
        zone: Which firewalld zone to write into.  Defaults to the daemon's own
            default zone, queried once and cached.
    """

    name = "firewalld"

    def __init__(self, runner: CommandRunner | None = None, zone: str | None = None) -> None:
        self.runner = runner or CommandRunner()
        self._zone = zone
        self._zone_checked = zone is not None
        self._status: BackendStatus | None = None
        self._status_at: float = 0.0

    # -- availability ------------------------------------------------------
    def status(self) -> BackendStatus:
        """Whether firewalld is installed and running (cached briefly).

        See :data:`STATUS_CACHE_SECONDS`.
        """
        now = time.monotonic()
        if self._status is not None and (now - self._status_at) < STATUS_CACHE_SECONDS:
            return self._status
        self._status = self._probe()
        self._status_at = now
        return self._status

    def _probe(self) -> BackendStatus:
        """Ask the system whether firewalld is usable.

        Both halves matter: an installed ``firewall-cmd`` talking to a stopped
        daemon would accept nothing, and reporting that as "available" would
        turn a clear refusal into a confusing failure mid-action.
        """
        if not self.runner.available("firewall-cmd"):
            return BackendStatus(
                name=self.name,
                available=False,
                reason="firewall-cmd was not found on this host",
                remedy="Install firewalld (sudo dnf install firewalld), or use "
                "SentinelForge without firewall containment.",
            )
        try:
            result = self.runner.run(["firewall-cmd", "--state"], timeout=10.0)
        except ExecutionError as exc:
            return BackendStatus(
                name=self.name,
                available=False,
                reason=f"firewalld could not be queried: {exc}",
                remedy="Check that firewalld is installed and this process may run it.",
            )
        if not result.ok or result.stdout.strip() != "running":
            return BackendStatus(
                name=self.name,
                available=False,
                reason="the firewalld daemon is not running",
                remedy="Start it yourself if that is appropriate for this host: "
                "sudo systemctl start firewalld. SentinelForge never starts, stops "
                "or reconfigures the firewall service.",
            )
        return BackendStatus(
            name=self.name,
            available=True,
            requires_privilege=not is_root(),
            details={
                "zone": self.zone(),
                "scope": "runtime rules only (cleared by a firewalld reload or reboot)",
            },
        )

    def zone(self) -> str:
        """The firewalld zone this backend writes into."""
        if self._zone_checked:
            return self._zone or "public"
        self._zone_checked = True
        try:
            result = self.runner.run(["firewall-cmd", "--get-default-zone"], timeout=10.0)
        except ExecutionError:
            result = None
        candidate = (result.stdout.strip() if result and result.ok else "") or "public"
        self._zone = candidate if _ZONE_PATTERN.match(candidate) else "public"
        return self._zone

    # -- target validation -------------------------------------------------
    def validate_target(self, address) -> dict:
        """Check that this backend can express a block for ``address``.

        Raises:
            ValidationError: The value is not an IP address at all.
        """
        parsed = validate_ip(address)
        return {
            "address": str(parsed),
            "family": "ipv4" if parsed.version == 4 else "ipv6",
            "zone": self.zone(),
        }

    # -- preview -----------------------------------------------------------
    def preview_block(self, address, action_id: str, ttl: int | None = None) -> dict:
        """Describe the rule that *would* be created.  Changes nothing."""
        target = self.validate_target(address)
        rule = build_rich_rule(address, action_id)
        return {
            "backend": self.name,
            "zone": target["zone"],
            "family": target["family"],
            "address": target["address"],
            "rich_rule": rule,
            "ttl_seconds": ttl,
            "permanent": False,
            "command": self._add_command(rule, ttl),
            "already_blocked": self.get_rule_state(rule, target["zone"]) is True,
        }

    # -- state -------------------------------------------------------------
    def get_rule_state(self, rich_rule: str, zone: str | None = None) -> bool | None:
        """Whether one exact rich rule is currently installed.

        Returns ``True``/``False``, or ``None`` when firewalld could not answer
        -- an unknown state is reported as unknown rather than guessed at.
        """
        zone = zone or self.zone()
        try:
            result = self.runner.run(
                ["firewall-cmd", "--zone", zone, "--query-rich-rule", rich_rule], timeout=10.0
            )
        except ExecutionError as exc:
            LOGGER.debug("could not query rich rule: %s", exc)
            return None
        answer = result.stdout.strip()
        if answer == "yes":
            return True
        if answer == "no":
            return False
        return None

    def managed_rules(self) -> list[dict]:
        """Every rich rule in the zone that SentinelForge created.

        Used to answer "is this address already contained?" and to show the
        analyst what this tool is currently holding.  Rules without the
        SentinelForge prefix are listed by nobody and touched by nothing here.
        """
        zone = self.zone()
        try:
            result = self.runner.run(
                ["firewall-cmd", "--zone", zone, "--list-rich-rules"], timeout=10.0
            )
        except ExecutionError as exc:
            LOGGER.debug("could not list rich rules: %s", exc)
            return []
        if not result.ok:
            return []
        rules = []
        for line in result.stdout.splitlines():
            line = line.strip()
            action_id = rule_action_id(line)
            if not action_id:
                continue
            match = re.search(r'source address="([^"]+)"', line)
            rules.append(
                {
                    "zone": zone,
                    "rich_rule": line,
                    "action_id": action_id,
                    "address": match.group(1) if match else None,
                }
            )
        return rules

    def blocked_addresses(self) -> dict[str, str]:
        """Map of ``address -> action_id`` for the blocks SentinelForge holds."""
        return {
            rule["address"]: rule["action_id"]
            for rule in self.managed_rules()
            if rule.get("address")
        }

    # -- mutation ----------------------------------------------------------
    def block_ip(self, address, action_id: str, ttl: int | None = None) -> ActionOutcome:
        """Install one drop rule for ``address``.

        Success is decided by re-querying the rule afterwards, never by the
        exit code: firewalld can report success for a rule that a later reload
        or a conflicting configuration removed.
        """
        target = self.validate_target(address)
        zone = target["zone"]
        rule = build_rich_rule(address, action_id)
        rollback = {
            "backend": self.name,
            "zone": zone,
            "rich_rule": rule,
            "address": target["address"],
            "action_id": action_id,
        }

        if self.get_rule_state(rule, zone) is True:
            return ActionOutcome(
                ok=True,
                detail=f"{target['address']} was already blocked by this exact rule",
                data={"zone": zone, "rich_rule": rule, "already_present": True},
                rollback_data=rollback,
            )

        try:
            result = self.runner.run(self._add_command(rule, ttl), timeout=20.0, mutating=True)
        except ExecutionError as exc:
            return ActionOutcome(
                ok=False, detail="the firewall command could not be run", error=str(exc)
            )
        if not result.ok:
            return ActionOutcome(
                ok=False,
                detail="firewalld refused the block rule",
                data=result.to_dict(),
                error=self._explain(result),
            )
        state = self.get_rule_state(rule, zone)
        if state is not True:
            return ActionOutcome(
                ok=False,
                detail="firewalld accepted the command but the rule is not present",
                data={"zone": zone, "rich_rule": rule, "verified": state},
                error="verification failed: the block rule could not be confirmed",
            )
        return ActionOutcome(
            ok=True,
            detail=f"{target['address']} is blocked in zone {zone}",
            data={
                "zone": zone,
                "rich_rule": rule,
                "ttl_seconds": ttl,
                "permanent": False,
                "command": list(result.argv),
            },
            rollback_data=rollback,
        )

    def unblock_ip(self, rollback_data: dict) -> ActionOutcome:
        """Remove exactly the rule described by ``rollback_data``.

        The rule text comes from the block that created it, so this can only
        ever remove SentinelForge's own rule.  A rule that is already gone (a
        lapsed TTL, a firewalld reload) counts as success: the desired end
        state is "not blocked", and reporting a failure there would push an
        analyst toward re-running removals.
        """
        rule = (rollback_data or {}).get("rich_rule")
        zone = (rollback_data or {}).get("zone") or self.zone()
        if not rule or not rule_action_id(rule):
            return ActionOutcome(
                ok=False,
                detail="refusing to remove a rule SentinelForge did not create",
                error="rollback data does not describe a SentinelForge block rule",
            )
        if not _ZONE_PATTERN.match(str(zone)):
            return ActionOutcome(
                ok=False, detail="unusable firewall zone", error=f"invalid zone {zone!r}"
            )

        if self.get_rule_state(rule, zone) is False:
            return ActionOutcome(
                ok=True,
                detail="the block rule was already gone (TTL expiry or a firewalld reload)",
                data={"zone": zone, "rich_rule": rule, "already_absent": True},
            )
        try:
            result = self.runner.run(
                ["firewall-cmd", "--zone", str(zone), "--remove-rich-rule", rule],
                timeout=20.0,
                mutating=True,
            )
        except ExecutionError as exc:
            return ActionOutcome(
                ok=False, detail="the firewall command could not be run", error=str(exc)
            )
        if not result.ok:
            return ActionOutcome(
                ok=False,
                detail="firewalld refused to remove the block rule",
                data=result.to_dict(),
                error=self._explain(result),
            )
        state = self.get_rule_state(rule, zone)
        if state is not False:
            return ActionOutcome(
                ok=False,
                detail="firewalld accepted the removal but the rule is still present",
                data={"zone": zone, "rich_rule": rule, "verified": state},
                error="verification failed: the block rule is still installed",
            )
        return ActionOutcome(
            ok=True,
            detail=f"the block rule was removed from zone {zone}",
            data={"zone": zone, "rich_rule": rule, "command": list(result.argv)},
        )

    # -- helpers -----------------------------------------------------------
    def _add_command(self, rich_rule: str, ttl: int | None) -> list[str]:
        """The exact argv for installing one rule (runtime only)."""
        command = ["firewall-cmd", "--zone", self.zone(), "--add-rich-rule", rich_rule]
        if ttl:
            # firewalld removes the rule itself when the timeout lapses, so no
            # SentinelForge thread ever has to touch firewall state on a timer.
            command.append(f"--timeout={int(ttl)}s")
        return command

    @staticmethod
    def _explain(result) -> str:
        if result.permission_denied:
            return (
                "firewalld refused the change for lack of privileges. Re-run the "
                "approved action with firewall administration rights "
                "(for example: sudo sentinelforge response execute <ACTION-ID>)."
            )
        return result.describe()


class UnsupportedFirewallBackend(FirewallBackend):
    """Stands in when no supported firewall manager is present.

    It refuses every containment request with the reason it was given.  This is
    the "no dangerous fallback" rule made concrete: SentinelForge would rather
    do nothing than write ``nft`` or ``iptables`` rules underneath a firewall
    manager that does not know about them.
    """

    name = "unsupported"

    def __init__(self, reason: str, remedy: str | None = None) -> None:
        self.reason = reason
        self.remedy = remedy

    def status(self) -> BackendStatus:
        return BackendStatus(
            name=self.name, available=False, reason=self.reason, remedy=self.remedy
        )

    def validate_target(self, address) -> dict:
        parsed = validate_ip(address)
        return {"address": str(parsed), "family": f"ipv{parsed.version}", "zone": None}

    def preview_block(self, address, action_id: str, ttl: int | None = None) -> dict:
        return {
            "backend": self.name,
            "address": str(validate_ip(address)),
            "zone": None,
            "rich_rule": None,
            "ttl_seconds": ttl,
            "unavailable_reason": self.reason,
            "already_blocked": False,
        }

    def get_rule_state(self, rich_rule: str, zone: str | None = None) -> bool | None:
        return None

    def managed_rules(self) -> list[dict]:
        return []

    def blocked_addresses(self) -> dict[str, str]:
        return {}

    def block_ip(self, address, action_id: str, ttl: int | None = None) -> ActionOutcome:
        return ActionOutcome(ok=False, detail=self.reason, error=self.reason)

    def unblock_ip(self, rollback_data: dict) -> ActionOutcome:
        return ActionOutcome(ok=False, detail=self.reason, error=self.reason)


def detect_firewall_backend(runner: CommandRunner | None = None) -> FirewallBackend:
    """Pick a firewall backend for this host.

    firewalld when it is installed and running, an
    :class:`UnsupportedFirewallBackend` otherwise.  Other firewall managers are
    detected only well enough to explain *why* SentinelForge will not use them.
    """
    runner = runner or CommandRunner()
    firewalld = FirewalldBackend(runner=runner)
    status = firewalld.status()
    if status.available:
        return firewalld
    remedy = status.remedy
    if not runner.available("firewall-cmd"):
        remedy = (
            "SentinelForge only manages firewalld rules. On a host using raw nftables "
            "or iptables it will not add rules behind the firewall manager's back; "
            "block the address with your own tooling instead."
        )
    return UnsupportedFirewallBackend(reason=status.reason or "no firewall backend", remedy=remedy)
