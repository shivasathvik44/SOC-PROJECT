"""SQLite persistence for incidents and response actions.

All SQL in SentinelForge lives in this module: the correlation engine works
with :class:`Incident` objects and the response engine with
:class:`~sentinelforge.response.models.ResponseAction` objects, and neither
ever sees a query.  The database is a plain file handled by the standard
library ``sqlite3`` -- no server, no daemon, and nothing to install on a Fedora
workstation.

Phase 7 adds two tables to the *same* database file rather than a second one:
response actions belong to the incidents they were taken on, and splitting them
across databases would make "what happened to INC-000001?" a join across files.

The ``response_audit`` table is append-only, and not merely by convention:
:class:`ResponseStore` exposes no update or delete for it, and SQLite triggers
abort any ``UPDATE`` or ``DELETE`` that reaches it anyway.  Each row also
carries the hash of the row before it, so removing or rewriting history at the
file level breaks a chain that :meth:`ResponseStore.verify_audit_chain` will
notice.

Every statement is parameterized.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import timedelta

from ..models.event import Severity, format_timestamp, parse_timestamp, utc_now
from ..models.incident import Incident, IncidentStatus

LOGGER = logging.getLogger(__name__)

#: Bump when the table layout changes.  v2 added the Phase 7 response tables.
SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk_score  INTEGER NOT NULL DEFAULT 0,
    host        TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    alert_count INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents (last_seen);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
"""

#: Phase 7.  ``response_actions`` holds the current state of each action (its
#: status changes as it is approved and executed); ``response_audit`` holds the
#: history, which never changes.
_RESPONSE_SCHEMA = """
CREATE TABLE IF NOT EXISTS response_actions (
    action_id    TEXT PRIMARY KEY,
    incident_id  TEXT,
    action_type  TEXT NOT NULL,
    target       TEXT NOT NULL,
    status       TEXT NOT NULL,
    dry_run      INTEGER NOT NULL DEFAULT 0,
    requested_by TEXT,
    requested_at TEXT,
    completed_at TEXT,
    updated_at   TEXT NOT NULL,
    data         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions (incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON response_actions (status);
CREATE INDEX IF NOT EXISTS idx_actions_target ON response_actions (action_type, target);

CREATE TABLE IF NOT EXISTS response_audit (
    sequence           INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id           TEXT NOT NULL UNIQUE,
    timestamp          TEXT NOT NULL,
    event              TEXT NOT NULL,
    action_id          TEXT,
    incident_id        TEXT,
    action_type        TEXT,
    target             TEXT,
    requested_by       TEXT,
    approved_by        TEXT,
    reason             TEXT,
    policy_decision    TEXT,
    dry_run            INTEGER NOT NULL DEFAULT 0,
    execution_status   TEXT,
    result             TEXT,
    error              TEXT,
    rollback_available INTEGER NOT NULL DEFAULT 0,
    previous_hash      TEXT,
    entry_hash         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_action ON response_audit (action_id);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON response_audit (incident_id);

-- The audit trail is append-only.  These triggers are the database saying so
-- even if a future caller forgets.
CREATE TRIGGER IF NOT EXISTS response_audit_no_update
BEFORE UPDATE ON response_audit
BEGIN
    SELECT RAISE(ABORT, 'the SentinelForge response audit trail is append-only');
END;
CREATE TRIGGER IF NOT EXISTS response_audit_no_delete
BEFORE DELETE ON response_audit
BEGIN
    SELECT RAISE(ABORT, 'the SentinelForge response audit trail is append-only');
END;
"""


def default_database_path() -> str:
    """Return the default database location under the user's XDG data dir."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return os.path.join(base, "sentinelforge", "incidents.db")


class IncidentStore:
    """Stores and retrieves incidents.

    Args:
        path: Database file, ``":memory:"`` for an ephemeral store, or ``None``
            for :func:`default_database_path`.

    Use it as a context manager so the connection is always closed::

        with IncidentStore(path) as store:
            store.save(incident)
    """

    def __init__(self, path: str | None = None) -> None:
        self.path = path or default_database_path()
        self._connection: sqlite3.Connection | None = None

    # -- connection handling ----------------------------------------------
    def connect(self) -> sqlite3.Connection:
        """Open the database (creating directories and schema on first use)."""
        if self._connection is not None:
            return self._connection
        if self.path != ":memory:":
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory:
                os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.executescript(_SCHEMA)
        connection.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        connection.commit()
        self._connection = connection
        return connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "IncidentStore":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- writes ------------------------------------------------------------
    def save(self, incident: Incident) -> None:
        """Insert or update one incident (keyed by ``incident_id``)."""
        connection = self.connect()
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, title, status, severity, risk_score,
                host, first_seen, last_seen, alert_count, updated_at, data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                title = excluded.title,
                status = excluded.status,
                severity = excluded.severity,
                risk_score = excluded.risk_score,
                host = excluded.host,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                alert_count = excluded.alert_count,
                updated_at = excluded.updated_at,
                data = excluded.data
            """,
            (
                incident.incident_id,
                incident.title,
                incident.status,
                incident.severity,
                int(incident.risk_score),
                incident.host,
                incident.first_seen,
                incident.last_seen,
                incident.alert_count,
                utc_now(),
                json.dumps(incident.to_dict(), ensure_ascii=False),
            ),
        )
        connection.commit()

    def save_all(self, incidents) -> int:
        """Save several incidents in one transaction; returns how many."""
        count = 0
        for incident in incidents:
            self.save(incident)
            count += 1
        return count

    def update_status(self, incident_id: str, status: str) -> bool:
        """Change an incident's lifecycle status.

        Returns ``False`` when the incident does not exist.  Raises
        ``ValueError`` for a status that is not in :class:`IncidentStatus`.
        """
        if not IncidentStatus.is_valid(status):
            raise ValueError(
                f"unknown incident status {status!r} (valid: {', '.join(IncidentStatus.ALL)})"
            )
        incident = self.get(incident_id)
        if incident is None:
            return False
        incident.status = status
        self.save(incident)
        return True

    def delete(self, incident_id: str) -> bool:
        """Remove one incident.  Returns whether a row was deleted."""
        connection = self.connect()
        cursor = connection.execute(
            "DELETE FROM incidents WHERE incident_id = ?", (incident_id,)
        )
        connection.commit()
        return cursor.rowcount > 0

    # -- reads -------------------------------------------------------------
    def get(self, incident_id: str) -> Incident | None:
        """Load one incident by id, or ``None``."""
        row = (
            self.connect()
            .execute("SELECT data FROM incidents WHERE incident_id = ?", (incident_id,))
            .fetchone()
        )
        return self._row_to_incident(row)

    def list_incidents(
        self,
        status: str | None = None,
        min_severity: str | None = None,
        limit: int | None = None,
    ) -> list[Incident]:
        """List incidents, most recent activity first."""
        query = "SELECT data, severity FROM incidents"
        parameters: list = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY last_seen DESC, incident_id DESC"
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(int(limit))

        rows = self.connect().execute(query, parameters).fetchall()
        incidents = [self._row_to_incident(row) for row in rows]
        incidents = [incident for incident in incidents if incident is not None]
        if min_severity:
            incidents = [
                incident
                for incident in incidents
                if Severity.at_least(incident.severity, min_severity)
            ]
        return incidents

    def active_incidents(self, reference: str | None, window_seconds: int) -> list[Incident]:
        """Incidents still open to correlation at ``reference`` time.

        "Active" means: the lifecycle status still accepts alerts *and* the last
        activity is within ``window_seconds``.  It says nothing about whether the
        incident was resolved -- that is a human decision, see the README.
        """
        moment = parse_timestamp(reference)
        if moment is None:
            return []
        cutoff = format_timestamp(moment - timedelta(seconds=max(0, window_seconds)))

        placeholders = ", ".join("?" for _ in IncidentStatus.ACTIVE)
        rows = (
            self.connect()
            .execute(
                f"SELECT data FROM incidents "
                f"WHERE status IN ({placeholders}) AND last_seen IS NOT NULL AND last_seen >= ? "
                f"ORDER BY last_seen ASC",
                (*IncidentStatus.ACTIVE, cutoff),
            )
            .fetchall()
        )
        return [incident for incident in map(self._row_to_incident, rows) if incident]

    def next_incident_number(self) -> int:
        """One past the highest incident number stored."""
        row = (
            self.connect()
            .execute("SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1")
            .fetchone()
        )
        if row is None:
            return 1
        digits = "".join(ch for ch in row["incident_id"] if ch.isdigit())
        return int(digits) + 1 if digits else 1

    def count(self) -> int:
        """How many incidents are stored."""
        row = self.connect().execute("SELECT COUNT(*) AS total FROM incidents").fetchone()
        return int(row["total"]) if row else 0

    def severity_counts(self) -> dict[str, int]:
        """Incident count per severity, computed in SQL.

        Added for the Phase 6 dashboard: counting in the database keeps the
        overview cheap, instead of deserializing every incident to add them up.
        """
        rows = self.connect().execute(
            "SELECT severity, COUNT(*) AS total FROM incidents GROUP BY severity"
        ).fetchall()
        return {row["severity"]: int(row["total"]) for row in rows}

    def status_counts(self) -> dict[str, int]:
        """Incident count per lifecycle status, computed in SQL."""
        rows = self.connect().execute(
            "SELECT status, COUNT(*) AS total FROM incidents GROUP BY status"
        ).fetchall()
        return {row["status"]: int(row["total"]) for row in rows}

    def revision_index(self) -> dict[str, str]:
        """Map of ``incident_id -> revision marker`` for every stored incident.

        The dashboard's watcher compares two of these to notice what changed
        without loading a single incident body.  The marker combines the save
        time with the columns that describe the incident's content, because
        ``updated_at`` has one-second resolution: two saves inside the same
        second would otherwise look identical.  ``length(data)`` is included so
        a change anywhere in the serialized incident -- a new timeline entry, an
        attached AI analysis -- shows up as well.

        Computed entirely in SQL: no incident body is deserialized.
        """
        rows = self.connect().execute(
            "SELECT incident_id, updated_at, status, severity, risk_score, "
            "alert_count, last_seen, length(data) AS size FROM incidents"
        ).fetchall()
        return {
            row["incident_id"]: "|".join(
                str(row[column])
                for column in (
                    "updated_at", "status", "severity", "risk_score",
                    "alert_count", "last_seen", "size",
                )
            )
            for row in rows
        }

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _row_to_incident(row) -> Incident | None:
        if row is None:
            return None
        try:
            return Incident.from_dict(json.loads(row["data"]))
        except (ValueError, KeyError, TypeError) as exc:  # pragma: no cover - corrupt row
            LOGGER.warning("skipping unreadable incident row: %s", exc)
            return None


class ResponseStore:
    """Stores response actions and their append-only audit trail (Phase 7).

    Shares the incident database file, so one investigation lives in one place.
    Opening a :class:`ResponseStore` creates the incident tables too (they come
    from the same schema script), which means a response-only process still
    produces a database the rest of SentinelForge can read.

    Use it as a context manager::

        with ResponseStore(path) as store:
            store.save_action(action)

    There is deliberately no method to update or delete an audit record.  The
    database refuses those operations as well; see the module docstring.
    """

    def __init__(self, path: str | None = None) -> None:
        self.path = path or default_database_path()
        self._connection: sqlite3.Connection | None = None

    # -- connection handling ----------------------------------------------
    def connect(self) -> sqlite3.Connection:
        if self._connection is not None:
            return self._connection
        if self.path != ":memory:":
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory:
                os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.executescript(_SCHEMA)
        connection.executescript(_RESPONSE_SCHEMA)
        connection.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        connection.commit()
        self._connection = connection
        return connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "ResponseStore":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- actions -----------------------------------------------------------
    def save_action(self, action) -> None:
        """Insert or update one action, keyed by ``action_id``."""
        connection = self.connect()
        connection.execute(
            """
            INSERT INTO response_actions (
                action_id, incident_id, action_type, target, status, dry_run,
                requested_by, requested_at, completed_at, updated_at, data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                incident_id = excluded.incident_id,
                action_type = excluded.action_type,
                target = excluded.target,
                status = excluded.status,
                dry_run = excluded.dry_run,
                requested_by = excluded.requested_by,
                requested_at = excluded.requested_at,
                completed_at = excluded.completed_at,
                updated_at = excluded.updated_at,
                data = excluded.data
            """,
            (
                action.action_id,
                action.incident_id,
                action.action_type,
                action.target,
                action.status,
                1 if action.dry_run else 0,
                action.requested_by,
                action.requested_at,
                action.completed_at,
                utc_now(),
                json.dumps(action.to_dict(), ensure_ascii=False),
            ),
        )
        connection.commit()

    def get_action(self, action_id: str):
        """Load one action by id, or ``None``."""
        row = (
            self.connect()
            .execute("SELECT data FROM response_actions WHERE action_id = ?", (action_id,))
            .fetchone()
        )
        return self._row_to_action(row)

    def list_actions(
        self,
        incident_id: str | None = None,
        status: str | None = None,
        action_type: str | None = None,
        target: str | None = None,
        include_dry_run: bool = True,
        limit: int | None = None,
    ) -> list:
        """List actions, most recently requested first."""
        query = "SELECT data FROM response_actions"
        conditions: list[str] = []
        parameters: list = []
        if incident_id:
            conditions.append("incident_id = ?")
            parameters.append(incident_id)
        if status:
            conditions.append("status = ?")
            parameters.append(status)
        if action_type:
            conditions.append("action_type = ?")
            parameters.append(action_type)
        if target:
            conditions.append("target = ?")
            parameters.append(target)
        if not include_dry_run:
            conditions.append("dry_run = 0")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY requested_at DESC, action_id DESC"
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(int(limit))
        rows = self.connect().execute(query, parameters).fetchall()
        return [action for action in map(self._row_to_action, rows) if action is not None]

    def next_action_number(self) -> int:
        """One past the highest action number stored."""
        row = (
            self.connect()
            .execute("SELECT action_id FROM response_actions ORDER BY action_id DESC LIMIT 1")
            .fetchone()
        )
        if row is None:
            return 1
        digits = "".join(ch for ch in row["action_id"] if ch.isdigit())
        return int(digits) + 1 if digits else 1

    def action_count(self, incident_id: str | None = None) -> int:
        if incident_id:
            row = self.connect().execute(
                "SELECT COUNT(*) AS total FROM response_actions WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        else:
            row = self.connect().execute(
                "SELECT COUNT(*) AS total FROM response_actions"
            ).fetchone()
        return int(row["total"]) if row else 0

    def status_counts(self) -> dict[str, int]:
        """Action count per status, computed in SQL."""
        rows = self.connect().execute(
            "SELECT status, COUNT(*) AS total FROM response_actions GROUP BY status"
        ).fetchall()
        return {row["status"]: int(row["total"]) for row in rows}

    # -- audit trail -------------------------------------------------------
    def append_audit(self, entry) -> str:
        """Append one audit record and return its chain hash.

        The record is hashed together with the hash of the record before it, so
        the trail is verifiable as a whole: editing or dropping a row breaks
        every hash after it.
        """
        connection = self.connect()
        previous = self.last_audit_hash()
        payload = entry.to_dict()
        entry_hash = entry.compute_hash(previous)
        connection.execute(
            """
            INSERT INTO response_audit (
                audit_id, timestamp, event, action_id, incident_id, action_type,
                target, requested_by, approved_by, reason, policy_decision, dry_run,
                execution_status, result, error, rollback_available,
                previous_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["audit_id"],
                payload["timestamp"],
                payload["event"],
                payload["action_id"],
                payload["incident_id"],
                payload["action_type"],
                payload["target"],
                payload["requested_by"],
                payload["approved_by"],
                payload["reason"],
                json.dumps(payload["policy_decision"], ensure_ascii=False)
                if payload["policy_decision"] is not None
                else None,
                1 if payload["dry_run"] else 0,
                payload["execution_status"],
                json.dumps(payload["result"], ensure_ascii=False)
                if payload["result"] is not None
                else None,
                payload["error"],
                1 if payload["rollback_available"] else 0,
                previous,
                entry_hash,
            ),
        )
        connection.commit()
        return entry_hash

    def last_audit_hash(self) -> str | None:
        row = (
            self.connect()
            .execute("SELECT entry_hash FROM response_audit ORDER BY sequence DESC LIMIT 1")
            .fetchone()
        )
        return row["entry_hash"] if row else None

    def list_audit(
        self,
        action_id: str | None = None,
        incident_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Audit records, newest first, as plain dicts."""
        query = "SELECT * FROM response_audit"
        conditions: list[str] = []
        parameters: list = []
        if action_id:
            conditions.append("action_id = ?")
            parameters.append(action_id)
        if incident_id:
            conditions.append("incident_id = ?")
            parameters.append(incident_id)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY sequence DESC"
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(int(limit))
        return [self._row_to_audit(row) for row in self.connect().execute(query, parameters)]

    def audit_count(self) -> int:
        row = self.connect().execute("SELECT COUNT(*) AS total FROM response_audit").fetchone()
        return int(row["total"]) if row else 0

    def next_audit_number(self) -> int:
        row = self.connect().execute(
            "SELECT MAX(sequence) AS top FROM response_audit"
        ).fetchone()
        top = row["top"] if row else None
        return int(top) + 1 if top else 1

    def verify_audit_chain(self) -> dict:
        """Re-hash the whole trail and report the first record that disagrees.

        Tamper *evidence*, not tamper proofing: someone with write access to the
        file can rewrite every subsequent hash too.  What it catches is the
        realistic case -- a row edited or deleted in place -- and it makes that
        visible rather than silent.
        """
        from ..response.audit import AuditRecord

        previous = None
        checked = 0
        for row in self.connect().execute("SELECT * FROM response_audit ORDER BY sequence ASC"):
            entry = self._row_to_audit(row)
            expected = AuditRecord.from_dict(entry).compute_hash(previous)
            if row["previous_hash"] != previous or row["entry_hash"] != expected:
                return {
                    "ok": False,
                    "checked": checked,
                    "total": self.audit_count(),
                    "broken_at": entry["audit_id"],
                    "detail": "an audit record does not match the hash chain: the trail "
                    "has been modified outside SentinelForge",
                }
            previous = row["entry_hash"]
            checked += 1
        return {"ok": True, "checked": checked, "total": checked, "broken_at": None,
                "detail": "every audit record matches the hash chain"}

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _row_to_action(row):
        if row is None:
            return None
        from ..response.models import ResponseAction

        try:
            return ResponseAction.from_dict(json.loads(row["data"]))
        except (ValueError, KeyError, TypeError) as exc:  # pragma: no cover - corrupt row
            LOGGER.warning("skipping unreadable response action row: %s", exc)
            return None

    @staticmethod
    def _row_to_audit(row) -> dict:
        def _json(value):
            if value in (None, ""):
                return None
            try:
                return json.loads(value)
            except ValueError:  # pragma: no cover - corrupt row
                return None

        return {
            "sequence": int(row["sequence"]),
            "audit_id": row["audit_id"],
            "timestamp": row["timestamp"],
            "event": row["event"],
            "action_id": row["action_id"],
            "incident_id": row["incident_id"],
            "action_type": row["action_type"],
            "target": row["target"],
            "requested_by": row["requested_by"],
            "approved_by": row["approved_by"],
            "reason": row["reason"],
            "policy_decision": _json(row["policy_decision"]),
            "dry_run": bool(row["dry_run"]),
            "execution_status": row["execution_status"],
            "result": _json(row["result"]),
            "error": row["error"],
            "rollback_available": bool(row["rollback_available"]),
            "previous_hash": row["previous_hash"],
            "entry_hash": row["entry_hash"],
        }
