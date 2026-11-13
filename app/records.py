"""T02: record store with provenance, versions and append-only decisions.

Rules enforced here (and tested):
- every record has a source and a status;
- restricted data is never stored;
- updates create a new version and keep the old one;
- decisions are append-only: they can be superseded, never edited or removed.
"""
import json
import sqlite3
from app.privacy import classify
import uuid
from datetime import datetime, timezone

STATUSES = {"confirmed", "working", "claimed", "observed", "to_confirm"}
SENSITIVITY = {"open", "personal"}  # "restricted" is refused outright (see T03)
APPEND_ONLY_TYPES = {"decision"}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RecordStore:
    def __init__(self, path, audit=None):
        self.path = path
        self.audit = audit
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                owner TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                current_version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS versions (
                record_id TEXT NOT NULL REFERENCES records(id),
                version INTEGER NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                reason TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                PRIMARY KEY (record_id, version)
            );
            CREATE TABLE IF NOT EXISTS links (
                from_id TEXT NOT NULL REFERENCES records(id),
                to_id TEXT NOT NULL REFERENCES records(id),
                relation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (from_id, to_id, relation)
            );
            """
        )
        self.db.commit()

    # ---- validation -------------------------------------------------
    @staticmethod
    def _validate_new(type_, title, status, source, sensitivity, body_class="open"):
        if not type_ or not title:
            raise ValueError("type and title are required")
        if sensitivity == "restricted":
            raise ValueError("restricted data is never stored")
        if body_class == "restricted":
            raise ValueError("restricted content is never stored")
        if sensitivity not in SENSITIVITY:
            raise ValueError(f"unknown sensitivity: {sensitivity}")
        if status not in STATUSES:
            raise ValueError(f"unknown status: {status}")
        if not source or not str(source).strip():
            raise ValueError("a source is required for every record")

    # ---- create -----------------------------------------------------
    def create(self, type_, title, body, *, status, source,
               sensitivity="open", owner="owner"):
        self._validate_new(type_, title, status, source, sensitivity,
                           classify(body) if body is not None else "open")
        rid = str(uuid.uuid4())
        now = _now()
        with self.db:
            self.db.execute(
                "INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?)",
                (rid, type_, title, status, source, sensitivity, owner,
                 now, now, 1),
            )
            self.db.execute(
                "INSERT INTO versions VALUES (?,?,?,?,?,?,?)",
                (rid, 1, json.dumps(body), status, source, "created", now),
            )
        self._log("create", rid, {"type": type_, "status": status})
        return rid

    def _log(self, action, rid, detail):
        if self.audit is not None:
            self.audit.append("owner", action, rid, detail)

    # ---- update (versioned) ----------------------------------------
    def update(self, rid, body, *, reason, status=None, source=None):
        rec = self._row(rid)
        if rec["type"] in APPEND_ONLY_TYPES:
            raise PermissionError(
                f"{rec['type']} records are append-only; use supersede()")
        if not reason or not reason.strip():
            raise ValueError("a reason is required for every change")
        new_status = status or rec["status"]
        new_source = source or rec["source"]
        if new_status not in STATUSES:
            raise ValueError(f"unknown status: {new_status}")
        version = rec["current_version"] + 1
        now = _now()
        with self.db:
            self.db.execute(
                "INSERT INTO versions VALUES (?,?,?,?,?,?,?)",
                (rid, version, json.dumps(body), new_status, new_source,
                 reason, now),
            )
            self.db.execute(
                "UPDATE records SET status=?, source=?, updated_at=?, "
                "current_version=? WHERE id=?",
                (new_status, new_source, now, version, rid),
            )
        self._log("update", rid, {"version": version, "reason": reason})
        return version

    # ---- decisions: supersede, never edit ---------------------------
    def supersede(self, old_id, body, *, reason, source, status="confirmed",
                  owner="owner"):
        old = self._row(old_id)
        if old["type"] != "decision":
            raise ValueError("only decisions are superseded")
        new_id = self.create("decision", body.get("title", old["title"]),
                             body, status=status, source=source,
                             owner=owner)
        with self.db:
            self.db.execute(
                "INSERT INTO links VALUES (?,?,?,?)",
                (new_id, old_id, "supersedes", _now()),
            )
        self._log("supersede", new_id, {"supersedes": old_id, "reason": reason})
        with self.db:
            # record the reason on the new decision's first version
            self.db.execute(
                "UPDATE versions SET reason=? WHERE record_id=? AND version=1",
                (reason, new_id),
            )
        return new_id

    # ---- read -------------------------------------------------------
    def _row(self, rid):
        row = self.db.execute(
            "SELECT * FROM records WHERE id=?", (rid,)).fetchone()
        if row is None:
            raise KeyError(f"no record {rid}")
        return row

    def get(self, rid, version=None):
        rec = dict(self._row(rid))
        v = version or rec["current_version"]
        ver = self.db.execute(
            "SELECT * FROM versions WHERE record_id=? AND version=?",
            (rid, v)).fetchone()
        if ver is None:
            raise KeyError(f"no version {v} for {rid}")
        rec["version"] = v
        rec["body"] = json.loads(ver["body"])
        if rec["sensitivity"] == "personal":
            self._log("read", rid, {"version": v, "sensitivity": "personal"})
        return rec

    def history(self, rid):
        rows = self.db.execute(
            "SELECT version, status, source, reason, changed_at FROM versions "
            "WHERE record_id=? ORDER BY version", (rid,)).fetchall()
        return [dict(r) for r in rows]

    def links_from(self, rid, relation=None):
        if relation:
            rows = self.db.execute(
                "SELECT to_id FROM links WHERE from_id=? AND relation=?",
                (rid, relation)).fetchall()
        else:
            rows = self.db.execute(
                "SELECT to_id, relation FROM links WHERE from_id=?",
                (rid,)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.db.close()
