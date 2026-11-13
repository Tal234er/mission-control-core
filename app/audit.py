"""T04: append-only audit log with a hash chain.

Every entry stores the hash of the previous entry, so any change or removal is
detectable by verify(). Database triggers block UPDATE and DELETE on the table.
Entries record what happened, never the content of a payload.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(prev_hash, ts, actor, action, target, detail):
    canonical = json.dumps(
        {"prev": prev_hash, "ts": ts, "actor": actor, "action": action,
         "target": target, "detail": detail},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, db):
        """db: a sqlite3 connection, or a path to a database file."""
        self.db = db if isinstance(db, sqlite3.Connection) else sqlite3.connect(db)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS audit_no_update
            BEFORE UPDATE ON audit
            BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete
            BEFORE DELETE ON audit
            BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
            """
        )
        self.db.commit()

    def _last_hash(self):
        row = self.db.execute(
            "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def append(self, actor, action, target, detail=None):
        detail = detail or {}
        ts = _now()
        prev = self._last_hash()
        detail_json = json.dumps(detail, sort_keys=True)
        h = _digest(prev, ts, actor, action, target, detail)
        with self.db:
            cur = self.db.execute(
                "INSERT INTO audit (ts, actor, action, target, detail, prev_hash, hash) "
                "VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, target, detail_json, prev, h))
        return cur.lastrowid

    def entries(self):
        rows = self.db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def verify(self):
        """Return (True, None) if the chain is intact, else (False, seq of first bad entry)."""
        prev = GENESIS
        for e in self.entries():
            if e["prev_hash"] != prev:
                return False, e["seq"]
            expected = _digest(prev, e["ts"], e["actor"], e["action"],
                               e["target"], e["detail"])
            if expected != e["hash"]:
                return False, e["seq"]
            prev = e["hash"]
        return True, None
