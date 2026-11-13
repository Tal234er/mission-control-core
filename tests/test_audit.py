import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.audit import AuditLog  # noqa
from app.privacy import PrivacyGateway  # noqa
from app.records import RecordStore  # noqa


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.db")
        self.log = AuditLog(self.path)

    def tearDown(self):
        self.log.db.close()
        self.tmp.cleanup()

    def test_appends_in_order_and_verifies(self):
        self.log.append("owner", "create", "r1", {"x": 1})
        self.log.append("owner", "update", "r1", {"x": 2})
        self.assertEqual([e["seq"] for e in self.log.entries()], [1, 2])
        self.assertEqual(self.log.verify(), (True, None))

    def test_update_and_delete_are_blocked(self):
        self.log.append("owner", "create", "r1")
        with self.assertRaises(sqlite3.DatabaseError):
            self.log.db.execute("UPDATE audit SET actor='x' WHERE seq=1")
        with self.assertRaises(sqlite3.DatabaseError):
            self.log.db.execute("DELETE FROM audit WHERE seq=1")

    def test_tampering_is_detected_when_triggers_are_bypassed(self):
        self.log.append("owner", "create", "r1", {"x": 1})
        self.log.append("owner", "update", "r1", {"x": 2})
        # Simulate an attacker who removes the guard and edits history.
        self.log.db.execute("DROP TRIGGER audit_no_update")
        self.log.db.execute("UPDATE audit SET detail='{\"x\": 99}' WHERE seq=1")
        self.log.db.commit()
        ok, bad = self.log.verify()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_deleted_entry_is_detected(self):
        self.log.append("owner", "a", "t")
        self.log.append("owner", "b", "t")
        self.log.append("owner", "c", "t")
        self.log.db.execute("DROP TRIGGER audit_no_delete")
        self.log.db.execute("DELETE FROM audit WHERE seq=2")
        self.log.db.commit()
        ok, _ = self.log.verify()
        self.assertFalse(ok)

    def test_log_never_stores_payload_content_for_gateway(self):
        gw = PrivacyGateway(audit=self.log)
        gw.check({"note": "passport scan"}, "external_ai")
        entries = self.log.entries()
        self.assertEqual(len(entries), 1)
        self.assertNotIn("passport", str(entries[0]))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(os.path.join(self.tmp.name, "a.db"))
        self.store = RecordStore(os.path.join(self.tmp.name, "r.db"),
                                 audit=self.audit)

    def tearDown(self):
        self.store.close()
        self.audit.db.close()
        self.tmp.cleanup()

    def test_create_and_update_are_logged(self):
        rid = self.store.create("goal", "sprint", {"t": 1},
                                status="confirmed", source="interview")
        self.store.update(rid, {"t": 2}, reason="changed")
        actions = [e["action"] for e in self.audit.entries()]
        self.assertEqual(actions, ["create", "update"])
        self.assertEqual(self.audit.verify(), (True, None))

    def test_decision_supersede_is_logged(self):
        old = self.store.create("decision", "Price", {"a": 1},
                                status="confirmed", source="interview")
        self.store.supersede(old, {"a": 2}, reason="new ladder",
                             source="interview")
        self.assertIn("supersede", [e["action"] for e in self.audit.entries()])

    def test_reading_personal_record_is_logged(self):
        rid = self.store.create("note", "family plan", {"x": 1},
                                status="observed", source="s",
                                sensitivity="personal")
        self.store.get(rid)
        self.assertEqual(self.audit.entries()[-1]["action"], "read")

    def test_reading_open_record_is_not_logged(self):
        rid = self.store.create("goal", "open", {"x": 1},
                                status="confirmed", source="s")
        before = len(self.audit.entries())
        self.store.get(rid)
        self.assertEqual(len(self.audit.entries()), before)

    def test_store_works_without_audit(self):
        plain = RecordStore(os.path.join(self.tmp.name, "p.db"))
        rid = plain.create("goal", "g", {}, status="confirmed", source="s")
        self.assertEqual(plain.get(rid)["title"], "g")
        plain.close()


if __name__ == "__main__":
    unittest.main()
