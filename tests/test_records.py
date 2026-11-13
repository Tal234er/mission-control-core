import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.records import RecordStore  # noqa: E402


class RecordStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "test.db")
        self.store = RecordStore(self.path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_create_requires_source_and_status(self):
        with self.assertRaises(ValueError):
            self.store.create("goal", "x", {}, status="confirmed", source="")
        with self.assertRaises(ValueError):
            self.store.create("goal", "x", {}, status="maybe", source="s")

    def test_restricted_data_is_never_stored(self):
        with self.assertRaises(ValueError):
            self.store.create("note", "x", {}, status="observed",
                              source="s", sensitivity="restricted")

    def test_create_and_read_back(self):
        rid = self.store.create("goal", "$10k sprint", {"target": 10000},
                                status="confirmed", source="interview 13 Nov")
        rec = self.store.get(rid)
        self.assertEqual(rec["body"], {"target": 10000})
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["version"], 1)

    def test_update_creates_version_and_keeps_old(self):
        rid = self.store.create("goal", "$10k", {"received": 0},
                                status="working", source="plan")
        self.store.update(rid, {"received": 1500}, reason="first sale paid")
        self.assertEqual(self.store.get(rid)["body"], {"received": 1500})
        self.assertEqual(self.store.get(rid, version=1)["body"], {"received": 0})
        self.assertEqual([h["version"] for h in self.store.history(rid)], [1, 2])

    def test_update_requires_reason(self):
        rid = self.store.create("goal", "g", {}, status="working", source="s")
        with self.assertRaises(ValueError):
            self.store.update(rid, {}, reason="  ")

    def test_decisions_cannot_be_edited(self):
        rid = self.store.create("decision", "Refund rule", {"refund": 0.5},
                                status="confirmed", source="interview")
        with self.assertRaises(PermissionError):
            self.store.update(rid, {"refund": 1.0}, reason="changed my mind")

    def test_decisions_are_superseded_and_linked(self):
        old = self.store.create("decision", "Price", {"ladder": "old"},
                                status="confirmed", source="interview")
        new = self.store.supersede(old, {"title": "Price", "ladder": "new"},
                                   reason="ladder confirmed", source="interview")
        self.assertEqual(self.store.get(old)["body"], {"ladder": "old"})
        self.assertEqual(self.store.links_from(new, "supersedes"),
                         [{"to_id": old}])

    def test_supersede_refuses_non_decisions(self):
        rid = self.store.create("goal", "g", {}, status="working", source="s")
        with self.assertRaises(ValueError):
            self.store.supersede(rid, {}, reason="r", source="s")

    def test_persists_across_reopen(self):
        rid = self.store.create("goal", "persist", {"a": 1},
                                status="confirmed", source="s")
        self.store.close()
        self.store = RecordStore(self.path)
        self.assertEqual(self.store.get(rid)["body"], {"a": 1})

    def test_unknown_record_raises(self):
        with self.assertRaises(KeyError):
            self.store.get("does-not-exist")


if __name__ == "__main__":
    unittest.main()
