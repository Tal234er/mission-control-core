import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.privacy import PrivacyGateway, classify, classify_text, redact  # noqa
from app.records import RecordStore  # noqa


class ClassifyTests(unittest.TestCase):
    def test_open_business_text(self):
        self.assertEqual(classify("LinkedIn planning target: 10,000 followers"), "open")
        self.assertEqual(classify({"target": 10000}), "open")

    def test_email_and_phone_are_personal(self):
        self.assertEqual(classify("write to someone@example.com"), "personal")
        # A spaced international number has the same digit pattern as a card
        # number, so the gateway treats it as restricted (conservative default).
        self.assertEqual(classify("call +234 801 234 5678"), "restricted")
        self.assertEqual(classify("call +234-801-234-5678 today"), "restricted")
        self.assertEqual(classify("write to a@b.co"), "personal")

    def test_bank_and_card_are_restricted(self):
        self.assertEqual(classify("account number 0123456789"), "restricted")
        self.assertEqual(classify("card 4111 1111 1111 1111"), "restricted")
        self.assertEqual(classify("bank transfer details"), "restricted")

    def test_identity_documents_are_restricted(self):
        self.assertEqual(classify("passport copy attached"), "restricted")
        self.assertEqual(classify("CPF 123.456.789-09"), "restricted")

    def test_health_is_restricted(self):
        self.assertEqual(classify("medical appointment on Friday"), "restricted")

    def test_family_details_are_restricted(self):
        self.assertEqual(classify("my mother arrives in February"), "restricted")

    def test_secrets_are_restricted(self):
        self.assertEqual(classify("api key sk-abc"), "restricted")
        self.assertEqual(classify("mcp_token=abc123"), "restricted")

    def test_restricted_wins_in_nested_data(self):
        payload = {"a": {"b": ["fine", {"c": "passport scan"}]}}
        self.assertEqual(classify(payload), "restricted")

    def test_unknown_text_defaults_to_open(self):
        self.assertEqual(classify_text("launch the offer on Monday"), "open")


class RedactTests(unittest.TestCase):
    def test_redacts_email_phone_and_numbers(self):
        out = redact("mail a@b.com, call 08012345678, ref 1234567890")
        self.assertNotIn("a@b.com", out)
        self.assertNotIn("08012345678", out)
        self.assertNotIn("1234567890", out)

    def test_redacts_tokens_in_urls(self):
        out = redact("https://x.test/?mcp_token=abc123&ok=1")
        self.assertNotIn("abc123", out)
        self.assertIn("ok=1", out)

    def test_redact_does_not_touch_the_original(self):
        original = {"note": "a@b.com"}
        redact(original)
        self.assertEqual(original["note"], "a@b.com")


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.gw = PrivacyGateway()

    def test_restricted_never_leaves_anywhere(self):
        for dest in ["external_ai", "shared_store"]:
            r = self.gw.check({"x": "passport"}, dest)
            self.assertEqual(r["decision"], "deny")
            self.assertIsNone(r["payload"])

    def test_personal_is_denied_externally(self):
        r = self.gw.check("someone@example.com", "external_ai")
        self.assertEqual(r["decision"], "deny")

    def test_open_is_allowed_and_redacted(self):
        r = self.gw.check({"note": "target 10000 by 28 Jan"}, "external_ai")
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["payload"], {"note": "target 10000 by 28 Jan"})

    def test_unknown_destination_is_denied(self):
        r = self.gw.check("open text", "random_site")
        self.assertEqual(r["decision"], "deny")

    def test_bypass_attempt_with_nesting_is_denied(self):
        r = self.gw.check({"items": [{"deep": {"s": "bank account"}}]}, "shared_store")
        self.assertEqual(r["decision"], "deny")

    def test_every_decision_is_logged_without_payload(self):
        self.gw.check("passport", "external_ai")
        self.gw.check("plan", "external_ai")
        self.assertEqual(len(self.gw.log), 2)
        for entry in self.gw.log:
            self.assertNotIn("payload", entry)
            self.assertNotIn("passport", str(entry))


class StoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = RecordStore(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_store_refuses_restricted_content_in_body(self):
        with self.assertRaises(ValueError):
            self.store.create("note", "x", {"text": "bank account 0123456789"},
                              status="observed", source="s")

    def test_store_accepts_open_content(self):
        rid = self.store.create("goal", "sprint", {"target": 10000},
                                status="confirmed", source="interview")
        self.assertEqual(self.store.get(rid)["body"], {"target": 10000})


if __name__ == "__main__":
    unittest.main()
