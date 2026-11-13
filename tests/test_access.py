import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.access import Access, AccessError, IDLE_TIMEOUT_SECONDS, LOCKOUT_SECONDS, MAX_FAILURES  # noqa
from app.audit import AuditLog  # noqa


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = os.path.join(self.tmp.name, "owner.json")
        self.clock = Clock()
        self.audit = AuditLog(os.path.join(self.tmp.name, "audit.db"))
        self.acc = Access(self.cfg, audit=self.audit, clock=self.clock)
        self.acc.setup("correct horse battery")

    def tearDown(self):
        self.audit.db.close()
        self.tmp.cleanup()

    def test_setup_runs_once_only(self):
        with self.assertRaises(AccessError):
            self.acc.setup("another passcode")

    def test_short_passcode_refused(self):
        other = Access(os.path.join(self.tmp.name, "x.json"), clock=self.clock)
        with self.assertRaises(AccessError):
            other.setup("short")

    def test_passcode_is_not_stored_in_plain_text(self):
        with open(self.cfg) as f:
            content = f.read()
        self.assertNotIn("correct horse battery", content)

    def test_config_file_is_private(self):
        mode = os.stat(self.cfg).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_correct_passcode_logs_in(self):
        token = self.acc.login("correct horse battery")
        self.assertTrue(self.acc.check(token))

    def test_wrong_passcode_refused(self):
        with self.assertRaises(AccessError):
            self.acc.login("wrong wrong wrong")

    def test_unknown_token_refused(self):
        self.assertFalse(self.acc.check("made-up-token"))

    def test_session_expires_after_idle_timeout(self):
        token = self.acc.login("correct horse battery")
        self.clock.now += IDLE_TIMEOUT_SECONDS + 1
        self.assertFalse(self.acc.check(token))

    def test_activity_keeps_session_alive(self):
        token = self.acc.login("correct horse battery")
        for _ in range(3):
            self.clock.now += IDLE_TIMEOUT_SECONDS - 60
            self.assertTrue(self.acc.check(token))

    def test_logout_ends_session(self):
        token = self.acc.login("correct horse battery")
        self.acc.logout(token)
        self.assertFalse(self.acc.check(token))

    def test_repeated_failures_lock_access(self):
        for _ in range(MAX_FAILURES):
            with self.assertRaises(AccessError):
                self.acc.login("wrong wrong wrong")
        with self.assertRaises(AccessError):
            self.acc.login("correct horse battery")  # locked, even if correct

    def test_lock_lifts_after_wait(self):
        for _ in range(MAX_FAILURES):
            with self.assertRaises(AccessError):
                self.acc.login("wrong wrong wrong")
        self.clock.now += LOCKOUT_SECONDS + 1
        token = self.acc.login("correct horse battery")
        self.assertTrue(self.acc.check(token))

    def test_events_are_audited(self):
        token = self.acc.login("correct horse battery")
        self.acc.logout(token)
        with self.assertRaises(AccessError):
            self.acc.login("wrong wrong wrong")
        actions = [e["action"] for e in self.audit.entries()]
        self.assertIn("access_setup", actions)
        self.assertIn("access_login", actions)
        self.assertIn("access_logout", actions)
        self.assertIn("access_login_failed", actions)
        self.assertEqual(self.audit.verify(), (True, None))


if __name__ == "__main__":
    unittest.main()
