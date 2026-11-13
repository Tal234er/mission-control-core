"""T05: single-user access control.

- One owner. Setup can run once; a second account cannot be created.
- The passcode is stored only as a salted PBKDF2 hash, in a file outside the repository.
- Sessions expire after an idle timeout. Failed logins are throttled.
- Every login, failure, lock and logout is written to the audit log when one is given.
"""
import hashlib
import hmac
import json
import os
import secrets
import time

ITERATIONS = 310_000
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300
IDLE_TIMEOUT_SECONDS = 15 * 60


class AccessError(Exception):
    pass


def _hash(passcode, salt):
    return hashlib.pbkdf2_hmac("sha256", passcode.encode("utf-8"), salt,
                               ITERATIONS)


class Access:
    def __init__(self, config_path, audit=None, clock=time.time,
                 idle_timeout=IDLE_TIMEOUT_SECONDS):
        self.config_path = config_path
        self.audit = audit
        self.clock = clock
        self.idle_timeout = idle_timeout
        self.sessions = {}     # token -> last-seen time
        self.failures = 0
        self.locked_until = 0.0

    # ---- configuration ---------------------------------------------
    def is_configured(self):
        return os.path.exists(self.config_path)

    def setup(self, passcode):
        if self.is_configured():
            raise AccessError("owner already set up; a second account cannot be created")
        if len(passcode) < 8:
            raise AccessError("passcode must be at least 8 characters")
        salt = secrets.token_bytes(16)
        data = {"salt": salt.hex(), "hash": _hash(passcode, salt).hex(),
                "iterations": ITERATIONS}
        os.makedirs(os.path.dirname(self.config_path) or ".", exist_ok=True)
        fd = os.open(self.config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        self._log("setup", {})

    def _load(self):
        with open(self.config_path) as f:
            return json.load(f)

    # ---- login and sessions ----------------------------------------
    def login(self, passcode):
        now = self.clock()
        if now < self.locked_until:
            self._log("login_refused", {"reason": "locked"})
            raise AccessError("locked after too many failed attempts; wait and retry")
        if not self.is_configured():
            raise AccessError("owner is not set up")
        cfg = self._load()
        salt = bytes.fromhex(cfg["salt"])
        ok = hmac.compare_digest(_hash(passcode, salt), bytes.fromhex(cfg["hash"]))
        if not ok:
            self.failures += 1
            self._log("login_failed", {"count": self.failures})
            if self.failures >= MAX_FAILURES:
                self.locked_until = now + LOCKOUT_SECONDS
                self.failures = 0
                self._log("locked", {"seconds": LOCKOUT_SECONDS})
            raise AccessError("wrong passcode")
        self.failures = 0
        token = secrets.token_urlsafe(32)
        self.sessions[token] = now
        self._log("login", {})
        return token

    def check(self, token):
        last = self.sessions.get(token)
        if last is None:
            return False
        if self.clock() - last > self.idle_timeout:
            del self.sessions[token]
            self._log("session_expired", {})
            return False
        self.sessions[token] = self.clock()
        return True

    def logout(self, token):
        if self.sessions.pop(token, None) is not None:
            self._log("logout", {})

    def _log(self, action, detail):
        if self.audit is not None:
            self.audit.append("owner", "access_" + action, "owner", detail)
