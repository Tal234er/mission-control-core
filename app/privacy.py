"""T03: privacy gateway. Classify, redact, allow or deny outbound data.

Default-deny. Restricted data never leaves the device and is refused by the
record store. Personal data is never sent to external AI or shared stores.
Only open data may leave, and only after redaction. Every decision is logged
without the payload.
"""
import copy
import re

DESTINATIONS = {"external_ai", "shared_store"}  # Notion, Sheets, external AI

# Restricted: the never-store list (family, health, bank/card, identity, secrets).
_RESTRICTED = [
    r"\b\d{10,}\b",                      # account, card or ID-like digit runs
    r"\b(?:\d[ -]?){13,19}\b",           # card-like digit groups
    r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",    # CPF
    r"\b(?:bank|account number|card number|cvv|routing|iban|sort code)\b",
    r"\b(?:bvn|nin|passport|national id|identity document)\b",
    r"\b(?:password|passcode|api[ _-]?key|secret|access token|mcp_token|bearer)\b",
    r"\b(?:medical|diagnos\w*|health|pregnan\w*|hospital|prescription)\b",
    r"\b(?:mother|mum|mom|grandmother|grandma|grandpa|father|dad|wife|husband|"
    r"son|daughter|baby|children|child|sister|brother)\b",
]
# Personal: contact details and similar, never sent to shared stores or AI.
_PERSONAL = [
    r"[\w.+-]+@[\w-]+\.[\w.-]+",         # email address
    r"(?:\+|00)\d[\d ()-]{7,}\d",        # international phone
    r"\b0\d{9,10}\b",                    # local phone
]
_RESTRICTED_RE = [re.compile(p, re.IGNORECASE) for p in _RESTRICTED]
_PERSONAL_RE = [re.compile(p, re.IGNORECASE) for p in _PERSONAL]

_REDACTIONS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[email removed]"),
    (re.compile(r"(?:\+|00)\d[\d ()-]{7,}\d"), "[phone removed]"),
    (re.compile(r"\b0\d{9,10}\b"), "[phone removed]"),
    (re.compile(r"\b\d{10,}\b"), "[number removed]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[number removed]"),
    (re.compile(r"(mcp_token|access_token|api[_-]?key|token)=[^&\s]+", re.I),
     r"\1=[removed]"),
]


def _strings(value):
    """Yield every string inside a nested structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item)
    elif value is not None and not isinstance(value, (int, float, bool)):
        yield str(value)


def classify_text(text):
    if any(p.search(text) for p in _RESTRICTED_RE):
        return "restricted"
    if any(p.search(text) for p in _PERSONAL_RE):
        return "personal"
    return "open"


def classify(value):
    """Most sensitive class found anywhere in a value (default open)."""
    order = {"open": 0, "personal": 1, "restricted": 2}
    worst = "open"
    for s in _strings(value):
        c = classify_text(s)
        if order[c] > order[worst]:
            worst = c
    return worst


def redact_text(text):
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def redact(value):
    """Return a copy with identifiers removed from every string."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v) for v in value)
    return copy.deepcopy(value)


class PrivacyGateway:
    def __init__(self, audit=None):
        self.log = []  # decisions only; never the payload
        self.audit = audit  # optional AuditLog (T04)

    def check(self, payload, destination):
        if destination not in DESTINATIONS:
            return self._record(destination, "deny", "unknown destination", None)
        cls = classify(payload)
        if cls == "restricted":
            return self._record(destination, "deny",
                                "restricted data never leaves the device", cls)
        if cls == "personal":
            return self._record(destination, "deny",
                                "personal data is not sent to this destination", cls)
        # open data: allowed, but still redacted before it leaves
        clean = redact(payload)
        return self._record(destination, "allow", "open data, redacted", cls, clean)

    def _record(self, destination, decision, reason, cls, payload=None):
        entry = {"destination": destination, "decision": decision,
                 "reason": reason, "class": cls}
        self.log.append(entry)
        if self.audit is not None:
            self.audit.append("gateway", "outbound_" + decision, destination,
                              {"reason": reason, "class": cls})
        return {"decision": decision, "reason": reason, "class": cls,
                "payload": payload}
