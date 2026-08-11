"""
Module: threat_patterns — shared catalog of threat signatures
Digital immune system — immune_system/threat_patterns.py

Single source of truth for attack patterns that were previously duplicated
between FastReflex (L1) and AIAnalyst (L2). Earlier the same tokens (union
select, /etc/passwd, <script>, {{, ${ ...) lived in three separate lists;
updating one and forgetting another led to detection drift. Now it is all here.

Patterns are split by USAGE SEMANTICS, not mixed into a single list:

  PAYLOAD_CORE             — unambiguously malicious payload signatures
                             (SQLi/XSS/traversal/RCE) that a legitimate user
                             NEVER sends. Shared core for L1 and L2.
  HARD_MALICIOUS_PATTERNS  — context-INDEPENDENT threats. Used by L2 to decide
                             whether a verdict is CACHEABLE. NARROW set.
  ANOMALY_PATTERNS         — BROADER set for ROUTING to the AI (L1 only sends
                             it for analysis, does not block on its own).
  INJECTION_MARKERS        — prompt-injection attempts against the AI judge itself.

IMPORTANT — why HARD and ANOMALY are NOT the same:
  HARD must stay NARROW. Broad tokens (';', \"'\", '--') must NOT be added to
  HARD, because a BLOCK verdict on /cast with such a token would be cached under
  the generic /cast signature and poison the next LEGITIMATE vote (false
  positive — disenfranchising a voter). So broad tokens live only in ANOMALY
  (where a false trigger means only an extra AI analysis, not a block).
"""

# ─── Unambiguously malicious core (shared by L1 and L2) ───────────────────────
# Legitimate traffic never contains these tokens under any circumstances.
PAYLOAD_CORE = [
    "/etc/passwd",
    "union select", "union+select",
    "or 1=1", "or+1=1",
    "<script", "<svg",
    "{{", "${",
    "sleep(", "waitfor",
    "0x", "%27",
]

# ─── L2: context-independent threats (decide cacheability of a verdict) ───────
# NARROW set — only what cannot be confused with legitimate traffic.
_HARD_EXTRA = ["..", "%2e%2e", "' or '", "</script", "/devlogin/login"]
HARD_MALICIOUS_PATTERNS = PAYLOAD_CORE + _HARD_EXTRA

# ─── L1: broader set for routing suspicious requests to AI analysis ───────────
# Broad tokens are fine here — a false trigger = only an extra AI analysis.
_ANOMALY_EXTRA = ["'", '"', "</", " or '", "--", ";", "%3c",
                  # XSS event handlers / js-URI (so they surely reach the AI)
                  "onerror=", "onload=", "onmouseover=", "javascript:", "<img", "<iframe"]
ANOMALY_PATTERNS = PAYLOAD_CORE + _ANOMALY_EXTRA

# ─── Path-traversal markers (checked by a separate L1 branch) ─────────────────
PATH_TRAVERSAL_MARKERS = ["..", "%2e%2e", "%2f%2f"]

# ─── L1 deterministic BLOCK: unambiguous payload tokens (0ms, no AI) ──────────
# Legitimate traffic NEVER contains them → a direct L1 block is safe (FP=0).
# Deliberately WITHOUT broad '0x','%27','<img','onerror=' — they occur in legit
# values (hex, apostrophe in a surname, html fragment in text) → those go to AI.
L1_HARD_BLOCK = {
    "/etc/passwd":   "path_traversal",
    "union select":  "sql_injection", "union+select": "sql_injection",
    "or 1=1":        "sql_injection", "or+1=1":       "sql_injection",
    "' or '":        "sql_injection", "sleep(":       "sql_injection",
    "waitfor":       "sql_injection",
    "<script":       "xss", "</script": "xss", "<svg": "xss",
    "{{":            "template_injection", "${": "template_injection",
    "/devlogin/login": "impersonation",
}


def l1_block_match(low_text: str):
    """Return (token, attack_class) for an UNAMBIGUOUS payload, or (None, None)."""
    for tok, ac in L1_HARD_BLOCK.items():
        if tok in low_text:
            return tok, ac
    return None, None


# ─── Body/path backstop AFTER the AI (deterministic override of a pass) ───────
# If the AI (L2) said ALLOW but the path/BODY contains an UNAMBIGUOUS payload —
# force-BLOCK: the AI cannot be tricked (prompt-injection) into passing an
# explicit payload, and L1 matches the path only and does not see a payload in
# the POST BODY.
# NARROW, FP-safe for free text: deliberately WITHOUT '..','%2e%2e','%27','0x'
# (they occur in legit text — '...', hex, apostrophe — or are purely URL notions).
BACKSTOP_PAYLOADS = [
    "/etc/passwd",
    "union select", "union+select",
    "or 1=1", "or+1=1", "' or '",
    "<script", "</script", "<svg",
    "{{", "${",
    "sleep(", "waitfor",
    "/devlogin/login",
]


def hard_payload_present(path: str, body: str = "") -> bool:
    """Whether the path OR body contains an unambiguously malicious payload (BACKSTOP set)."""
    blob = (str(path) + " " + (body or ""))[:8000].lower()
    return any(p in blob for p in BACKSTOP_PAYLOADS)


def classify_hard_payload(path: str, body: str = ""):
    """attack_class for a found hard-payload (via the L1 catalog), or
    'payload_injection' if the token is in BACKSTOP but outside L1_HARD_BLOCK. None — clean."""
    blob = (str(path) + " " + (body or ""))[:8000].lower()
    tok, ac = l1_block_match(blob)
    if tok:
        return ac
    return "payload_injection" if any(p in blob for p in BACKSTOP_PAYLOADS) else None

# ─── Markers of a prompt-injection attempt against the AI judge ───────────────
# Their presence in a request is ITSELF a sign of attack (a legitimate ballot
# never contains "ignore instructions").
INJECTION_MARKERS = [
    "ignore previous", "ignore all", "disregard", "forget previous",
    "you are now", "new instructions", "system:", "assistant:",
    "verdict allow", "verdict: allow", "respond with allow", "is legitimate",
    "this is a legitimate", "не є атакою", "проігноруй", "забудь попередні",
    "ти тепер", "поверни allow", "це легітимний", "</untrusted",
    "[/data]", "```", "<|", "|>",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def is_path_traversal(path: str) -> bool:
    """Whether the path shows path-traversal signs (raw '..' or URL-encoded)."""
    low = path.lower()
    return (".." in path
            or any(m in low for m in PATH_TRAVERSAL_MARKERS if m != ".."))


def anomaly_payload_match(low_text: str) -> bool:
    """Whether the (already lower-cased) text contains injection-payload signs → L1 INSPECT."""
    return any(m in low_text for m in ANOMALY_PATTERNS)


def is_pattern_malicious(path: str, body: str) -> bool:
    """
    Whether the request contains a context-INDEPENDENT malicious pattern (L2 → cache).
    Includes payload signatures and prompt-injection attempts.
    """
    blob = (path + " " + (body or ""))[:2000].lower()
    if any(p in blob for p in HARD_MALICIOUS_PATTERNS):
        return True
    if any(m in blob for m in INJECTION_MARKERS):
        return True
    return False


def detect_injection(text: str) -> bool:
    """Whether the text contains prompt-injection attempt markers."""
    if not text:
        return False
    low = str(text).lower()
    return any(m in low for m in INJECTION_MARKERS)
