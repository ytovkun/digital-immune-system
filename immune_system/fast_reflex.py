"""
Module: FastReflex — Layer 1 of the digital immune system
Digital immune system — immune_system/fast_reflex.py

Fast reflex layer (analogue of innate immunity).
Makes a decision in ~1ms based on:
  - signatures of sensitive endpoints + patterns
  - rate windows (sliding window of requests per IP)
  - concurrency detector (simultaneous POST /cast = race condition)

Returns a verdict: ALLOW / BLOCK / INSPECT
  ALLOW   — clearly safe, pass through
  BLOCK   — clear attack, drop instantly (403)
  INSPECT — suspicious but unclear → hand off to Layer 2 (AI analyst)
"""

import time
import threading
from collections import defaultdict, deque, OrderedDict

from threat_patterns import is_path_traversal, anomaly_payload_match, l1_block_match


# ─── Detection configuration ──────────────────────────────────────────────────

# Sensitive endpoints where attacks are possible
SENSITIVE_PATTERNS = {
    "/auth/devlogin/login":   "impersonation",
    "/upload-decryption":     "csrf_trustee_takeover",
    "/cast":                  "ballot_stuffing",
    "/password_voter_login":  "voter_suppression_targeted",
    "/auth/password/login":   "voter_phishing_credential",
    # critical admin operations of the election lifecycle → always to AI analysis
    "/encrypt_tally":         "tally_manipulation",
    "/freeze":                "manipulation",
    "/combine_decryptions":   "tally_manipulation",
}

# Rate limits (requests per window)
RATE_WINDOW_SEC = 10.0          # sliding window size
RATE_LIMITS = {
    "/cast":                 8,   # >8 casts per 10s = flood/race
    "/auth/password/login":  10,  # >10 logins per 10s = brute-force/suppression
    "/password_voter_login": 10,
    "/voters/":              15,  # >15 list requests = harvest (phishing recon)
    "/ballots/":             25,  # >25 per 10s = mass ballot collection (timing-deanon recon)
    "_default":              60,  # overall per-IP limit
}

# Admin-only tally operations: a legitimate VOTER never calls them → deterministic
# L1 block (not an "AI coin flip"). The AI remains for voter vote/login/behavior.
ADMIN_ONLY_ENDPOINTS = ("/encrypt_tally", "/freeze", "/combine_decryptions")

# Login endpoints: the rate limit is counted ONLY for POST (real login attempts).
# A GET of these paths shows the form (Helios itself redirects to it), not an attack.
LOGIN_ENDPOINTS = ("/auth/password/login", "/password_voter_login")

# Concurrency: simultaneous POST /cast from a single session
CONCURRENCY_WINDOW_SEC = 2.0    # requests within 2s are treated as "simultaneous"
CONCURRENCY_THRESHOLD = 3       # ≥3 casts per 2s from one session = race condition

MAX_TRACKED_KEYS = 20000        # window-dict cap (memory-DoS protection)
EVICT_EVERY = 2000              # how often to sweep dead keys


class FastReflex:
    """Fast reflex layer — decides in milliseconds, thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        # sliding timestamp windows: key=(ip, endpoint) → deque[timestamps]
        self._rate_windows = defaultdict(deque)
        # concurrency: key=(session, "/cast") → deque[timestamps]
        self._cast_windows = defaultdict(deque)
        self._req_since_evict = 0
        # Learned signatures: the AI (L2) synthesizes them from blocked NEW patterns,
        # and L1 blocks repeats instantly (0ms). Analogue of adaptive→innate immunity.
        self._learned = OrderedDict()       # sig(lower) → attack_class
        self._learned_hits = 0

    MAX_LEARNED = 2000

    def add_learned_signature(self, sig: str, attack_class: str) -> bool:
        """
        Add an AI-synthesized signature to L1 (thread-safe). Only an unambiguous
        context-independent token is accepted (the AI is invoked only when
        _is_pattern_malicious=True), so a direct L1 block is exactly as safe as
        the existing hard-malicious patterns. Returns True if added.
        """
        if not sig:
            return False
        s = sig.strip().lower()
        if not (4 <= len(s) <= 60):
            return False
        with self._lock:
            if s in self._learned:
                return False
            self._learned[s] = attack_class or "ai_learned"
            self._learned.move_to_end(s)
            while len(self._learned) > self.MAX_LEARNED:
                self._learned.popitem(last=False)
        return True

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _evict_dead(self, now: float):
        """Remove empty/stale window keys (memory-DoS protection).
        Called periodically under the lock."""
        for store, window in ((self._rate_windows, RATE_WINDOW_SEC),
                              (self._cast_windows, CONCURRENCY_WINDOW_SEC)):
            dead = [k for k, dq in store.items()
                    if not dq or (now - dq[-1]) > window]
            for k in dead:
                del store[k]
            # hard cap, if the dict is still too large
            if len(store) > MAX_TRACKED_KEYS:
                oldest = sorted(store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
                for k, _ in oldest[: len(store) - MAX_TRACKED_KEYS]:
                    del store[k]

    def _match_endpoint(self, path: str) -> str:
        """Return the signature pattern contained in path, or ''."""
        for pat in SENSITIVE_PATTERNS:
            if pat in path:
                return pat
        return ""

    def _rate_key_pattern(self, path: str, method: str) -> str:
        for pat in RATE_LIMITS:
            if pat == "_default" or pat not in path:
                continue
            # for a login endpoint the special limit applies only to POST (login
            # attempts); a GET of the login form goes under the generic default limit
            if pat in LOGIN_ENDPOINTS and method != "POST":
                continue
            return pat
        return "_default"

    def _prune(self, dq: deque, now: float, window: float):
        while dq and (now - dq[0]) > window:
            dq.popleft()

    def _anomaly_signal(self, method: str, path: str):
        """
        Return (action, label, attack_class) or None:
          action="BLOCK"   — UNAMBIGUOUS payload (legit never sends) → L1 blocks itself (0ms);
          action="INSPECT" — AMBIGUOUS → the AI decides (intent/behavior).
        """
        low = path.lower()
        # ── UNAMBIGUOUS payload → deterministic L1 BLOCK (do not rely on AI) ──
        if is_path_traversal(path):
            return ("BLOCK", "path_traversal", "path_traversal")
        tok, ac = l1_block_match(low)
        if tok:
            return ("BLOCK", f"hard:{tok}", ac)
        # ── HIGH-RISK admin/verb → deterministic L1 BLOCK (not an "AI coin flip") ──
        # A legitimate VOTER does not do this; admin acts through a separate authorized
        # channel, not this voter-facing proxy. So we block unambiguously and stably.
        if method in ("DELETE", "PUT", "PATCH", "TRACE") and "/helios/" in low:
            return ("BLOCK", f"dangerous_verb:{method}", "dangerous_verb")
        admin_paths = ["/delete", "/archive", "/admins", "/unfreeze", "/copy",
                       "/keygenerator", "/set_reg"]
        if method == "POST" and any(a in low for a in admin_paths):
            return ("BLOCK", "admin_lifecycle", "admin_lifecycle")
        # ── AMBIGUOUS markers (occur in legit) → the AI decides ────────────────
        if anomaly_payload_match(low):
            return ("INSPECT", "injection_pattern", None)
        return None

    # ─── Main evaluation ──────────────────────────────────────────────────────

    def evaluate(self, method: str, path: str, headers: dict,
                 client_ip: str, session_id: str) -> dict:
        """
        Evaluate a single request. Returns a dict:
          {verdict, reason, attack_class, signal, latency_ms}
        verdict ∈ {ALLOW, BLOCK, INSPECT}
        """
        t0 = time.perf_counter()
        now = time.time()
        method = method.upper()
        verdict, reason, attackClass, signal = "ALLOW", "", None, None

        with self._lock:
            # Periodic eviction of dead keys (memory-DoS protection)
            self._req_since_evict += 1
            if self._req_since_evict >= EVICT_EVERY:
                self._req_since_evict = 0
                self._evict_dead(now)

            # 1. Concurrency detector: race condition on /cast
            if method == "POST" and "/cast" in path and "cast_confirm" not in path:
                ckey = (session_id or client_ip, "/cast")
                dq = self._cast_windows[ckey]
                dq.append(now)
                self._prune(dq, now, CONCURRENCY_WINDOW_SEC)
                if len(dq) >= CONCURRENCY_THRESHOLD:
                    verdict = "BLOCK"
                    attackClass = "ballot_stuffing"
                    reason = (f"Race condition: {len(dq)} одночасних POST /cast "
                              f"за {CONCURRENCY_WINDOW_SEC}с від однієї сесії")
                    signal = "concurrency"

            # 2. Rate window (if not already blocked)
            if verdict == "ALLOW":
                ratePat = self._rate_key_pattern(path, method)
                limit = RATE_LIMITS[ratePat]
                rkey = (client_ip, ratePat)
                dq = self._rate_windows[rkey]
                dq.append(now)
                self._prune(dq, now, RATE_WINDOW_SEC)
                if len(dq) > limit:
                    verdict = "BLOCK"
                    attackClass = SENSITIVE_PATTERNS.get(ratePat, "dos_zk_flood")
                    reason = (f"Rate limit: {len(dq)} запитів на {ratePat} "
                              f"за {RATE_WINDOW_SEC}с (ліміт {limit})")
                    signal = "rate"

        # 2.5 AI-learned signatures — instant L1 block of repeated new attacks (0ms).
        # Snapshot under the lock, then scan WITHOUT the lock (so we do not hold the
        # global lock during an O(N) substring search over many learned signatures).
        if verdict == "ALLOW" and self._learned:
            low = path.lower()
            with self._lock:
                snapshot = tuple(self._learned.items())
            for sig, ac in snapshot:
                if sig in low:
                    with self._lock:
                        self._learned_hits += 1
                    verdict, attackClass, signal = "BLOCK", ac, "learned_signature"
                    reason = (f"Вивчена ШІ-сигнатура «{sig}» — миттєвий L1-блок "
                              f"(adaptive→innate immunity)")
                    break

        # 3. Signature heuristics (outside the lock — only reads headers)
        if verdict == "ALLOW":
            sigPat = self._match_endpoint(path)
            if sigPat:
                # devlogin — login without a password, must be disabled in prod
                if sigPat == "/auth/devlogin/login" and method == "POST":
                    verdict = "BLOCK"
                    attackClass = "impersonation"
                    reason = "DevLogin POST — автентифікація без пароля (заборонено в проді)"
                    signal = "signature"
                # CSRF on a trustee: external Referer
                elif sigPat == "/upload-decryption" and method == "POST":
                    referer = headers.get("Referer", "") or headers.get("referer", "")
                    if referer and "localhost" not in referer and "127.0.0.1" not in referer:
                        verdict = "BLOCK"
                        attackClass = "csrf_trustee_takeover"
                        reason = f"CSRF: trustee upload із зовнішнього Referer ({referer[:40]})"
                        signal = "signature"
                    else:
                        verdict = "INSPECT"
                        reason = "Trustee decryption upload — потребує ШІ-аналізу"
                        signal = "sensitive"
                # Admin-only tally (tally/freeze/combine) → deterministic block
                elif sigPat in ADMIN_ONLY_ENDPOINTS:
                    verdict = "BLOCK"
                    attackClass = SENSITIVE_PATTERNS.get(sigPat, "tally_manipulation")
                    reason = (f"Admin-only операція {sigPat} на voter-facing проксі — "
                              f"детермінований L1-блок (виборець її не викликає)")
                    signal = "admin_only"
                # Login (GET form + POST attempt) → LEGITIMATE at L1. Real attacks
                # on login are guarded by the rate limit (flood/suppression) and the
                # tempo filter (bot recon→login); a single voter attempt is normal
                # (ALLOW, no AI, so the AI does not falsely block a legitimate login).
                elif sigPat in LOGIN_ENDPOINTS:
                    pass   # verdict stays ALLOW
                # Other sensitive endpoints (cast) → to AI analysis (vote intent)
                else:
                    verdict = "INSPECT"
                    attackClass = SENSITIVE_PATTERNS.get(sigPat)
                    reason = f"Чутливий endpoint {sigPat} — потребує перевірки наміру"
                    signal = "sensitive"
            else:
                # Non-cataloged endpoint: check GENERIC anomalies.
                # FastReflex only ROUTES the suspicious to the AI (does not block
                # itself) — the final decision is the AI's reasoning. This catches
                # NEW attacks that are in neither the signatures nor the catalog.
                anomaly = self._anomaly_signal(method, path)
                if anomaly:
                    action, label, ac = anomaly
                    if action == "BLOCK":
                        verdict = "BLOCK"
                        attackClass = ac
                        reason = (f"Однозначний шкідливий payload ({label}) — "
                                  f"детермінований L1-блок (0мс)")
                        signal = f"payload:{label}"
                    else:
                        verdict = "INSPECT"
                        reason = f"Аномалія ({label}) — потребує перевірки наміру ШІ"
                        signal = f"anomaly:{label}"

        latencyMs = round((time.perf_counter() - t0) * 1000, 3)
        return {
            "verdict":      verdict,
            "reason":       reason,
            "attack_class": attackClass,
            "signal":       signal,
            "latency_ms":   latencyMs,
        }

    def cast_count(self, session_key: str) -> int:
        """Thread-safe count of recent POST /cast for a session (for AI context)."""
        with self._lock:
            dq = self._cast_windows.get((session_key, "/cast"))
            return len(dq) if dq else 0

    def stats(self) -> dict:
        with self._lock:
            return {
                "tracked_rate_keys":  len(self._rate_windows),
                "tracked_cast_keys":  len(self._cast_windows),
                "learned_signatures": len(self._learned),
                "learned_hits":       self._learned_hits,
            }
