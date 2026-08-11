"""
Module: ImmuneProxy — inline reverse proxy of the digital immune system
Digital immune system — immune_system/immune_proxy.py

Sits on port 8000 IN FRONT OF Helios (port 8001). Every request goes through
two-layer defense in real time:

  Request → :8000 ImmuneProxy
            ↓
   Layer 1: FastReflex (~1ms)  → ALLOW / BLOCK / INSPECT
            ↓ (INSPECT)
   Layer 2: AIAnalyst (Claude) → ALLOW / BLOCK
            ↓ (ALLOW)
   forward → :8001 Helios → response back
            (BLOCK)
   → 403 Forbidden, the request does NOT reach Helios

Run:      python immune_system/immune_proxy.py
Metrics:  GET http://localhost:8000/__immune__/stats
"""

import sys
import json
import re
import time
import hashlib
import threading
import posixpath
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote
from pathlib import Path

# Auto-load .env (ANTHROPIC_API_KEY) before initializing AIAnalyst
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env
load_env()

import requests
from flask import Flask, request, Response, jsonify

from fast_reflex import FastReflex, RATE_WINDOW_SEC, CONCURRENCY_WINDOW_SEC
from ai_analyst import AIAnalyst, DEFAULT_MODEL
from threat_patterns import hard_payload_present, classify_hard_payload


# ─── Configuration ────────────────────────────────────────────────────────────

from env_loader import load_config

_cfg = load_config()
PROJECT_ROOT  = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
LOGS_DIR      = PROJECT_ROOT / _cfg.get("paths", {}).get("logs_dir", "logs")
CLAUDE_MODEL  = _cfg.get("claude", {}).get("model", DEFAULT_MODEL)
CLAUDE_EFFORT = _cfg.get("claude", {}).get("effort", "low")   # глибина L2-міркування
# a separate limit for the AI judge (NOT to be confused with claude.max_tokens=7000 for
# generation): with adaptive thinking, tokens also go to reasoning — 512 would truncate the JSON verdict.
JUDGE_MAX_TOKENS = _cfg.get("claude", {}).get("judge_max_tokens", 2048)

_proxy_cfg     = _cfg.get("immune_proxy", {})
LISTEN_HOST    = _proxy_cfg.get("listen_host", "127.0.0.1")
PROXY_PORT     = _proxy_cfg.get("listen_port", 8000)
HELIOS_BACKEND = _proxy_cfg.get("helios_backend", "http://localhost:8001")
MAX_BODY_BYTES = _proxy_cfg.get("max_body_bytes", 5 * 1024 * 1024)   # 5 МБ
# Forward timeout to Helios. Was 30s: with threads=8 eight slow backend responses
# would exhaust the worker pool (thread-starvation DoS). 10s is a reasonable ceiling
# for e-voting (view/cast are fast); slower = either an overloaded Helios or an attack.
FORWARD_TIMEOUT_SEC = _proxy_cfg.get("forward_timeout_sec", 10)
AI_BODY_PREVIEW = 2000          # скільки байтів тіла подавати ШІ
BLOCKS_LOG     = LOGS_DIR / "immune_blocks.jsonl"

# Inject secure HTTP headers into EVERY response (voter browser protection:
# XSS, clickjacking, MITB/CDN-compromise, sniffing). Standard OWASP control.
SECURITY_HEADERS_ENABLED = _proxy_cfg.get("security_headers_enabled", True)
SECURITY_HEADERS = _proxy_cfg.get("security_headers") or {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    # HSTS is effective only over TLS (the browser ignores it over HTTP) — added for the future
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # script-src 'self' blocks EXTERNAL scripts (CDN-compromise/MITB vector);
    # frame-ancestors 'none' — anti-clickjacking; object-src 'none' — no plugins.
    # 'unsafe-inline'/'eval' are kept, because Helios cryptography is inline JS in the browser.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
}

# Timestamp coarsening on the ballot board: a public cast_at reveals the exact
# cast time → timing-deanonymization. We round to the hour in /ballots/ responses.
COARSEN_BALLOT_TS = _proxy_cfg.get("coarsen_ballot_timestamps", True)

# RESPONSE inspection (anti-exfiltration of PII). Protecting voting data is not
# only "not letting a write in" but also "not letting a mass LEAK" of the voters/ballots list.
# An anomalously large dump on /voters/ or /ballots/ is a sign of harvest/exfiltration.
#   soft → only a flag (log+metric+header), return the response (FP-safe);
#   hard → 403 block (DISABLED by default: 0, so legit volumes are not cut off).
EXFIL_INSPECT_PATHS = ("/voters/", "/ballots/")
EXFIL_SOFT_BYTES = _proxy_cfg.get("exfil_soft_bytes", 256 * 1024)   # 256 КБ → підозра
EXFIL_HARD_BYTES = _proxy_cfg.get("exfil_hard_bytes", 0)            # 0 = блок вимкнено

# Verbose blocks: whether to return attack_class + reason in the 403 body to the attacker.
# DEMO/lab (True) — convenient for adaptive_generator and reports; PROD (False) —
# do not hint to the attacker WHAT triggered (a minimal 403 without detection details).
VERBOSE_BLOCKS = _proxy_cfg.get("verbose_blocks", True)

# How many BODY bytes the deterministic backstop scans (payload not only at the start).
# Separate from AI_BODY_PREVIEW (the AI preview stays 2KB) — the backstop looks deeper.
BACKSTOP_BODY_BYTES = _proxy_cfg.get("backstop_body_bytes", 64 * 1024)   # 64 КБ
# Optional token for /__immune__/stats (empty = no auth; the proxy listens on
# 127.0.0.1, so not exposed — but in prod set a token in config.json).
STATS_TOKEN = _proxy_cfg.get("stats_token", "")
_TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}):\d{2}:\d{2}(?:\.\d+)?')

LOGS_DIR.mkdir(exist_ok=True)

# Headers that must not be forwarded (hop-by-hop)
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


# ─── Components ───────────────────────────────────────────────────────────────

app = Flask(__name__)
# Memory-DoS protection: reject bodies over the limit (Flask returns 413)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
reflex = FastReflex()
analyst = AIAnalyst(model=CLAUDE_MODEL, memory_db=LOGS_DIR / "ai_memory.db",
                    effort=CLAUDE_EFFORT, max_tokens=JUDGE_MAX_TOKENS)

# Window of SUSPICIOUS requests from an IP (a secondary signal for the AI). NOTE: it is
# populated only on the INSPECT path (_recent_ip_count is called only before L2), so it is
# "how many times this IP reached AI analysis in the window", NOT a full counter of all
# requests — the real rate-limit is done by FastReflex (L1). For the AI it is a hint of
# "recent suspicious activity", not the exact traffic volume.
_ip_window = defaultdict(deque)
MAX_TRACKED_IPS = 10000   # межа для захисту від memory-DoS (евікція найстаріших)

# Behavioral TRAJECTORY of the actor (session|IP): the sequence and tempo of recent requests.
# Gives the AI context to detect MULTI-STEP attacks / APT recon (recon→login→cast in
# seconds) that look innocent individually. A server signal (measured by the proxy).
_actor_history = defaultdict(deque)   # actor → deque[(ts, method, label)]
MAX_TRAJ_ENTRIES = 12                  # скільки останніх кроків тримати на актора
TRAJ_WINDOW_SEC = 60.0                 # горизонт траєкторії
# Deterministic tempo filter (non-human tempo = bot/APT). A single source of the threshold —
# both the prod path and tests use these constants (without duplicating "magic 4/2s").
NONHUMAN_TEMPO_WINDOW_SEC = 2.0        # вікно вимірювання темпу
NONHUMAN_TEMPO_THRESHOLD = 4           # ≥N різних endpoint за вікно = нелюдина

# Antigen correlation: client fingerprint → recent IPs (to detect IP rotation).
_fp_history = defaultdict(deque)       # fp → deque[(ts, ip)]
FP_WINDOW_SEC = 60.0
_UUID_RE2 = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
# a long SINGLE segment (ballot hash, etc.) — WITHOUT '/', so it does not eat "helios/elections"
_HASH_RE2 = re.compile(r'/[A-Za-z0-9+=_-]{20,}')

# Metrics + a single lock (Flask threaded=True → mutations must be atomic)
_state_lock = threading.Lock()
metrics = {
    "total": 0, "allowed": 0,
    "blocked_fast": 0, "blocked_ai": 0,
    "inspected": 0, "errors": 0,
    "exfil_suspected": 0,         # підозра на ексфільтрацію (аномальний дамп у відповіді)
    "latency_sum_ms": 0.0,
    "by_attack_class": defaultdict(int),
}


# SOC alerts: log warnings when thresholds are crossed (for the on-call shift/SIEM).
# Fires once per level (×threshold), to avoid spamming.
ALERT_THRESHOLDS = {"errors": 50, "blocked_ai": 100, "exfil_suspected": 1}
_alerts_fired = set()


def _soc_alert(key: str, value: int):
    th = ALERT_THRESHOLDS.get(key)
    if not th:
        return
    level = value // th
    if level >= 1 and (key, level) not in _alerts_fired:
        _alerts_fired.add((key, level))
        print(f"  🚨 SOC-ALERT: метрика '{key}' досягла {value} (поріг {th}×{level}) "
              f"— перевірте чергу інцидентів", file=sys.stderr, flush=True)


def bump(key: str, n=1, attack_class: str = None):
    """Atomic increment of metrics (+ a SOC alert when a threshold is crossed)."""
    fire = None
    with _state_lock:
        if key in metrics:
            metrics[key] += n
            if key in ALERT_THRESHOLDS:
                fire = (key, metrics[key])
        if attack_class:
            metrics["by_attack_class"][attack_class] += 1
    if fire:
        _soc_alert(*fire)


# ─── Decision logging ─────────────────────────────────────────────────────────

# Log rotation by size (protection against unbounded growth of immune_blocks.jsonl).
MAX_LOG_BYTES = 50 * 1024 * 1024   # 50 МБ на файл
LOG_BACKUPS   = 5                  # скільки ротованих копій тримати (.1 … .5)


def _rotate_if_needed(path: Path):
    """Rotate the log if it grew past MAX_LOG_BYTES (file → file.1 → … → file.N)."""
    try:
        if not (path.exists() and path.stat().st_size >= MAX_LOG_BYTES):
            return
        oldest = path.with_name(path.name + f".{LOG_BACKUPS}")
        if oldest.exists():
            oldest.unlink()
        for i in range(LOG_BACKUPS - 1, 0, -1):
            src = path.with_name(path.name + f".{i}")
            if src.exists():
                src.rename(path.with_name(path.name + f".{i + 1}"))
        path.rename(path.with_name(path.name + ".1"))
    except OSError as e:
        print(f"[!] Ротація журналу {path.name} не вдалася: {e}", file=sys.stderr)


# Masking voter/ballot identifiers in the path before logging.
# Ballot secrecy: the log must NOT link a specific voter (voter_uuid) or their
# ballot (ballot_hash) with an action/time. The election UUID is not masked —
# it is public.
_VOTER_SEG_RE  = re.compile(r"(/voters/)[^/?#]+", re.IGNORECASE)
_BALLOT_SEG_RE = re.compile(r"(/ballots/)[^/?#]+", re.IGNORECASE)


def _redact_pii(path: str) -> str:
    """Mask voter_uuid and ballot_hash in the path (log privacy)."""
    if not path:
        return path
    p = _VOTER_SEG_RE.sub(r"\1{voter}", path)
    p = _BALLOT_SEG_RE.sub(r"\1{ballot}", p)
    return p


def log_decision(entry: dict):
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    if "path" in entry:
        entry["path"] = _redact_pii(entry["path"])   # без PII виборця в журналі
    _rotate_if_needed(BLOCKS_LOG)
    with open(BLOCKS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _parse_client_ip(xff_header: str, remote_addr: str) -> str:
    """Extract the client IP from X-Forwarded-For. XFF may be a chain
    'client, proxy1, proxy2' — we take the FIRST (the real client), otherwise the
    same client with different proxy tails would split the tracking."""
    if xff_header:
        first = xff_header.split(",")[0].strip()
        if first:
            return first
    return remote_addr or "127.0.0.1"


def _client_ip() -> str:
    return _parse_client_ip(request.headers.get("X-Forwarded-For"), request.remote_addr)


def _session_id() -> str:
    return request.cookies.get("sessionid", "")


# Behavioral "antigen" of the actor: client fingerprint by the SET/ORDER of headers
# + key values (UA/Accept*). Lets us correlate activity NOT only by IP: the address is
# variable (subnet rotation — a typical APT evasion), while the HTTP-client fingerprint
# is stable. Weak on its own for a BLOCK (many voters may have the same browser), so it
# is used as an AI SIGNAL (how many IPs per one fingerprint), not as a deterministic
# block — so as not to hit legit voters behind a shared UA.
_FP_VALUE_HEADERS = ("User-Agent", "Accept", "Accept-Language", "Accept-Encoding")


def _client_fingerprint(headers) -> str:
    order = ",".join(k.lower() for k in headers.keys())
    values = "|".join(str(headers.get(h, "")) for h in _FP_VALUE_HEADERS)
    raw = (values + "||" + order).encode("utf-8", "replace")
    return "fp:" + hashlib.sha1(raw).hexdigest()[:16]


# ─── Behavioral actor trajectory (for the AI) ─────────────────────────────────

def _endpoint_label(path: str) -> str:
    """A compact endpoint label (UUID/hash masked) for the trajectory."""
    p = _UUID_RE2.sub("{id}", path)
    p = _HASH_RE2.sub("/{hash}", p)
    return p[:60]


def _record_request(actor: str, method: str, path: str, now: float):
    """Register an actor step in the trajectory (thread-safe, with eviction)."""
    with _state_lock:
        dq = _actor_history[actor]
        dq.append((now, method, _endpoint_label(path)))
        while len(dq) > MAX_TRAJ_ENTRIES:
            dq.popleft()
        if len(_actor_history) > MAX_TRACKED_IPS:
            stale = [k for k, v in _actor_history.items()
                     if not v or (now - v[-1][0]) > TRAJ_WINDOW_SEC]
            for k in stale:
                del _actor_history[k]
            if len(_actor_history) > MAX_TRACKED_IPS:
                oldest = sorted(_actor_history.items(),
                                key=lambda kv: kv[1][-1][0] if kv[1] else 0)
                for k, _ in oldest[: len(_actor_history) - MAX_TRACKED_IPS]:
                    del _actor_history[k]


def _recent_distinct_endpoints(actor: str, now: float,
                               window: float = NONHUMAN_TEMPO_WINDOW_SEC) -> list:
    """A sorted list of the actor's DISTINCT endpoints in the window (a single source of
    the tempo logic for the prod path and tests)."""
    with _state_lock:
        return sorted({e[2] for e in _actor_history.get(actor, ()) if now - e[0] <= window})


def _nonhuman_tempo(actor: str, now: float,
                    window: float = NONHUMAN_TEMPO_WINDOW_SEC,
                    threshold: int = NONHUMAN_TEMPO_THRESHOLD) -> bool:
    """Deterministic bot signal: ≥threshold DISTINCT endpoints in <window (a human
    physically cannot). FP-safe: a legitimate voter does not click 4 pages in 2s."""
    return len(_recent_distinct_endpoints(actor, now, window)) >= threshold


def _record_fingerprint(fp: str, ip: str, now: float):
    """Register the IP under the client fingerprint (antigen) — to detect IP rotation."""
    with _state_lock:
        dq = _fp_history[fp]
        dq.append((now, ip))
        while dq and (now - dq[0][0]) > FP_WINDOW_SEC:
            dq.popleft()
        if len(_fp_history) > MAX_TRACKED_IPS:
            stale = [k for k, v in _fp_history.items()
                     if not v or (now - v[-1][0]) > FP_WINDOW_SEC]
            for k in stale:
                del _fp_history[k]
            if len(_fp_history) > MAX_TRACKED_IPS:
                oldest = sorted(_fp_history.items(),
                                key=lambda kv: kv[1][-1][0] if kv[1] else 0)
                for k, _ in oldest[: len(_fp_history) - MAX_TRACKED_IPS]:
                    del _fp_history[k]


def _fp_distinct_ips(fp: str, now: float, window: float = FP_WINDOW_SEC) -> int:
    """How many DISTINCT IPs this fingerprint used in the window (>1 within seconds = IP rotation)."""
    with _state_lock:
        return len({ip for ts, ip in _fp_history.get(fp, ()) if now - ts <= window})


def _trajectory_summary(actor: str, now: float) -> str:
    """A text summary of the actor's recent steps (for the AI prompt)."""
    with _state_lock:
        entries = [e for e in _actor_history.get(actor, ())
                   if now - e[0] <= TRAJ_WINDOW_SEC]
    if len(entries) <= 1:
        return "(перший запит у вікні — траєкторії ще немає)"
    lines = []
    for ts, m, label in entries:
        ago = now - ts
        mark = "  ← поточний" if ago < 0.05 else ""
        lines.append(f"  -{ago:>4.1f}с {m:<6} {label}{mark}")
    span = now - entries[0][0]
    distinct = len({label for _, _, label in entries})
    header = f"{len(entries)} кроків ({distinct} унікальних endpoint) за {span:.1f}с"
    # an explicit deterministic non-human-tempo signal — so the AI does not confuse recon
    # masquerading with human browsing: 4+ different endpoints in <2s are physically impossible for a human
    if distinct >= 4 and span < 2.0:
        header = ("⚠ НЕЛЮДСЬКИЙ ТЕМП (автоматизація/бот: фізично неможливо для людини) — "
                  + header)
    return header + ":\n" + "\n".join(lines)


# Session validation in Helios with a TTL cache. A positive result is cached for long,
# a negative one — briefly: otherwise an anonymous session checked BEFORE login would poison
# the cache for the same sessionid after login (Helios reuses the session key).
_session_cache = {}          # sessionid → (is_valid: bool, expiry: float)
SESSION_TTL_VALID = 30.0     # дійсна сесія лишається дійсною
SESSION_TTL_INVALID = 3.0    # недійсну перевіряємо часто (вікно після логіну)
SESSION_CACHE_MAX = 5000

# Circuit breaker for session validation: every invalid session triggers a blocking call to
# Helios. Under a flood of unique cookies this amplifies backend load and adds latency to L2.
# If Helios fails/times out in a row — we OPEN the circuit: for a while we do not call
# validation (return False quickly). Login/cast are ALLOW-by-default anyway, so
# "not validated" does not cause a false positive.
HELIOS_CB_FAIL_THRESHOLD = 3     # стільки збоїв підряд → розмикання
HELIOS_CB_OPEN_SEC = 10.0        # на скільки розмикаємо (не звертаємось до Helios)
HELIOS_CB_TIMEOUT = 3.0          # таймаут одного validation-call (було 5с)
_helios_cb = {"fails": 0, "open_until": 0.0}


def _cb_is_open(now: float) -> bool:
    with _state_lock:
        return now < _helios_cb["open_until"]


def _cb_record_fail(now: float):
    """Register a Helios failure; at the threshold — open the circuit for HELIOS_CB_OPEN_SEC."""
    with _state_lock:
        _helios_cb["fails"] += 1
        if _helios_cb["fails"] >= HELIOS_CB_FAIL_THRESHOLD:
            _helios_cb["open_until"] = now + HELIOS_CB_OPEN_SEC
            _helios_cb["fails"] = 0


def _cb_record_success():
    with _state_lock:
        _helios_cb["fails"] = 0


_ELECTION_RE = re.compile(r"/helios/elections/([0-9a-fA-F-]{36})")


def _validate_session(session_id: str, req_path: str = "") -> bool:
    """
    Check whether the cookie corresponds to a REALLY authenticated Helios voter
    (a server signal, unforgeable). Helios sessions are tied to ELECTIONS, so we
    validate via the election view, not the global /auth/. 30s cache + breaker.
    """
    if not session_id:
        return False
    now = time.time()
    cache_key = session_id
    with _state_lock:
        ent = _session_cache.get(cache_key)
        if ent and now < ent[1]:
            return ent[0]
    # Circuit breaker open (Helios unhealthy) → do not amplify load,
    # return False quickly (do not cache — to check again after recovery).
    if _cb_is_open(now):
        return False
    # determine the election from the request path (otherwise validation is impossible)
    m = _ELECTION_RE.search(req_path or "")
    valid = False
    if m:
        uuid = m.group(1)
        try:
            r = requests.get(f"{HELIOS_BACKEND}/helios/elections/{uuid}/view",
                             cookies={"sessionid": session_id},
                             timeout=HELIOS_CB_TIMEOUT, allow_redirects=False)
            body = r.text.lower()
            # an anonymous user sees a login-gate / redirect; a logged-in voter does not
            is_login_gate = ("log in to view" in body or
                             "password_voter_login" in body or
                             r.status_code in (302, 301))
            valid = (r.status_code == 200) and not is_login_gate
            _cb_record_success()
        except requests.exceptions.RequestException:
            valid = False
            _cb_record_fail(now)   # Helios таймаут/відмова → наближаємо розмикання
    ttl = SESSION_TTL_VALID if valid else SESSION_TTL_INVALID
    with _state_lock:
        _session_cache[cache_key] = (valid, now + ttl)
        if len(_session_cache) > SESSION_CACHE_MAX:
            for k in [k for k, v in _session_cache.items() if v[1] <= now]:
                del _session_cache[k]
    return valid


def _recent_ip_count(ip: str) -> int:
    now = time.time()
    with _state_lock:
        dq = _ip_window[ip]
        dq.append(now)
        while dq and (now - dq[0]) > RATE_WINDOW_SEC:
            dq.popleft()
        count = len(dq)
        # Eviction of dead IPs (memory-DoS protection): remove empty
        # and oldest keys if the dict grew past the limit.
        if len(_ip_window) > MAX_TRACKED_IPS:
            stale = [k for k, v in _ip_window.items() if not v]
            for k in stale:
                del _ip_window[k]
            # if still too large — remove the oldest by last timestamp
            if len(_ip_window) > MAX_TRACKED_IPS:
                oldest = sorted(_ip_window.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
                for k, _ in oldest[: len(_ip_window) - MAX_TRACKED_IPS]:
                    del _ip_window[k]
    return count


# ─── Blocking ─────────────────────────────────────────────────────────────────

def make_block_response(decision: dict, tier: str) -> Response:
    body = {
        "error": "Forbidden — Digital Immune System",
        "incident_time": datetime.now(timezone.utc).isoformat(),
    }
    # Detection details (attack_class/reason/level) — only in VERBOSE mode (demo/reports).
    # In prod we do not hint to the attacker WHAT triggered (minimize the bypass oracle).
    # The log/metrics still record the full reason server-side.
    if VERBOSE_BLOCKS:
        body["blocked_by"] = tier
        body["attack_class"] = decision.get("attack_class")
        body["reason"] = decision.get("reason") or decision.get("reasoning")
    return Response(json.dumps(body, ensure_ascii=False),
                    status=403, content_type="application/json")


# ─── Forwarding to Helios ─────────────────────────────────────────────────────

_BACKEND_HOST = urlsplit(HELIOS_BACKEND).netloc


def _safe_backend_url(path: str):
    """
    Build the backend URL, ensuring the path does NOT escape the backend
    (SSRF / path-escape protection). Returns the url or None if suspicious.
    """
    # absolute URL / protocol-relative / backslash — forbidden
    if "://" in path or path.startswith("//") or "\\" in path:
        return None
    # any ".." segment — forbidden (strict, no normalization attempts)
    if ".." in path.split("/"):
        return None
    clean = posixpath.normpath("/" + path).lstrip("/")
    if clean.startswith(".."):
        return None
    url = f"{HELIOS_BACKEND}/{clean}"
    # final check: the host must stay the backend host
    if urlsplit(url).netloc != _BACKEND_HOST:
        return None
    return url


def _exfil_verdict(path: str, method: str, size: int) -> str:
    """Classify a RESPONSE on a sensitive list endpoint by size:
    'block' (hard), 'flag' (soft) or '' (normal). Pure function — tested without servers."""
    if method != "GET" or not any(s in path for s in EXFIL_INSPECT_PATHS):
        return ""
    if EXFIL_HARD_BYTES and size >= EXFIL_HARD_BYTES:
        return "block"
    if size >= EXFIL_SOFT_BYTES:
        return "flag"
    return ""


def forward_to_helios(path: str) -> Response:
    url = _safe_backend_url(path)
    if url is None:
        bump("errors")
        return Response(json.dumps({"error": "Заборонений шлях (path escape)"},
                                   ensure_ascii=False),
                        status=400, content_type="application/json")
    fwdHeaders = {k: v for k, v in request.headers if k.lower() not in HOP_BY_HOP}
    # The proxy is the trust boundary: we OVERWRITE X-Forwarded-For with the REAL client IP
    # (otherwise a client-spoofed XFF would pass to Helios and poison its logs/
    # rate logic). Single-hop: the backend sees only our conclusion about the source.
    fwdHeaders = {k: v for k, v in fwdHeaders.items() if k.lower() != "x-forwarded-for"}
    fwdHeaders["X-Forwarded-For"] = _client_ip()
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=fwdHeaders,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=FORWARD_TIMEOUT_SEC,
        )
    except requests.exceptions.RequestException as e:
        bump("errors")
        return Response(json.dumps({"error": f"Helios backend недоступний: {e}"}),
                        status=502, content_type="application/json")
    excluded = HOP_BY_HOP | {"content-encoding"}
    respHeaders = [(k, v) for k, v in resp.raw.headers.items()
                   if k.lower() not in excluded]
    content = resp.content
    # Timestamp coarsening on the ballot board (privacy: against timing-deanon)
    ctype = resp.headers.get("Content-Type", "")
    if (COARSEN_BALLOT_TS and "/ballots" in path
            and any(t in ctype for t in ("json", "text", "html"))):
        content = _coarsen_timestamps(content)
    # Response inspection for exfiltration (an anomalously large list dump)
    exfil = _exfil_verdict("/" + path, request.method, len(content or b""))
    if exfil == "block":
        bump("blocked_fast", attack_class="data_exfiltration")
        log_decision({
            "tier": "ResponseGuard", "verdict": "BLOCK", "method": request.method,
            "path": "/" + path, "client_ip": _client_ip(),
            "attack_class": "data_exfiltration",
            "reason": f"Аномальний дамп {len(content)} Б на {path} — ексфільтрація PII",
            "signal": "response_size", "latency_ms": 0,
        })
        print(f"  🔴 BLOCK [ResponseGuard] {request.method} /{path} "
              f"→ data_exfiltration ({len(content)} Б)", flush=True)
        return make_block_response(
            {"attack_class": "data_exfiltration",
             "reason": "Аномальний обсяг відповіді — захист від ексфільтрації PII"},
            "ResponseGuard")
    out = Response(content, status=resp.status_code, headers=respHeaders)
    if exfil == "flag":
        bump("exfil_suspected")
        out.headers["X-Immune-Exfil"] = "suspected"
        log_decision({
            "tier": "ResponseGuard", "verdict": "FLAG", "method": request.method,
            "path": "/" + path, "client_ip": _client_ip(),
            "attack_class": "data_exfiltration_suspected",
            "reason": f"Великий дамп {len(content)} Б на {path} (≥{EXFIL_SOFT_BYTES} Б)",
            "signal": "response_size", "latency_ms": 0,
        })
        print(f"  ⚠️  FLAG [ResponseGuard] {request.method} /{path} "
              f"→ можлива ексфільтрація ({len(content)} Б)", flush=True)
    return out


def _coarsen_timestamps(body: bytes) -> bytes:
    """Round ISO timestamps to the hour (HH:MM:SS → HH:00:00) in the response body.
    Safe: on any error returns the original unchanged."""
    try:
        text = body.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return body
    return _TS_RE.sub(r"\1:00:00", text).encode("utf-8")


@app.after_request
def _add_security_headers(resp):
    """Inject secure headers into EVERY response (voter browser protection)."""
    if SECURITY_HEADERS_ENABLED:
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
    return resp


@app.errorhandler(413)
def _too_large(e):
    bump("errors")
    return Response(json.dumps({"error": "Тіло запиту завелике (memory-DoS захист)"},
                               ensure_ascii=False),
                    status=413, content_type="application/json")


# ─── Main route (catch-all) ───────────────────────────────────────────────────

@app.route("/__immune__/stats", methods=["GET"])
def stats():
    if STATS_TOKEN and request.args.get("token") != STATS_TOKEN \
            and request.headers.get("X-Stats-Token") != STATS_TOKEN:
        return Response(json.dumps({"error": "Forbidden — потрібен stats-токен"}),
                        status=403, content_type="application/json")
    with _state_lock:
        snap = {k: (dict(v) if isinstance(v, defaultdict) else v)
                for k, v in metrics.items()}
    avg = (snap["latency_sum_ms"] / snap["total"]) if snap["total"] else 0
    return jsonify({
        "build":           "v8-tempo-ai",     # маркер версії запущеного коду
        "total_requests":  snap["total"],
        "allowed":         snap["allowed"],
        "blocked_fast":    snap["blocked_fast"],
        "blocked_ai":      snap["blocked_ai"],
        "inspected_by_ai": snap["inspected"],
        "errors":          snap["errors"],
        "exfil_suspected": snap["exfil_suspected"],
        "avg_latency_ms":  round(avg, 3),
        "by_attack_class": snap["by_attack_class"],
        "fast_reflex":     reflex.stats(),
        "ai_analyst":      analyst.stats(),
    })


@app.route("/__immune__/metrics", methods=["GET"])
def prometheus_metrics():
    """Export metrics in Prometheus text format (for SOC/Grafana scraping)."""
    if STATS_TOKEN and request.args.get("token") != STATS_TOKEN \
            and request.headers.get("X-Stats-Token") != STATS_TOKEN:
        return Response("# forbidden\n", status=403, content_type="text/plain")
    with _state_lock:
        snap = {k: (dict(v) if isinstance(v, defaultdict) else v)
                for k, v in metrics.items()}
    avg = (snap["latency_sum_ms"] / snap["total"]) if snap["total"] else 0
    ai = analyst.stats()
    fr = reflex.stats()
    lines = []

    def metric(name, value, mtype, help_text, labels=""):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name}{labels} {value}")

    metric("dis_requests_total", snap["total"], "counter", "Усього запитів через ЦІС")
    metric("dis_allowed_total", snap["allowed"], "counter", "Пропущено до Helios")
    metric("dis_blocked_fast_total", snap["blocked_fast"], "counter", "Блоків L1 FastReflex")
    metric("dis_blocked_ai_total", snap["blocked_ai"], "counter", "Блоків L2 AIAnalyst")
    metric("dis_inspected_total", snap["inspected"], "counter", "Запитів на ШІ-аналіз")
    metric("dis_errors_total", snap["errors"], "counter", "Помилки форвардингу/бекенду")
    metric("dis_exfil_suspected_total", snap["exfil_suspected"], "counter",
           "Підозри на ексфільтрацію PII у відповідях")
    metric("dis_avg_latency_ms", round(avg, 3), "gauge", "Середня латентність рішення, мс")
    metric("dis_ai_cache_hit_rate", ai.get("cache_hit_rate", 0), "gauge", "Hit-rate ШІ-кешу, %")
    metric("dis_ai_rate_capped_total", ai.get("rate_capped", 0), "counter", "ШІ rate-cap спрацювань")
    metric("dis_learned_signatures", fr.get("learned_signatures", 0), "gauge",
           "Сигнатур, вивчених L1 від ШІ")
    # breakdown of blocks by attack class (label)
    lines.append("# HELP dis_blocked_by_class_total Блоків за класом атаки")
    lines.append("# TYPE dis_blocked_by_class_total counter")
    for ac, cnt in snap["by_attack_class"].items():
        safe = str(ac).replace('"', "'")
        lines.append(f'dis_blocked_by_class_total{{attack_class="{safe}"}} {cnt}')
    return Response("\n".join(lines) + "\n", content_type="text/plain; version=0.0.4")


@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def proxy(path):
    t0 = time.perf_counter()
    bump("total")
    method   = request.method
    fullPath = "/" + path
    # the full path with the query string — so FastReflex/AI see injections in params.
    # We DECODE %-encoding for DETECTION (the original is forwarded): otherwise %20-SQL
    # ('union%20select') and %7B-SSTI ('%7B%7B') would slip past the patterns.
    inspectPath = fullPath
    if request.query_string:
        inspectPath = fullPath + "?" + request.query_string.decode("utf-8", "replace")
    inspectPath = unquote(inspectPath)
    headers  = dict(request.headers)
    clientIp = _client_ip()
    sessionId = _session_id()
    # The actor for trajectory/tempo is clientIp (a server-observed source), NOT a cookie:
    # otherwise an attacker would evade behavioral tracking by rotating the sessionid cookie.
    actorKey = clientIp
    _now0 = time.time()
    _record_request(actorKey, method, fullPath, _now0)         # поведінкова траєкторія
    # Antigen correlation: register the IP under the client fingerprint (anti IP-rotation).
    fpKey = _client_fingerprint(request.headers)
    _record_fingerprint(fpKey, clientIp, _now0)

    # ─── Layer 1: FastReflex ──────────────────────────────────────────────────
    decision = reflex.evaluate(method, inspectPath, headers, clientIp, sessionId)
    verdict = decision["verdict"]

    if verdict == "BLOCK":
        latency = round((time.perf_counter() - t0) * 1000, 2)
        bump("blocked_fast", attack_class=decision.get("attack_class"))
        bump("latency_sum_ms", latency)
        log_decision({
            "tier": "FastReflex", "verdict": "BLOCK", "method": method,
            "path": fullPath, "client_ip": clientIp,
            "attack_class": decision["attack_class"], "reason": decision["reason"],
            "signal": decision["signal"], "latency_ms": latency,
        })
        print(f"  🔴 BLOCK [L1 {decision['signal']}] {method} {fullPath} "
              f"→ {decision['attack_class']} ({latency}ms)", flush=True)
        resp = make_block_response(decision, "FastReflex")
        resp.headers["X-Immune-Score"] = "1.0"     # L1-блок = впевнена загроза (для ROC)
        return resp

    threat_score = 0.0   # ймовірність загрози (для ROC-кривої у бенчмарку)

    # ─── Behavioral signal: non-human tempo (bot/APT recon) ───────────────────
    # For VOTER ACTIONS (login/cast): if the actor scrolled 4+ different endpoints in
    # <2s before the action — this is a suspicion of automated recon→action. BUT it is
    # NOT a hard block: in e-voting a false block = disenfranchisement, and a fast-but-legit
    # voter is also possible. So the tempo ESCALATES to the AI (INSPECT), which sees the FULL
    # trajectory (+the tempo flag) and distinguishes a recon-sweep from a voter-flow.
    _VOTER_ACTIONS = ("/auth/password/login", "/password_voter_login", "/cast")
    is_voter_action = (any(a in fullPath for a in _VOTER_ACTIONS)
                       and "cast_confirm" not in fullPath)
    _now = time.time()
    _eps = _recent_distinct_endpoints(actorKey, _now)   # єдине джерело темп-логіки
    nonhuman_tempo = is_voter_action and len(_eps) >= NONHUMAN_TEMPO_THRESHOLD
    if nonhuman_tempo:
        verdict = "INSPECT"   # ескалація на ШІ (не детермінований блок)
        print(f"  🟡 ТЕМП→ШІ {method} {fullPath} | actor={actorKey}; "
              f"{len(_eps)} endpoints за {NONHUMAN_TEMPO_WINDOW_SEC}с "
              f"→ рішення виносить ШІ", flush=True)

    # Read the body ONCE (Flask caches get_data — forward gets the same).
    # The backstop scans DEEPER (payload not only at the start), the AI — only a 2KB preview.
    _raw_body = request.get_data(as_text=True)[:BACKSTOP_BODY_BYTES] if request.content_length else ""
    body = _raw_body[:AI_BODY_PREVIEW]   # превʼю для ШІ

    # ─── Deterministic PAYLOAD BACKSTOP (path OR body) ────────────────────────
    # Guarantee: the AI cannot be tricked (prompt-injection) into passing an UNAMBIGUOUS
    # payload. L1 matches only the path; SQLi/SSTI in the POST BODY bypass it and reach
    # the AI — here a deterministic override blocks them regardless of the AI verdict.
    if hard_payload_present(inspectPath, _raw_body):
        ac = classify_hard_payload(inspectPath, _raw_body) or "payload_injection"
        latency = round((time.perf_counter() - t0) * 1000, 2)
        bump("blocked_fast", attack_class=ac)
        bump("latency_sum_ms", latency)
        log_decision({
            "tier": "FastReflex", "verdict": "BLOCK", "method": method,
            "path": fullPath, "client_ip": clientIp, "attack_class": ac,
            "reason": "Однозначний payload у шляху/тілі — детермінований бэкстоп (ШІ не обдурити)",
            "signal": "payload_backstop", "latency_ms": latency,
        })
        print(f"  🔴 BLOCK [backstop payload] {method} {fullPath} → {ac} ({latency}ms)",
              flush=True)
        resp = make_block_response(
            {"attack_class": ac,
             "reason": "Однозначний шкідливий payload у шляху/тілі (детермінований бэкстоп)"},
            "FastReflex")
        resp.headers["X-Immune-Score"] = "1.0"
        return resp

    # ─── Layer 2: AIAnalyst (for INSPECT) ─────────────────────────────────────
    if verdict == "INSPECT":
        bump("inspected")
        behavior = {
            "client_ip":     clientIp,
            # server signal: how many times this IP reached AI analysis in the window
            # (a secondary hint of "recent suspiciousness", not a full traffic counter)
            "recent_count":  _recent_ip_count(clientIp),
            "cast_count":    reflex.cast_count(sessionId or clientIp),  # серверний сигнал
            "session_cookie_present": bool(sessionId),       # клієнтський (непідтверджений)
            # SERVER-side session validation in Helios — the real authentication signal
            "session_validated": _validate_session(sessionId, fullPath),
            # BEHAVIORAL TRAJECTORY — to detect multi-step attacks/APT
            "trajectory": _trajectory_summary(actorKey, time.time()),
            # ANTIGEN: how many DIFFERENT IPs per one client fingerprint (IP rotation = evasion)
            "fp_distinct_ips": _fp_distinct_ips(fpKey, _now0),
            # NON-HUMAN TEMPO before a voter action (4+ endpoints <2s) — a strong APT signal
            "nonhuman_tempo": nonhuman_tempo,
        }
        aiDecision = analyst.analyze(method, inspectPath, headers, body, behavior)
        threat_score = float(aiDecision.get("confidence") or 0.0)
        # L1 learning: the AI synthesized a signature of a new pattern → FastReflex will
        # catch repeats instantly (adaptive→innate immunity)
        learned = aiDecision.get("learnable_signature")
        if learned and reflex.add_learned_signature(learned, aiDecision.get("attack_class")):
            print(f"  🧬 L1 ВИВЧИВ сигнатуру «{learned}» від ШІ "
                  f"({aiDecision.get('attack_class')})", flush=True)
        if aiDecision["verdict"] == "BLOCK":
            latency = round((time.perf_counter() - t0) * 1000, 2)
            bump("blocked_ai", attack_class=aiDecision.get("attack_class"))
            bump("latency_sum_ms", latency)
            log_decision({
                "tier": "AIAnalyst", "verdict": "BLOCK", "method": method,
                "path": fullPath, "client_ip": clientIp,
                "attack_class": aiDecision.get("attack_class"),
                "reason": aiDecision.get("reasoning"),
                "confidence": aiDecision.get("confidence"),
                "from_cache": aiDecision.get("from_cache"),
                "session_validated": behavior.get("session_validated"),
                "latency_ms": latency,
            })
            if aiDecision.get("rate_capped"):
                tag = "rate-cap"
            elif aiDecision.get("fail_closed"):
                tag = "fail-closed"
            elif aiDecision.get("from_cache"):
                tag = "cache"
            else:
                tag = "ШІ"
            print(f"  🔴 BLOCK [L2 {tag}] {method} {fullPath} "
                  f"→ {aiDecision.get('attack_class')} "
                  f"conf={aiDecision.get('confidence')} ({latency}ms)", flush=True)
            resp = make_block_response(aiDecision, "AIAnalyst")
            resp.headers["X-Immune-Score"] = str(round(threat_score, 4))
            return resp
        # the AI allowed it
        if not aiDecision.get("from_cache"):
            print(f"  🟡 INSPECT→ALLOW [L2 ШІ] {method} {fullPath} "
                  f"({aiDecision.get('latency_ms')}ms)", flush=True)

    # ─── ALLOW: forward to Helios ─────────────────────────────────────────────
    response = forward_to_helios(path)
    response.headers["X-Immune-Score"] = str(round(threat_score, 4))   # для ROC
    latency = round((time.perf_counter() - t0) * 1000, 2)
    bump("allowed")
    bump("latency_sum_ms", latency)
    return response


# ─── Entry point ──────────────────────────────────────────────────────────────

def _serve():
    """
    Start the server. If waitress (production WSGI) is available — use it;
    otherwise — the Flask dev server (PoC) with an explicit warning.
    Force dev mode: --dev.
    """
    use_dev = "--dev" in sys.argv
    if not use_dev:
        try:
            from waitress import serve as waitress_serve
            print("  Сервер: waitress (production WSGI), threads=8")
            print("=" * 68)
            # IMPORTANT: by default waitress STRIPS X-Forwarded-For
            # (clear_untrusted_proxy_headers=True) → the proxy would see everyone as 127.0.0.1,
            # and per-IP tracking (rate-cap, trajectory/tempo) would collapse. We trust
            # XFF from a TRUSTED peer (here — localhost; in prod set your LB's IP).
            waitress_serve(app, host=LISTEN_HOST, port=PROXY_PORT, threads=8,
                           trusted_proxy=LISTEN_HOST,
                           trusted_proxy_headers={"x-forwarded-for"},
                           clear_untrusted_proxy_headers=True)
            return
        except ImportError:
            print("  ⚠️  waitress не встановлено → Flask dev-сервер (PoC).")
            print("     Для production: pip install waitress")
    print("  Сервер: Flask dev (⚠️ PoC, НЕ для production deployment)")
    print("=" * 68)
    app.run(host=LISTEN_HOST, port=PROXY_PORT, threaded=True)


if __name__ == "__main__":
    print("=" * 68)
    print("  🛡  IMMUNE PROXY — Цифрова імунна система (inline real-time)")
    print(f"  Слухає:  http://localhost:{PROXY_PORT}  (атакуючі б'ють сюди)")
    print(f"  Backend: {HELIOS_BACKEND}  (справжній Helios)")
    print(f"  ШІ-аналітик: {'УВІМКНЕНО (' + CLAUDE_MODEL + ')' if analyst.enabled else 'ВИМКНЕНО (немає API ключа)'}")
    print(f"  Метрики: http://localhost:{PROXY_PORT}/__immune__/stats")
    print("=" * 68)
    print("  Рівні захисту:")
    print("    L1 FastReflex — rate, concurrency, payload-блок (~1ms)")
    print("    L2 AIAnalyst  — Claude розмірковує про намір (підозрілі)")
    print("    Кеш вердиктів — повторні патерни ловить L1 миттєво")
    print("  Активні фічі (build v8): login→ALLOW · темп→ШІ(INSPECT, не хард-блок) · "
          "актор=IP (XFF-trust) · decode-payload · admin/tally детерм. · "
          "payload-бэкстоп(тіло 64КБ) · fp-антиген · anti-exfil · session-breaker · "
          f"/metrics(Prometheus) · verbose-blocks={'on' if VERBOSE_BLOCKS else 'off'} · XFF→Helios=clientIP")
    print("=" * 68)
    _serve()
