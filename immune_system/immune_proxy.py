"""
Модуль: ImmuneProxy — inline reverse-proxy цифрової імунної системи
Цифрова імунна система — immune_system/immune_proxy.py

Стоїть на порту 8000 ПЕРЕД Helios (порт 8001). Кожен запит проходить через
дворівневий захист у реальному часі:

  Запит → :8000 ImmuneProxy
            ↓
   Уровень 1: FastReflex (~1ms)  → ALLOW / BLOCK / INSPECT
            ↓ (INSPECT)
   Уровень 2: AIAnalyst (Claude) → ALLOW / BLOCK
            ↓ (ALLOW)
   форвард → :8001 Helios → відповідь назад
            (BLOCK)
   → 403 Forbidden, запит НЕ доходить до Helios

Запуск:  python immune_system/immune_proxy.py
Метрики: GET http://localhost:8000/__immune__/stats
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

# Автозавантаження .env (ключ ANTHROPIC_API_KEY) до ініціалізації AIAnalyst
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env
load_env()

import requests
from flask import Flask, request, Response, jsonify

from fast_reflex import FastReflex, RATE_WINDOW_SEC, CONCURRENCY_WINDOW_SEC
from ai_analyst import AIAnalyst, DEFAULT_MODEL
from threat_patterns import hard_payload_present, classify_hard_payload


# ─── Конфігурація ─────────────────────────────────────────────────────────────

from env_loader import load_config

_cfg = load_config()
PROJECT_ROOT  = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
LOGS_DIR      = PROJECT_ROOT / _cfg.get("paths", {}).get("logs_dir", "logs")
CLAUDE_MODEL  = _cfg.get("claude", {}).get("model", DEFAULT_MODEL)
CLAUDE_EFFORT = _cfg.get("claude", {}).get("effort", "low")   # глибина L2-міркування
# окремий ліміт для ШІ-судді (НЕ плутати з claude.max_tokens=7000 для генерації):
# з adaptive thinking токени йдуть і на міркування — 512 обрізало б JSON-вердикт.
JUDGE_MAX_TOKENS = _cfg.get("claude", {}).get("judge_max_tokens", 2048)

_proxy_cfg     = _cfg.get("immune_proxy", {})
LISTEN_HOST    = _proxy_cfg.get("listen_host", "127.0.0.1")
PROXY_PORT     = _proxy_cfg.get("listen_port", 8000)
HELIOS_BACKEND = _proxy_cfg.get("helios_backend", "http://localhost:8001")
MAX_BODY_BYTES = _proxy_cfg.get("max_body_bytes", 5 * 1024 * 1024)   # 5 МБ
# Таймаут форварду до Helios. Було 30с: при threads=8 вісім повільних відповідей
# бекенду вичерпали б пул воркерів (thread-starvation DoS). 10с — розумний стель
# для e-voting (view/cast швидкі); повільніше = або перевантажений Helios, або атака.
FORWARD_TIMEOUT_SEC = _proxy_cfg.get("forward_timeout_sec", 10)
AI_BODY_PREVIEW = 2000          # скільки байтів тіла подавати ШІ
BLOCKS_LOG     = LOGS_DIR / "immune_blocks.jsonl"

# Інʼєкція безпечних HTTP-заголовків у КОЖНУ відповідь (захист браузера виборця:
# XSS, clickjacking, MITB/CDN-compromise, sniffing). Стандартний контроль OWASP.
SECURITY_HEADERS_ENABLED = _proxy_cfg.get("security_headers_enabled", True)
SECURITY_HEADERS = _proxy_cfg.get("security_headers") or {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    # HSTS дієвий лише поверх TLS (браузер ігнорує по HTTP) — додаємо на майбутнє
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # script-src 'self' блокує ЗОВНІШНІ скрипти (CDN-compromise/MITB-вектор);
    # frame-ancestors 'none' — анти-clickjacking; object-src 'none' — без плагінів.
    # 'unsafe-inline'/'eval' лишаємо, бо криптографія Helios — інлайн-JS у браузері.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    ),
}

# Огрублення timestamp на ballot board: публічний cast_at розкриває точний час
# подачі → timing-деанонімізація. Округлюємо до години у відповідях /ballots/.
COARSEN_BALLOT_TS = _proxy_cfg.get("coarsen_ballot_timestamps", True)

# Інспекція ВІДПОВІДЕЙ (анти-ексфільтрація PII). Захист даних голосування — це не
# лише «не пустити запис», а й «не дати масово ВИТЕКТИ» списку виборців/бюлетенів.
# Аномально великий дамп на /voters/ чи /ballots/ — ознака harvest/ексфільтрації.
#   soft → лише позначка (лог+метрика+заголовок), віддаємо відповідь (FP-safe);
#   hard → блок 403 (за замовчуванням ВИМКНЕНО: 0, щоб не зрізати легіт-обсяги).
EXFIL_INSPECT_PATHS = ("/voters/", "/ballots/")
EXFIL_SOFT_BYTES = _proxy_cfg.get("exfil_soft_bytes", 256 * 1024)   # 256 КБ → підозра
EXFIL_HARD_BYTES = _proxy_cfg.get("exfil_hard_bytes", 0)            # 0 = блок вимкнено

# Verbose-блоки: чи повертати атакувальнику attack_class + reason у тілі 403.
# DEMO/лабораторія (True) — зручно для adaptive_generator та звітів; ПРОД (False) —
# не підказувати зловмиснику, ЩО саме спрацювало (мінімальна 403 без деталей детекції).
VERBOSE_BLOCKS = _proxy_cfg.get("verbose_blocks", True)

# Скільки байтів ТІЛА сканувати детермінованим бэкстопом (payload не лише на початку).
# Окремо від AI_BODY_PREVIEW (превʼю для ШІ лишається 2КБ) — бэкстоп дивиться глибше.
BACKSTOP_BODY_BYTES = _proxy_cfg.get("backstop_body_bytes", 64 * 1024)   # 64 КБ
# Опц. токен для /__immune__/stats (порожній = без авторизації; проксі слухає
# 127.0.0.1, тож не назовні — але в проді задай токен у config.json).
STATS_TOKEN = _proxy_cfg.get("stats_token", "")
_TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}):\d{2}:\d{2}(?:\.\d+)?')

LOGS_DIR.mkdir(exist_ok=True)

# Заголовки, які не можна форвардити (hop-by-hop)
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}


# ─── Компоненти ───────────────────────────────────────────────────────────────

app = Flask(__name__)
# Захист від memory-DoS: відхиляємо тіла понад межу (Flask поверне 413)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
reflex = FastReflex()
analyst = AIAnalyst(model=CLAUDE_MODEL, memory_db=LOGS_DIR / "ai_memory.db",
                    effort=CLAUDE_EFFORT, max_tokens=JUDGE_MAX_TOKENS)

# Вікно ПІДОЗРІЛИХ запитів від IP (вторинний сигнал для ШІ). УВАГА: поповнюється
# лише на шляху INSPECT (_recent_ip_count зветься тільки перед L2), тож це «скільки
# разів цей IP дійшов до ШІ-аналізу за вікно», а НЕ повний лічильник усіх запитів —
# справжній rate-limit робить FastReflex (L1). Для ШІ це підказка «недавня підозріла
# активність», не точний обсяг трафіку.
_ip_window = defaultdict(deque)
MAX_TRACKED_IPS = 10000   # межа для захисту від memory-DoS (евікція найстаріших)

# Поведінкова ТРАЄКТОРІЯ актора (session|IP): послідовність і темп останніх запитів.
# Дає ШІ контекст для виявлення БАГАТОКРОКОВИХ атак / APT-розвідки (recon→login→cast
# за секунди), які поштучно виглядають невинно. Серверний сигнал (виміряний проксі).
_actor_history = defaultdict(deque)   # actor → deque[(ts, method, label)]
MAX_TRAJ_ENTRIES = 12                  # скільки останніх кроків тримати на актора
TRAJ_WINDOW_SEC = 60.0                 # горизонт траєкторії
# Детермінований темп-фільтр (нелюдський темп = бот/APT). Єдине джерело порогу —
# і прод-шлях, і тести користуються цими константами (без дублювання «магічних 4/2с»).
NONHUMAN_TEMPO_WINDOW_SEC = 2.0        # вікно вимірювання темпу
NONHUMAN_TEMPO_THRESHOLD = 4           # ≥N різних endpoint за вікно = нелюдина

# Антиген-кореляція: відбиток клієнта → недавні IP (для виявлення ротації IP).
_fp_history = defaultdict(deque)       # fp → deque[(ts, ip)]
FP_WINDOW_SEC = 60.0
_UUID_RE2 = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
# довгий ОДИН сегмент (ballot hash тощо) — БЕЗ '/', щоб не з'їдати «helios/elections»
_HASH_RE2 = re.compile(r'/[A-Za-z0-9+=_-]{20,}')

# Метрики + єдиний лок (Flask threaded=True → мутації мають бути атомарними)
_state_lock = threading.Lock()
metrics = {
    "total": 0, "allowed": 0,
    "blocked_fast": 0, "blocked_ai": 0,
    "inspected": 0, "errors": 0,
    "exfil_suspected": 0,         # підозра на ексфільтрацію (аномальний дамп у відповіді)
    "latency_sum_ms": 0.0,
    "by_attack_class": defaultdict(int),
}


# SOC-алерти: лог-попередження при перетині порогів (для чергової зміни/SIEM).
# Спрацьовує один раз на кожен рівень (×поріг), щоб не спамити.
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
    """Атомарне інкрементування метрик (+ SOC-алерт при перетині порогу)."""
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


# ─── Логування рішень ─────────────────────────────────────────────────────────

# Ротація журналів за розміром (захист від необмеженого росту immune_blocks.jsonl).
MAX_LOG_BYTES = 50 * 1024 * 1024   # 50 МБ на файл
LOG_BACKUPS   = 5                  # скільки ротованих копій тримати (.1 … .5)


def _rotate_if_needed(path: Path):
    """Ротує журнал, якщо він переріс MAX_LOG_BYTES (file → file.1 → … → file.N)."""
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


# Маскування ідентифікаторів виборця/бюлетеня у шляху перед логуванням.
# Таємниця голосування: журнал НЕ повинен звʼязувати конкретного виборця
# (voter_uuid) чи його бюлетень (ballot_hash) з дією/часом. Election UUID
# не маскуємо — він публічний.
_VOTER_SEG_RE  = re.compile(r"(/voters/)[^/?#]+", re.IGNORECASE)
_BALLOT_SEG_RE = re.compile(r"(/ballots/)[^/?#]+", re.IGNORECASE)


def _redact_pii(path: str) -> str:
    """Маскує voter_uuid та ballot_hash у шляху (приватність журналу)."""
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
    """Витягує IP клієнта з X-Forwarded-For. XFF може бути ланцюгом
    'client, proxy1, proxy2' — беремо ПЕРШИЙ (реального клієнта), інакше один
    і той самий клієнт із різними proxy-хвостами розщепив би трекінг."""
    if xff_header:
        first = xff_header.split(",")[0].strip()
        if first:
            return first
    return remote_addr or "127.0.0.1"


def _client_ip() -> str:
    return _parse_client_ip(request.headers.get("X-Forwarded-For"), request.remote_addr)


def _session_id() -> str:
    return request.cookies.get("sessionid", "")


# Поведінковий «антиген» актора: відбиток клієнта за НАБОРОМ/ПОРЯДКОМ заголовків
# + ключові значення (UA/Accept*). Дозволяє корелювати активність НЕ лише за IP:
# адреса змінна (ротація підмережі — типове ухилення APT), а відбиток HTTP-клієнта
# стабільний. Слабкий сам по собі для БЛОКУ (багато виборців можуть мати однаковий
# браузер), тож використовується як СИГНАЛ ШІ (скільки IP за одним відбитком), а не
# як детермінований блок — щоб не зачепити легіт-виборців за спільним UA.
_FP_VALUE_HEADERS = ("User-Agent", "Accept", "Accept-Language", "Accept-Encoding")


def _client_fingerprint(headers) -> str:
    order = ",".join(k.lower() for k in headers.keys())
    values = "|".join(str(headers.get(h, "")) for h in _FP_VALUE_HEADERS)
    raw = (values + "||" + order).encode("utf-8", "replace")
    return "fp:" + hashlib.sha1(raw).hexdigest()[:16]


# ─── Поведінкова траєкторія актора (для ШІ) ───────────────────────────────────

def _endpoint_label(path: str) -> str:
    """Компактна мітка endpoint (UUID/hash замасковані) для траєкторії."""
    p = _UUID_RE2.sub("{id}", path)
    p = _HASH_RE2.sub("/{hash}", p)
    return p[:60]


def _record_request(actor: str, method: str, path: str, now: float):
    """Реєструє крок актора у траєкторію (потокобезпечно, з евікцією)."""
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
    """Відсортований список РІЗНИХ endpoint актора у вікні (єдине джерело темп-логіки
    для прод-шляху і тестів)."""
    with _state_lock:
        return sorted({e[2] for e in _actor_history.get(actor, ()) if now - e[0] <= window})


def _nonhuman_tempo(actor: str, now: float,
                    window: float = NONHUMAN_TEMPO_WINDOW_SEC,
                    threshold: int = NONHUMAN_TEMPO_THRESHOLD) -> bool:
    """Детермінований сигнал бота: ≥threshold РІЗНИХ endpoint за <window (людина
    фізично не може). FP-safe: легітимний виборець не клацає 4 сторінки за 2с."""
    return len(_recent_distinct_endpoints(actor, now, window)) >= threshold


def _record_fingerprint(fp: str, ip: str, now: float):
    """Реєструє IP під відбитком клієнта (антиген) — для виявлення ротації IP."""
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
    """Скільки РІЗНИХ IP використав цей відбиток за вікно (>1 за секунди = ротація IP)."""
    with _state_lock:
        return len({ip for ts, ip in _fp_history.get(fp, ()) if now - ts <= window})


def _trajectory_summary(actor: str, now: float) -> str:
    """Текстове зведення останніх кроків актора (для промпту ШІ)."""
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
    # явний детермінований сигнал нелюдського темпу — щоб ШІ не сплутав recon-маскування
    # з людським переглядом: 4+ різних endpoint за <2с фізично неможливі для людини
    if distinct >= 4 and span < 2.0:
        header = ("⚠ НЕЛЮДСЬКИЙ ТЕМП (автоматизація/бот: фізично неможливо для людини) — "
                  + header)
    return header + ":\n" + "\n".join(lines)


# Валідація сесії у Helios з TTL-кешем. Позитивний результат кешуємо надовго,
# негативний — коротко: інакше анонімна сесія, перевірена ДО логіну, отруїть кеш
# на той самий sessionid після логіну (Helios переви.користовує ключ сесії).
_session_cache = {}          # sessionid → (is_valid: bool, expiry: float)
SESSION_TTL_VALID = 30.0     # дійсна сесія лишається дійсною
SESSION_TTL_INVALID = 3.0    # недійсну перевіряємо часто (вікно після логіну)
SESSION_CACHE_MAX = 5000

# Circuit-breaker валідації сесій: кожна невалідна сесія тригерить blocking-call до
# Helios. Під флудом унікальних cookie це амплифікує навантаження на backend і додає
# латентність у L2. Якщо Helios підряд відмовляє/таймаутить — РОЗМИКАЄМО ланцюг:
# певний час валідацію не викликаємо (повертаємо False швидко). Login/cast і так
# ALLOW-by-default, тож «не валідовано» не дає false-positive.
HELIOS_CB_FAIL_THRESHOLD = 3     # стільки збоїв підряд → розмикання
HELIOS_CB_OPEN_SEC = 10.0        # на скільки розмикаємо (не звертаємось до Helios)
HELIOS_CB_TIMEOUT = 3.0          # таймаут одного validation-call (було 5с)
_helios_cb = {"fails": 0, "open_until": 0.0}


def _cb_is_open(now: float) -> bool:
    with _state_lock:
        return now < _helios_cb["open_until"]


def _cb_record_fail(now: float):
    """Реєструє збій Helios; при порозі — розмикає ланцюг на HELIOS_CB_OPEN_SEC."""
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
    Перевіряє, чи cookie відповідає РЕАЛЬНО автентифікованому виборцю Helios
    (серверний сигнал, не підробити). Сесії Helios привʼязані до ВИБОРІВ, тому
    валідуємо через election view, а не глобальний /auth/. Кеш на 30с + breaker.
    """
    if not session_id:
        return False
    now = time.time()
    cache_key = session_id
    with _state_lock:
        ent = _session_cache.get(cache_key)
        if ent and now < ent[1]:
            return ent[0]
    # Circuit-breaker розімкнено (Helios нездоровий) → не амплифікуємо навантаження,
    # повертаємо False швидко (не кешуємо — щоб перевірити знову після відновлення).
    if _cb_is_open(now):
        return False
    # визначаємо election зі шляху запиту (інакше валідація неможлива)
    m = _ELECTION_RE.search(req_path or "")
    valid = False
    if m:
        uuid = m.group(1)
        try:
            r = requests.get(f"{HELIOS_BACKEND}/helios/elections/{uuid}/view",
                             cookies={"sessionid": session_id},
                             timeout=HELIOS_CB_TIMEOUT, allow_redirects=False)
            body = r.text.lower()
            # анонім бачить login-gate / редірект; залогінений виборець — ні
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
        # Евікція мертвих IP (захист від memory-DoS): прибираємо порожні
        # та найстаріші ключі, якщо словник переріс межу.
        if len(_ip_window) > MAX_TRACKED_IPS:
            stale = [k for k, v in _ip_window.items() if not v]
            for k in stale:
                del _ip_window[k]
            # якщо все ще завелико — видаляємо найстаріші за останнім таймстампом
            if len(_ip_window) > MAX_TRACKED_IPS:
                oldest = sorted(_ip_window.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
                for k, _ in oldest[: len(_ip_window) - MAX_TRACKED_IPS]:
                    del _ip_window[k]
    return count


# ─── Блокування ───────────────────────────────────────────────────────────────

def make_block_response(decision: dict, tier: str) -> Response:
    body = {
        "error": "Forbidden — Digital Immune System",
        "incident_time": datetime.now(timezone.utc).isoformat(),
    }
    # Деталі детекції (attack_class/reason/рівень) — лише у VERBOSE-режимі (демо/звіти).
    # У проді не підказуємо зловмиснику, ЩО саме спрацювало (мінімізуємо oracle для
    # обходу). Журнал/метрики все одно фіксують повну причину серверно.
    if VERBOSE_BLOCKS:
        body["blocked_by"] = tier
        body["attack_class"] = decision.get("attack_class")
        body["reason"] = decision.get("reason") or decision.get("reasoning")
    return Response(json.dumps(body, ensure_ascii=False),
                    status=403, content_type="application/json")


# ─── Форвардинг до Helios ─────────────────────────────────────────────────────

_BACKEND_HOST = urlsplit(HELIOS_BACKEND).netloc


def _safe_backend_url(path: str):
    """
    Будує URL до backend, гарантуючи що шлях НЕ виходить за межі бекенда
    (захист від SSRF / path-escape). Повертає url або None, якщо підозріло.
    """
    # абсолютний URL / protocol-relative / backslash — заборонено
    if "://" in path or path.startswith("//") or "\\" in path:
        return None
    # будь-який сегмент ".." — заборонено (строго, без спроб нормалізації)
    if ".." in path.split("/"):
        return None
    clean = posixpath.normpath("/" + path).lstrip("/")
    if clean.startswith(".."):
        return None
    url = f"{HELIOS_BACKEND}/{clean}"
    # фінальна перевірка: host має лишитися backend-host
    if urlsplit(url).netloc != _BACKEND_HOST:
        return None
    return url


def _exfil_verdict(path: str, method: str, size: int) -> str:
    """Класифікує ВІДПОВІДЬ на чутливому list-endpoint за обсягом:
    'block' (hard), 'flag' (soft) або '' (норма). Чиста функція — тестується без серверів."""
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
    # Проксі — межа довіри: ПЕРЕЗАПИСУЄМО X-Forwarded-For на РЕАЛЬНИЙ IP клієнта
    # (інакше клієнтський спуфнутий XFF пройшов би до Helios і отруїв би його логи/
    # rate-логіку). Single-hop: бекенд бачить лише наш висновок про джерело.
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
    # Огрублення timestamp на ballot board (приватність: проти timing-деанону)
    ctype = resp.headers.get("Content-Type", "")
    if (COARSEN_BALLOT_TS and "/ballots" in path
            and any(t in ctype for t in ("json", "text", "html"))):
        content = _coarsen_timestamps(content)
    # Інспекція відповіді на ексфільтрацію (аномально великий дамп списку)
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
    """Округлює ISO-timestamp до години (HH:MM:SS → HH:00:00) у тілі відповіді.
    Безпечно: при будь-якій помилці повертає оригінал без змін."""
    try:
        text = body.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return body
    return _TS_RE.sub(r"\1:00:00", text).encode("utf-8")


@app.after_request
def _add_security_headers(resp):
    """Інʼєкція безпечних заголовків у КОЖНУ відповідь (захист браузера виборця)."""
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


# ─── Головний маршрут (catch-all) ─────────────────────────────────────────────

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
    """Експорт метрик у Prometheus text-форматі (для scrape SOC/Grafana)."""
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
    # розбивка блоків за класом атаки (label)
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
    # повний шлях із query-рядком — щоб FastReflex/ШІ бачили інʼєкції в параметрах.
    # ДЕКОДУЄМО %-кодування для ДЕТЕКЦІЇ (форвардиться оригінал): інакше %20-SQL
    # ('union%20select') та %7B-SSTI ('%7B%7B') проходили б повз патерни.
    inspectPath = fullPath
    if request.query_string:
        inspectPath = fullPath + "?" + request.query_string.decode("utf-8", "replace")
    inspectPath = unquote(inspectPath)
    headers  = dict(request.headers)
    clientIp = _client_ip()
    sessionId = _session_id()
    # Актор для траєкторії/темпу — clientIp (server-наблюдаемое джерело), НЕ cookie:
    # інакше атакувальник уникав би поведінкового трекінгу, ротуючи sessionid-cookie.
    actorKey = clientIp
    _now0 = time.time()
    _record_request(actorKey, method, fullPath, _now0)         # поведінкова траєкторія
    # Антиген-кореляція: реєструємо IP під відбитком клієнта (анти-ротація IP).
    fpKey = _client_fingerprint(request.headers)
    _record_fingerprint(fpKey, clientIp, _now0)

    # ─── Уровень 1: FastReflex ────────────────────────────────────────────────
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

    # ─── Поведінковий сигнал: нелюдський темп (бот/APT-розвідка) ───────────────
    # Для ДІЙ ВИБОРЦЯ (login/cast): якщо актор перед дією прокрутив 4+ різних
    # endpoint за <2с — це підозра на автоматизовану recon→дію. АЛЕ це НЕ хард-блок:
    # у e-voting хибне блокування = позбавлення голосу, а швидкий-але-легітимний
    # виборець теж можливий. Тому темп ЕСКАЛЮЄ на ШІ (INSPECT), який бачить ПОВНУ
    # траєкторію (+прапор темпу) і відрізняє recon-sweep від voter-flow.
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

    # Тіло читаємо ОДИН раз (Flask кешує get_data — forward отримає те саме).
    # Бэкстоп сканує ГЛИБШЕ (payload не лише на початку), ШІ — лише превʼю 2КБ.
    _raw_body = request.get_data(as_text=True)[:BACKSTOP_BODY_BYTES] if request.content_length else ""
    body = _raw_body[:AI_BODY_PREVIEW]   # превʼю для ШІ

    # ─── Детермінований PAYLOAD-БЭКСТОП (path АБО ТІЛО) ────────────────────────
    # Гарантія: ШІ НЕ можна обманути (prompt-injection) у бік пропуску ОДНОЗНАЧНОГО
    # payload. L1 матчить лише path; SQLi/SSTI у ТІЛІ POST його обходять і доходять
    # до ШІ — тут детермінований override блокує їх незалежно від вердикту ШІ.
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

    # ─── Уровень 2: AIAnalyst (для INSPECT) ───────────────────────────────────
    if verdict == "INSPECT":
        bump("inspected")
        behavior = {
            "client_ip":     clientIp,
            # серверний сигнал: скільки разів цей IP дійшов до ШІ-аналізу за вікно
            # (вторинна підказка «недавня підозрілість», не повний лічильник трафіку)
            "recent_count":  _recent_ip_count(clientIp),
            "cast_count":    reflex.cast_count(sessionId or clientIp),  # серверний сигнал
            "session_cookie_present": bool(sessionId),       # клієнтський (непідтверджений)
            # СЕРВЕРНА валідація сесії у Helios — справжній сигнал автентифікації
            "session_validated": _validate_session(sessionId, fullPath),
            # ПОВЕДІНКОВА ТРАЄКТОРІЯ — для виявлення багатокрокових атак/APT
            "trajectory": _trajectory_summary(actorKey, time.time()),
            # АНТИГЕН: скільки РІЗНИХ IP за одним відбитком клієнта (ротація IP = ухилення)
            "fp_distinct_ips": _fp_distinct_ips(fpKey, _now0),
            # НЕЛЮДСЬКИЙ ТЕМП перед дією виборця (4+ endpoint <2с) — сильний сигнал APT
            "nonhuman_tempo": nonhuman_tempo,
        }
        aiDecision = analyst.analyze(method, inspectPath, headers, body, behavior)
        threat_score = float(aiDecision.get("confidence") or 0.0)
        # Навчання L1: ШІ синтезував сигнатуру нового патерну → FastReflex ловитиме
        # повторні миттєво (adaptive→innate immunity)
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
        # ШІ дозволив
        if not aiDecision.get("from_cache"):
            print(f"  🟡 INSPECT→ALLOW [L2 ШІ] {method} {fullPath} "
                  f"({aiDecision.get('latency_ms')}ms)", flush=True)

    # ─── ALLOW: форвард до Helios ─────────────────────────────────────────────
    response = forward_to_helios(path)
    response.headers["X-Immune-Score"] = str(round(threat_score, 4))   # для ROC
    latency = round((time.perf_counter() - t0) * 1000, 2)
    bump("allowed")
    bump("latency_sum_ms", latency)
    return response


# ─── Entry point ──────────────────────────────────────────────────────────────

def _serve():
    """
    Запускає сервер. Якщо доступний waitress (production WSGI) — використовує
    його; інакше — Flask dev-сервер (PoC) з явним попередженням.
    Примусово dev-режим: --dev.
    """
    use_dev = "--dev" in sys.argv
    if not use_dev:
        try:
            from waitress import serve as waitress_serve
            print("  Сервер: waitress (production WSGI), threads=8")
            print("=" * 68)
            # ВАЖЛИВО: за замовчуванням waitress ВИРІЗАЄ X-Forwarded-For
            # (clear_untrusted_proxy_headers=True) → проксі бачив би всіх як 127.0.0.1,
            # і per-IP трекінг (rate-cap, траєкторія/темп) схлопувався б. Довіряємо
            # XFF від ДОВІРЕНОГО peer (тут — localhost; у проді вкажи IP свого LB).
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
