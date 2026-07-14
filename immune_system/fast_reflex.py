"""
Модуль: FastReflex — Уровень 1 цифрової імунної системи
Цифрова імунна система — immune_system/fast_reflex.py

Швидкий рефлекторний шар (аналог вродженого імунітету).
Приймає рішення за ~1ms на основі:
  - сигнатур чутливих endpoint + патернів
  - rate-вікон (ковзне вікно запитів по IP)
  - concurrency-детектора (одночасні POST /cast = race condition)

Повертає вердикт: ALLOW / BLOCK / INSPECT
  ALLOW   — явно безпечно, пропустити
  BLOCK   — явна атака, дропнути миттєво (403)
  INSPECT — підозріло, але неясно → передати на Уровень 2 (ШІ-аналітик)
"""

import time
import threading
from collections import defaultdict, deque, OrderedDict

from threat_patterns import is_path_traversal, anomaly_payload_match, l1_block_match


# ─── Конфігурація детекції ────────────────────────────────────────────────────

# Чутливі endpoint, де можливі атаки
SENSITIVE_PATTERNS = {
    "/auth/devlogin/login":   "impersonation",
    "/upload-decryption":     "csrf_trustee_takeover",
    "/cast":                  "ballot_stuffing",
    "/password_voter_login":  "voter_suppression_targeted",
    "/auth/password/login":   "voter_phishing_credential",
    # критичні адмін-операції життєвого циклу виборів → завжди на ШІ-аналіз
    "/encrypt_tally":         "tally_manipulation",
    "/freeze":                "manipulation",
    "/combine_decryptions":   "tally_manipulation",
}

# Ліміти rate (запитів за вікно)
RATE_WINDOW_SEC = 10.0          # розмір ковзного вікна
RATE_LIMITS = {
    "/cast":                 8,   # >8 cast за 10с = флуд/race
    "/auth/password/login":  10,  # >10 логінів за 10с = brute-force/suppression
    "/password_voter_login": 10,
    "/voters/":              15,  # >15 запитів списку = harvest (phishing recon)
    "/ballots/":             25,  # >25 за 10с = масовий збір бюлетенів (timing-деанон recon)
    "_default":              60,  # загальний ліміт на IP
}

# Admin-only операції підрахунку: легітимний ВИБОРЕЦЬ їх не викликає → детермінований
# L1-блок (а не «монетка ШІ»). ШІ лишається для голосу/логіну/поведінки виборця.
ADMIN_ONLY_ENDPOINTS = ("/encrypt_tally", "/freeze", "/combine_decryptions")

# Endpoint логіну: rate-ліміт рахується ЛИШЕ для POST (реальні спроби входу).
# GET цих шляхів — це показ форми (Helios сам редиректить на неї), не атака.
LOGIN_ENDPOINTS = ("/auth/password/login", "/password_voter_login")

# Concurrency: одночасні POST /cast від однієї сесії
CONCURRENCY_WINDOW_SEC = 2.0    # «одночасними» вважаємо запити в межах 2с
CONCURRENCY_THRESHOLD = 3       # ≥3 cast за 2с від однієї сесії = race condition

MAX_TRACKED_KEYS = 20000        # межа словників вікон (захист від memory-DoS)
EVICT_EVERY = 2000              # періодичність прибирання мертвих ключів


class FastReflex:
    """Швидкий рефлекторний шар — рішення за мілісекунди, потокобезпечний."""

    def __init__(self):
        self._lock = threading.Lock()
        # ковзні вікна часових міток: key=(ip, endpoint) → deque[timestamps]
        self._rate_windows = defaultdict(deque)
        # concurrency: key=(session, "/cast") → deque[timestamps]
        self._cast_windows = defaultdict(deque)
        self._req_since_evict = 0
        # Вивчені сигнатури: ШІ (L2) синтезує їх із заблокованих НОВИХ патернів,
        # і L1 блокує повторні миттєво (0мс). Аналог adaptive→innate immunity.
        self._learned = OrderedDict()       # sig(lower) → attack_class
        self._learned_hits = 0

    MAX_LEARNED = 2000

    def add_learned_signature(self, sig: str, attack_class: str) -> bool:
        """
        Додає синтезовану ШІ сигнатуру до L1 (потокобезпечно). Приймається лише
        однозначний контекстно-незалежний токен (ШІ викликається тільки коли
        _is_pattern_malicious=True), тож прямий L1-блок настільки ж безпечний,
        як і наявні hard-malicious патерни. Повертає True, якщо додано.
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

    # ─── Допоміжне ────────────────────────────────────────────────────────────

    def _evict_dead(self, now: float):
        """Прибирає порожні/застарілі ключі вікон (захист від memory-DoS).
        Викликається періодично під локом."""
        for store, window in ((self._rate_windows, RATE_WINDOW_SEC),
                              (self._cast_windows, CONCURRENCY_WINDOW_SEC)):
            dead = [k for k, dq in store.items()
                    if not dq or (now - dq[-1]) > window]
            for k in dead:
                del store[k]
            # жорстка межа, якщо словник усе ще завеликий
            if len(store) > MAX_TRACKED_KEYS:
                oldest = sorted(store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
                for k, _ in oldest[: len(store) - MAX_TRACKED_KEYS]:
                    del store[k]

    def _match_endpoint(self, path: str) -> str:
        """Повертає сигнатурний patttern, що міститься у path, або ''."""
        for pat in SENSITIVE_PATTERNS:
            if pat in path:
                return pat
        return ""

    def _rate_key_pattern(self, path: str, method: str) -> str:
        for pat in RATE_LIMITS:
            if pat == "_default" or pat not in path:
                continue
            # для login-endpoint спеціальний ліміт лише на POST (спроби входу);
            # GET форми логіну йде по загальному дефолтному ліміту
            if pat in LOGIN_ENDPOINTS and method != "POST":
                continue
            return pat
        return "_default"

    def _prune(self, dq: deque, now: float, window: float):
        while dq and (now - dq[0]) > window:
            dq.popleft()

    def _anomaly_signal(self, method: str, path: str):
        """
        Повертає (action, label, attack_class) або None:
          action="BLOCK"   — ОДНОЗНАЧНИЙ payload (легіт не шле) → L1 блокує сам (0мс);
          action="INSPECT" — НЕОДНОЗНАЧНЕ → рішення приймає ШІ (намір/поведінка).
        """
        low = path.lower()
        # ── ОДНОЗНАЧНІ payload → детермінований L1-БЛОК (не покладаємось на ШІ) ──
        if is_path_traversal(path):
            return ("BLOCK", "path_traversal", "path_traversal")
        tok, ac = l1_block_match(low)
        if tok:
            return ("BLOCK", f"hard:{tok}", ac)
        # ── ВИСОКОРИЗИКОВІ admin/verb → детермінований L1-БЛОК (не «монетка ШІ») ──
        # Легітимний ВИБОРЕЦЬ цього не робить; admin діє через окремий авторизований
        # канал, не через цей voter-facing проксі. Тож блокуємо однозначно й стабільно.
        if method in ("DELETE", "PUT", "PATCH", "TRACE") and "/helios/" in low:
            return ("BLOCK", f"dangerous_verb:{method}", "dangerous_verb")
        admin_paths = ["/delete", "/archive", "/admins", "/unfreeze", "/copy",
                       "/keygenerator", "/set_reg"]
        if method == "POST" and any(a in low for a in admin_paths):
            return ("BLOCK", "admin_lifecycle", "admin_lifecycle")
        # ── НЕОДНОЗНАЧНІ маркери (бувають у легіт) → ШІ вирішує ────────────────
        if anomaly_payload_match(low):
            return ("INSPECT", "injection_pattern", None)
        return None

    # ─── Головна оцінка ───────────────────────────────────────────────────────

    def evaluate(self, method: str, path: str, headers: dict,
                 client_ip: str, session_id: str) -> dict:
        """
        Оцінює один запит. Повертає dict:
          {verdict, reason, attack_class, signal, latency_ms}
        verdict ∈ {ALLOW, BLOCK, INSPECT}
        """
        t0 = time.perf_counter()
        now = time.time()
        method = method.upper()
        verdict, reason, attackClass, signal = "ALLOW", "", None, None

        with self._lock:
            # Періодична евікція мертвих ключів (захист від memory-DoS)
            self._req_since_evict += 1
            if self._req_since_evict >= EVICT_EVERY:
                self._req_since_evict = 0
                self._evict_dead(now)

            # 1. Concurrency-детектор: race condition на /cast
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

            # 2. Rate-вікно (якщо ще не заблоковано)
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

        # 2.5 Вивчені ШІ сигнатури — миттєвий L1-блок повторних нових атак (0мс).
        # Знімок під локом, потім скан БЕЗ лока (щоб не тримати глобальний лок на
        # O(N) substring-пошуку при великій кількості вивчених сигнатур).
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

        # 3. Сигнатурні евристики (поза локом — лише читання headers)
        if verdict == "ALLOW":
            sigPat = self._match_endpoint(path)
            if sigPat:
                # devlogin — вхід без пароля, у проді має бути вимкнено
                if sigPat == "/auth/devlogin/login" and method == "POST":
                    verdict = "BLOCK"
                    attackClass = "impersonation"
                    reason = "DevLogin POST — автентифікація без пароля (заборонено в проді)"
                    signal = "signature"
                # CSRF на trustee: зовнішній Referer
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
                # Admin-only підрахунок (tally/freeze/combine) → детермінований блок
                elif sigPat in ADMIN_ONLY_ENDPOINTS:
                    verdict = "BLOCK"
                    attackClass = SENSITIVE_PATTERNS.get(sigPat, "tally_manipulation")
                    reason = (f"Admin-only операція {sigPat} на voter-facing проксі — "
                              f"детермінований L1-блок (виборець її не викликає)")
                    signal = "admin_only"
                # Логін (GET форма + POST спроба) → ЛЕГІТИМНО на L1. Реальні атаки
                # на логін стереже rate-limit (флуд/suppression) та темп-фільтр
                # (бот recon→login); одиночна спроба виборця — норма (ALLOW, без ШІ,
                # щоб ШІ не давав хибних блокувань легітимного входу).
                elif sigPat in LOGIN_ENDPOINTS:
                    pass   # verdict лишається ALLOW
                # Інші чутливі endpoint (cast) → на ШІ-аналіз (намір голосу)
                else:
                    verdict = "INSPECT"
                    attackClass = SENSITIVE_PATTERNS.get(sigPat)
                    reason = f"Чутливий endpoint {sigPat} — потребує перевірки наміру"
                    signal = "sensitive"
            else:
                # Не каталогізований endpoint: перевіряємо ГЕНЕРИЧНІ аномалії.
                # FastReflex лише МАРШРУТИЗУЄ підозріле на ШІ (не блокує сам) —
                # фінальне рішення приймає ШІ своїм міркуванням. Це ловить НОВІ
                # атаки, яких немає ні в сигнатурах, ні в каталозі.
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
        """Потокобезпечна кількість недавніх POST /cast для сесії (для контексту ШІ)."""
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
