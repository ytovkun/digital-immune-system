"""
Модуль: threat_patterns — спільний каталог сигнатур загроз
Цифрова імунна система — immune_system/threat_patterns.py

Єдине джерело істини для патернів атак, які раніше дублювалися між
FastReflex (L1) та AIAnalyst (L2). Раніше ті самі токени (union select,
/etc/passwd, <script>, {{, ${ ...) жили у трьох окремих списках; оновлення
одного й забування іншого вело до рассинхрону детекції. Тепер усе тут.

Патерни розділені за СЕМАНТИКОЮ використання, а не змішані в один список:

  PAYLOAD_CORE             — однозначно шкідливі payload-сигнатури
                             (SQLi/XSS/traversal/RCE), які легітимний користувач
                             НІКОЛИ не надсилає. Спільне ядро для L1 і L2.
  HARD_MALICIOUS_PATTERNS  — контекстно-НЕЗАЛЕЖні загрози. Використовується L2
                             для рішення про КЕШОВАНІСТЬ вердикту. ВУЗЬКИЙ набір.
  ANOMALY_PATTERNS         — ШИРШИЙ набір для МАРШРУТИЗАЦІЇ на ШІ (L1 лише
                             відправляє на аналіз, не блокує сам).
  INJECTION_MARKERS        — спроби prompt-injection проти самого ШІ-судді.

ВАЖЛИВО — чому HARD і ANOMALY НЕ однакові:
  HARD має лишатися ВУЗЬКИМ. Широкі токени (';', \"'\", '--') НЕ можна додавати
  у HARD, бо вердикт BLOCK на /cast з таким токеном став би кешованим під
  загальним підписом /cast і отруїв би наступний ЛЕГІТИМНИЙ голос (false
  positive — позбавлення виборця голосу). Тому широкі токени живуть лише в
  ANOMALY (де хибне спрацювання означає тільки зайвий ШІ-аналіз, не блок).
"""

# ─── Однозначно шкідливе ядро (спільне для L1 та L2) ──────────────────────────
# Ці токени легітимний трафік не містить за жодних обставин.
PAYLOAD_CORE = [
    "/etc/passwd",
    "union select", "union+select",
    "or 1=1", "or+1=1",
    "<script", "<svg",
    "{{", "${",
    "sleep(", "waitfor",
    "0x", "%27",
]

# ─── L2: контекстно-незалежні загрози (рішення про кешованість вердикту) ──────
# ВУЗЬКИЙ набір — лише те, що неможливо сплутати з легітимним трафіком.
_HARD_EXTRA = ["..", "%2e%2e", "' or '", "</script", "/devlogin/login"]
HARD_MALICIOUS_PATTERNS = PAYLOAD_CORE + _HARD_EXTRA

# ─── L1: ширший набір для маршрутизації підозрілого на ШІ-аналіз ──────────────
# Тут можна тримати широкі токени — хибне спрацювання = лише зайвий аналіз ШІ.
_ANOMALY_EXTRA = ["'", '"', "</", " or '", "--", ";", "%3c",
                  # XSS-обробники подій / js-URI (щоб точно дійшли до ШІ)
                  "onerror=", "onload=", "onmouseover=", "javascript:", "<img", "<iframe"]
ANOMALY_PATTERNS = PAYLOAD_CORE + _ANOMALY_EXTRA

# ─── Маркери path-traversal (перевіряються окремою гілкою L1) ─────────────────
PATH_TRAVERSAL_MARKERS = ["..", "%2e%2e", "%2f%2f"]

# ─── L1 детермінований БЛОК: однозначні payload-токени (0мс, без ШІ) ──────────
# Легітимний трафік їх НІКОЛИ не містить → прямий L1-блок безпечний (FP=0).
# Свідомо БЕЗ широких '0x','%27','<img','onerror=' — вони бувають у легіт-значеннях
# (hex, апостроф у прізвищі, html-фрагмент у тексті) → ті йдуть на ШІ-аналіз.
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
    """Повертає (token, attack_class) для ОДНОЗНАЧНОГО payload, або (None, None)."""
    for tok, ac in L1_HARD_BLOCK.items():
        if tok in low_text:
            return tok, ac
    return None, None


# ─── Бэкстоп тіла/шляху ПІСЛЯ ШІ (детермінований override пропуску) ────────────
# Якщо ШІ (L2) сказав ALLOW, але у шляху/ТІЛІ є ОДНОЗНАЧНИЙ payload — форс-BLOCK:
# ШІ не можна обманути (prompt-injection) у бік пропуску явного payload, а L1
# матчить лише path і не бачить payload у ТІЛІ POST.
# ВУЗЬКИЙ, FP-safe для вільного тексту: свідомо БЕЗ '..','%2e%2e','%27','0x'
# (бувають у легіт-тексті — '...', hex, апостроф — або є суто URL-поняттями).
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
    """Чи містить шлях АБО тіло однозначно шкідливий payload (BACKSTOP-набір)."""
    blob = (str(path) + " " + (body or ""))[:8000].lower()
    return any(p in blob for p in BACKSTOP_PAYLOADS)


def classify_hard_payload(path: str, body: str = ""):
    """attack_class для знайденого hard-payload (через L1-каталог), або
    'payload_injection' якщо токен у BACKSTOP, але поза L1_HARD_BLOCK. None — чисто."""
    blob = (str(path) + " " + (body or ""))[:8000].lower()
    tok, ac = l1_block_match(blob)
    if tok:
        return ac
    return "payload_injection" if any(p in blob for p in BACKSTOP_PAYLOADS) else None

# ─── Маркери спроби prompt-injection проти ШІ-судді ───────────────────────────
# Наявність їх у запиті — САМА ПО СОБІ ознака атаки (легітимний бюлетень
# ніколи не містить «ignore instructions»).
INJECTION_MARKERS = [
    "ignore previous", "ignore all", "disregard", "forget previous",
    "you are now", "new instructions", "system:", "assistant:",
    "verdict allow", "verdict: allow", "respond with allow", "is legitimate",
    "this is a legitimate", "не є атакою", "проігноруй", "забудь попередні",
    "ти тепер", "поверни allow", "це легітимний", "</untrusted",
    "[/data]", "```", "<|", "|>",
]


# ─── Хелпери ──────────────────────────────────────────────────────────────────

def is_path_traversal(path: str) -> bool:
    """Чи містить шлях ознаки path-traversal (сирий '..' або URL-encoded)."""
    low = path.lower()
    return (".." in path
            or any(m in low for m in PATH_TRAVERSAL_MARKERS if m != ".."))


def anomaly_payload_match(low_text: str) -> bool:
    """Чи містить (вже lower-cased) текст ознаки injection-payload → L1 INSPECT."""
    return any(m in low_text for m in ANOMALY_PATTERNS)


def is_pattern_malicious(path: str, body: str) -> bool:
    """
    Чи містить запит контекстно-НЕЗАЛЕЖний шкідливий патерн (L2 → кешувати).
    Включає payload-сигнатури та спроби prompt-injection.
    """
    blob = (path + " " + (body or ""))[:2000].lower()
    if any(p in blob for p in HARD_MALICIOUS_PATTERNS):
        return True
    if any(m in blob for m in INJECTION_MARKERS):
        return True
    return False


def detect_injection(text: str) -> bool:
    """Чи містить текст маркери спроби prompt-injection."""
    if not text:
        return False
    low = str(text).lower()
    return any(m in low for m in INJECTION_MARKERS)
