"""
Модуль: Immune Response Engine (IRE)
Цифрова імунна система — immune_response_engine.py

Реалізує OFFLINE-цикл цифрового імунітету (SOC-агрегація):
  🛡 Detect → 🔍 Classify → ⚡ Respond → 🧠 Learn

ДВА ВЗАЄМОДОПОВНЮВАЛЬНІ РЕЖИМИ ІМУНІТЕТУ (важливо для розуміння архітектури):

  1. INLINE-режим (immune_system/immune_proxy.py) — реальний час, ПРЕВЕНЦІЯ.
     Проксі стоїть перед Helios і БЛОКУЄ атаку до того, як вона дійде до
     сервера (аналог вродженого+адаптивного імунітету «на кордоні»).
     Кожне блокування пишеться у logs/immune_blocks.jsonl.

  2. OFFLINE-режим (цей модуль, IRE) — постфактум, АГРЕГАЦІЯ та РЕАГУВАННЯ.
     Аналог лімфовузла: збирає сигнали з усіх джерел (червона команда +
     РЕАЛЬНІ inline-блокування проксі), класифікує за STRIDE/MITRE/LINDDUN,
     визначає рівень ризику, радить патч, веде довготривалу пам'ять інцидентів.

  Інтеграція: inline-проксі ВІДВЕРТАЄ атаку та емітує інцидент → IRE його
  ІНГЕСТУЄ (detect_from_immune_blocks), класифікує і запам'ятовує. Так дві
  частини утворюють єдиний контур: превенція на кордоні + SOC-аналітика.

Компоненти:
  ThreatDetector   — виявлення інцидентів з логів, репортів та inline-блокувань
  ThreatClassifier — класифікація за STRIDE + MITRE + LINDDUN
  ResponseSelector — вибір дій реагування
  ImmuneMemory     — SQLite-пам'ять про попередні атаки
  ImmunityEngine   — головний оркестратор
"""

import sys

import hashlib
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ─── Конфігурація ─────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
PROJECT_ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent))
LOGS_DIR    = str(PROJECT_ROOT / _cfg.get("paths", {}).get("logs_dir", "logs"))
REPORTS_DIR = str(PROJECT_ROOT / _cfg.get("paths", {}).get("reports_dir", "reports"))

EVENTS_LOG    = Path(LOGS_DIR) / "attack_events.jsonl"
RESPONSES_LOG = Path(LOGS_DIR) / "immune_responses.jsonl"
MEMORY_DB     = Path(LOGS_DIR) / "immune_memory.db"
# Лог inline-блокувань реального проксі (immune_system/immune_proxy.py) —
# джерело РЕАЛЬНИХ відвернених атак для OFFLINE-агрегації.
BLOCKS_LOG    = Path(LOGS_DIR) / "immune_blocks.jsonl"

Path(LOGS_DIR).mkdir(exist_ok=True)
Path(REPORTS_DIR).mkdir(exist_ok=True)

# ─── Константи класифікації ────────────────────────────────────────────────────

ATTACK_SIGNATURES = {
    "ballot_stuffing": {
        "stride": "Tampering",
        "mitre":  "T1565.001",
        "linddun": "L — Linkability",
        "keywords": ["ballot", "cast", "stuffing", "castvote", "race"],
        "endpoints": ["/cast", "/cast_confirm"],
        "risk_base": "Critical",
    },
    "impersonation": {
        "stride": "Spoofing",
        "mitre":  "T1539",
        "linddun": "I — Identifiability",
        "keywords": ["impersonation", "session", "hijack", "credential", "cookie"],
        "endpoints": ["/auth/", "/password_voter_login"],
        "risk_base": "Critical",
    },
    "session_forgery": {
        "stride": "Spoofing",
        "mitre":  "T1606.001",
        "linddun": "I — Identifiability",
        "keywords": ["session", "forgery", "secret_key", "replaceme", "signing"],
        "endpoints": ["/auth/", "/helios/elections"],
        "risk_base": "Critical",
    },
    "replay_attack": {
        "stride": "Tampering",
        "mitre":  "T1550.004",
        "linddun": "Nr — Non-repudiation",
        "keywords": ["replay", "token", "reuse", "duplicate"],
        "endpoints": ["/cast", "/cast_confirm"],
        "risk_base": "High",
    },
    "manipulation": {
        "stride": "Elevation of Privilege",
        "mitre":  "T1565",
        "linddun": "Nc — Non-compliance",
        "keywords": ["manipulation", "tally", "result", "admin", "freeze"],
        "endpoints": ["/encrypt_tally", "/freeze", "/result"],
        "risk_base": "Critical",
    },
    "tally_manipulation": {
        "stride": "Tampering",
        "mitre":  "T1565.001",
        "linddun": "Nc — Non-compliance",
        "keywords": ["tally", "verify_p", "compute_tally", "manipulation"],
        "endpoints": ["/encrypt_tally", "/result"],
        "risk_base": "Critical",
    },
    "csrf_trustee_takeover": {
        "stride": "Tampering",
        "mitre":  "T1539",
        "linddun": "Nr — Non-repudiation",
        "keywords": ["csrf", "trustee", "decryption", "upload"],
        "endpoints": ["/trustees/", "/upload-decryption"],
        "risk_base": "Critical",
    },
    "dos": {
        "stride": "Denial of Service",
        "mitre":  "T1499.002",
        "linddun": "D — Detectability",
        "keywords": ["dos", "flood", "celery", "queue", "saturation"],
        "endpoints": ["/cast"],
        "risk_base": "High",
    },
    "dos_zk_flood": {
        "stride": "Denial of Service",
        "mitre":  "T1499.002",
        "linddun": "D — Detectability",
        "keywords": ["flood", "zk", "celery", "queue", "saturation"],
        "endpoints": ["/cast"],
        "risk_base": "High",
    },
    "voter_coercion_receipt": {
        "stride": "Repudiation",
        "mitre":  "T1530",
        "linddun": "Nr — Non-repudiation",
        "keywords": ["coercion", "receipt", "audit", "randomness"],
        "endpoints": ["/ballots/", "/voters/"],
        "risk_base": "Critical",
    },
    "voter_phishing_credential": {
        "stride": "Spoofing",
        "mitre":  "T1566.002",
        "linddun": "I — Identifiability",
        "keywords": ["phishing", "credential", "login", "password", "cleartext"],
        "endpoints": ["/auth/password/login", "/voters/"],
        "risk_base": "Critical",
    },
    "voter_suppression_targeted": {
        "stride": "Denial of Service",
        "mitre":  "T1531",
        "linddun": "D — Detectability",
        "keywords": ["suppression", "lockout", "session_invalid", "flood_login"],
        "endpoints": ["/auth/password/login"],
        "risk_base": "High",
    },
    "voter_social_engineering_vote_change": {
        "stride": "Spoofing",
        "mitre":  "T1566.002",
        "linddun": "U — Unawareness",
        "keywords": ["social", "engineering", "phishing", "portal", "fake"],
        "endpoints": ["/voters/", "/auth/"],
        "risk_base": "Critical",
    },
    "voter_device_js_injection": {
        "stride": "Tampering",
        "mitre":  "T1185",
        "linddun": "Nr — Non-repudiation",
        "keywords": ["injection", "js", "browser", "mitb", "extension"],
        "endpoints": ["/cast", "/helios/elections"],
        "risk_base": "Critical",
    },
    "voter_timing_deanonymization": {
        "stride": "Information Disclosure",
        "mitre":  "T1040",
        "linddun": "T — Tracking",
        "keywords": ["timing", "deanon", "correlation", "network", "sniff"],
        "endpoints": ["/ballots/", "/voters/"],
        "risk_base": "High",
    },
    "election_integrity_apt": {
        "stride": "Spoofing + Tampering + Elevation of Privilege",
        "mitre":  "T1078",
        "linddun": "L + I + Nr + Nc",
        "keywords": ["apt", "kill_chain", "election_integrity", "full_chain"],
        "endpoints": ["/cast", "/trustees/", "/encrypt_tally"],
        "risk_base": "Critical",
    },
}

RESPONSE_RULES = {
    "ballot_stuffing":                      ["BLOCK", "ISOLATE", "ALERT"],
    "impersonation":                        ["BLOCK", "ALERT"],
    "session_forgery":                      ["BLOCK", "ALERT", "PATCH"],
    "replay_attack":                        ["BLOCK"],
    "manipulation":                         ["ISOLATE", "ALERT"],
    "tally_manipulation":                   ["ISOLATE", "ALERT", "PATCH"],
    "csrf_trustee_takeover":                ["BLOCK", "ISOLATE", "ALERT"],
    "dos":                                  ["BLOCK", "ALERT"],
    "dos_zk_flood":                         ["BLOCK", "ALERT"],
    "voter_coercion_receipt":               ["ALERT", "LOG"],
    "voter_phishing_credential":            ["BLOCK", "ALERT"],
    "voter_suppression_targeted":           ["BLOCK", "ALERT"],
    "voter_social_engineering_vote_change": ["ALERT", "LOG"],
    "voter_device_js_injection":            ["ALERT", "LOG"],
    "voter_timing_deanonymization":         ["LOG", "ALERT"],
    "election_integrity_apt":               ["ISOLATE", "ALERT", "PATCH"],
}

PATCH_RECOMMENDATIONS = {
    "ballot_stuffing":       "VULN-08: Додати SELECT FOR UPDATE в one_election_cast_confirm; впровадити row-level locking",
    "impersonation":         "VULN-02: Хешувати паролі виборців (django.contrib.auth.hashers); встановити httponly+secure на session cookie",
    "session_forgery":       "VULN-11: Встановити SECRET_KEY з os.environ — ніколи не використовувати 'replaceme'; ротація ключа",
    "replay_attack":         "Додати nonce/timestamp до ballot submission; перевірка uniq(voter_id, election_id) з UNIQUE constraint",
    "manipulation":          "VULN-05: Змінити verify_p=False на verify_p=True в compute_tally(); додати перевірку цілісності ZK-доказів",
    "tally_manipulation":    "VULN-05: compute_tally() has verify_p=False — змінити на True; логувати всі зміни voter.vote в audit trail",
    "csrf_trustee_takeover": "VULN-16: Перевіряти ідентичність trustee в trustee_upload_decryption; увімкнути CsrfViewMiddleware",
    "dos":                   "VULN-06: Впровадити rate limiting (django-ratelimit) на /cast; обмеження 1 бюлетень/хвилину на voter",
    "dos_zk_flood":          "VULN-06: Rate limiting на /cast endpoint; Celery worker autoscaling; max_queue_size limit",
    "voter_coercion_receipt":"Архітектурна: перейти на receipt-free протокол (Civitas або Belenios); реалізувати re-encryption mix-net",
    "voter_phishing_credential": "VULN-02+15: Хешувати паролі; ніколи не надсилати пароль у email; впровадити 2FA для виборців",
    "voter_suppression_targeted": "VULN-06: Rate limiting на /auth/password/login; account lockout після 5 невдалих спроб; CAPTCHA",
    "voter_social_engineering_vote_change": "VULN-15: Не надсилати пароль у відкритому вигляді; DMARC/SPF для домену виборів",
    "voter_device_js_injection": "Додати SRI (integrity=) на всі script теги; Content-Security-Policy заголовок; HTTPS everywhere",
    "voter_timing_deanonymization": "Впровадити mix-net або Verifiable Shuffle (Verificatum); рандомізувати затримку відповіді /ballots/",
    "election_integrity_apt": "Комплексний патч: SECRET_KEY + rate limiting + verify_p=True + trustee auth + password hashing",
}


# ─── 1. ThreatDetector ────────────────────────────────────────────────────────

class ThreatDetector:
    """Виявляє інциденти з логів та репортів."""

    SENSITIVE_ENDPOINTS = ["/cast", "/cast_confirm", "/trustees/", "/voters/",
                           "/encrypt_tally", "/freeze", "/upload-decryption", "/auth/"]
    CRITICAL_SEVERITIES = {"CRITICAL", "WARNING"}

    def detect_from_events(self, events_path: Path) -> list:
        incidents = []
        if not events_path.exists():
            return incidents
        attack_buffer = {}
        with open(events_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_type = event.get("event_type", "")
                severity  = event.get("severity", "")
                details   = event.get("details", {})
                attack_id  = details.get("attack_id", "")
                if event_type == "ATTACK_START":
                    attack_buffer[attack_id] = {
                        "attack_id":    attack_id,
                        "attack_class": details.get("attack_class", "unknown"),
                        "name":         details.get("name", ""),
                        "stride":       details.get("stride", ""),
                        "mitre":        details.get("mitre", ""),
                        "linddun":      details.get("linddun", ""),
                        "severity":     details.get("severity", ""),
                        "steps_total":  details.get("steps_total", 0),
                        "timestamp":    event.get("timestamp"),
                        "ioc_hits":     [],
                        "sensitive_hits": [],
                        "success_steps": 0,
                    }
                elif event_type == "ATTACK_STEP" and attack_id in attack_buffer:
                    result = details.get("result", {})
                    endpoint = result.get("endpoint", "") or ""
                    if result.get("success") and not result.get("is_simulated"):
                        attack_buffer[attack_id]["success_steps"] += 1
                        for ep in self.SENSITIVE_ENDPOINTS:
                            if ep in endpoint:
                                attack_buffer[attack_id]["sensitive_hits"].append(endpoint)
                elif event_type == "ATTACK_COMPLETE" and attack_id in attack_buffer:
                    buf = attack_buffer.pop(attack_id)
                    # red_team_agent v2 пише http_success_rate; підтримуємо обидва імені
                    success_rate = details.get("http_success_rate",
                                              details.get("success_rate", 0))
                    weighted_rate = details.get("weighted_success_rate", success_rate)
                    is_successful = details.get("attack_successful", False)
                    if is_successful or success_rate >= 50 or buf["sensitive_hits"]:
                        incidents.append({
                            "source":         "events_log",
                            "attack_id":      buf["attack_id"],
                            "attack_class":   buf["attack_class"],
                            "name":           buf["name"],
                            "stride":         buf["stride"],
                            "mitre":          buf["mitre"],
                            "linddun":        buf["linddun"],
                            "declared_severity": buf["severity"],
                            "timestamp":      buf["timestamp"],
                            "success_rate":   success_rate,
                            "weighted_rate":  weighted_rate,
                            "verdict":        details.get("verdict", ""),
                            "is_successful":  is_successful,
                            "sensitive_hits": list(set(buf["sensitive_hits"])),
                            "ioc_hits":       buf["ioc_hits"],
                        })
        return incidents

    def detect_from_reports(self, reports_dir: Path) -> list:
        incidents = []
        if not reports_dir.exists():
            return incidents
        # Дедуплікація за attack_id: campaign пише КОЖЕН сценарій двічі
        # (attacks/baseline/ і attacks/defended/) → без дедупу IRE подвоїв би
        # інциденти. Тримаємо ОДИН звіт на attack_id — з МАКСИМАЛЬНИМ http-успіхом
        # (найгірший випадок = потенціал атаки проти НЕзахищеного сервера).
        by_id = {}
        for f in sorted(reports_dir.rglob("ATK*_report.json")):
            try:
                r = json.load(open(f, encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
                print(f"[!] Пропускаю пошкоджений репорт {f.name}: {e}", file=sys.stderr)
                continue
            key = r.get("attack_id") or f.name
            prev = by_id.get(key)
            if prev is None or r.get("http_success_rate", 0) > prev.get("http_success_rate", 0):
                by_id[key] = r
        for r in by_id.values():
            verdict      = r.get("verdict", "")
            http_rate     = r.get("http_success_rate", 0)
            weighted_rate = r.get("weighted_success_rate", 0)
            attack_class  = r.get("attack_class", "unknown")
            if verdict in ("EXECUTED", "PARTIAL") or http_rate >= 50:
                incidents.append({
                    "source":           "report",
                    "attack_id":        r.get("attack_id", ""),
                    "attack_class":     attack_class,
                    "name":             r.get("name", ""),
                    "stride":           r.get("stride_category", ""),
                    "mitre":            r.get("mitre_technique_id", ""),
                    "linddun":          r.get("linddun_category", ""),
                    "declared_severity": r.get("severity", ""),
                    "timestamp":        r.get("executed_at", ""),
                    "success_rate":     http_rate,
                    "weighted_rate":    weighted_rate,
                    "verdict":          verdict,
                    "is_successful":    r.get("attack_successful", False),
                    "ioc":              r.get("indicators_of_compromise", []),
                    "detection_gaps":   r.get("detection_gaps", []),
                    "helios_vulns":     r.get("helios_vulns_exploited", []),
                    "voter_impact":     r.get("voter_impact", {}),
                    "affected_cia":     r.get("affected_cia", {}),
                })
        return incidents

    def detect_from_immune_blocks(self, blocks_path: Path) -> list:
        """
        Інциденти з INLINE-проксі (immune_blocks.jsonl) — РЕАЛЬНІ блокування в
        реальному часі. На відміну від events/reports (offline-симуляція червоної
        команди), це фактично ВІДВЕРНЕНІ атаки. Інтегрує inline-превенцію в
        offline-агрегацію: проксі заблокував → IRE класифікує, радить патч,
        запам'ятовує. verdict=BLOCKED, success_rate=0 (атака не дійшла до Helios).
        """
        incidents = []
        if not blocks_path.exists():
            return incidents
        with open(blocks_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("verdict") != "BLOCK":
                    continue
                attack_class = e.get("attack_class") or "unknown"
                tier = e.get("tier", "")
                ts   = e.get("timestamp", "")
                # стабільний унікальний id, щоб дедуплікація не злила різні блоки
                raw_id = f"{ts}|{e.get('client_ip','')}|{e.get('method','')}|{e.get('path','')}"
                attack_id = "INLINE-" + hashlib.sha1(raw_id.encode()).hexdigest()[:10]
                incidents.append({
                    "source":         "inline_proxy",
                    "attack_id":      attack_id,
                    "attack_class":   attack_class,
                    "name":           e.get("reason", "") or f"inline-блок ({tier})",
                    "stride":         "",
                    "mitre":          "",
                    "linddun":        "",
                    "declared_severity": "",
                    "timestamp":      ts,
                    # атаку ВІДВЕРНЕНО проксі → не успішна
                    "success_rate":   0,
                    "weighted_rate":  0,
                    "verdict":        "BLOCKED",
                    "is_successful":  False,
                    "blocked_inline": True,
                    "defense_tier":   tier,
                    "client_ip":      e.get("client_ip", ""),
                    "ai_confidence":  e.get("confidence"),
                    "signal":         e.get("signal"),
                })
        return incidents


# ─── 2. ThreatClassifier ──────────────────────────────────────────────────────

class ThreatClassifier:
    """Класифікує інцидент за STRIDE + MITRE + LINDDUN, визначає рівень ризику."""

    RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    def classify(self, incident: dict) -> dict:
        attack_class = incident.get("attack_class", "unknown")
        sig = ATTACK_SIGNATURES.get(attack_class)
        if not sig:
            sig = self._infer_signature(incident)
        stride  = sig.get("stride")  or incident.get("stride", "Unknown")
        mitre   = sig.get("mitre")   or incident.get("mitre", "T0000")
        linddun = sig.get("linddun") or incident.get("linddun", "L")
        risk_level = self._calc_risk_level(sig, incident)
        return {
            "attack_class": attack_class,
            "stride":       stride,
            "mitre":        mitre,
            "linddun":      linddun,
            "risk_level":   risk_level,
            "vector":       self._detect_vector(attack_class, incident),
            "confidence":   self._calc_confidence(sig, incident),
        }

    def _infer_signature(self, incident: dict) -> dict:
        text = (incident.get("name","") + " " +
                incident.get("attack_class","") + " " +
                str(incident.get("ioc",""))).lower()
        for attack_class, sig in ATTACK_SIGNATURES.items():
            if any(kw in text for kw in sig["keywords"]):
                return sig
        return {"stride":"Unknown","mitre":"T0000","linddun":"L","risk_base":"Medium","keywords":[],"endpoints":[]}

    def _calc_risk_level(self, sig: dict, incident: dict) -> str:
        # Базовий рівень визначає притаманна небезпека класу атаки,
        # модулюється фактичним результатом виконання.
        base = sig.get("risk_base", "Medium")
        base_score = self.RISK_ORDER.get(base, 2)
        success_rate = incident.get("success_rate", 0)
        weighted_rate = incident.get("weighted_rate", success_rate)
        verdict = incident.get("verdict", "")
        # Підвищуємо лише недооцінені атаки (Low/Medium), що несподівано спрацювали
        if base_score <= 2 and verdict == "EXECUTED" and weighted_rate >= 80:
            base_score = min(base_score + 1, 4)
        # Знижуємо рівень, якщо атаку було заблоковано
        elif verdict == "BLOCKED" and success_rate < 30:
            base_score = max(base_score - 1, 1)
        return ["Low", "Medium", "High", "Critical"][base_score - 1]

    def _detect_vector(self, attack_class: str, incident: dict) -> str:
        voter_attacks = {"voter_coercion_receipt","voter_phishing_credential",
                        "voter_suppression_targeted","voter_social_engineering_vote_change",
                        "voter_device_js_injection","voter_timing_deanonymization"}
        return "voter" if attack_class in voter_attacks else "system"

    def _calc_confidence(self, sig: dict, incident: dict) -> str:
        if sig.get("keywords") and sig.get("endpoints"):
            return "HIGH"
        if incident.get("verdict") == "EXECUTED":
            return "HIGH"
        if incident.get("success_rate", 0) >= 60:
            return "MEDIUM"
        return "LOW"


# ─── 3. ResponseSelector ──────────────────────────────────────────────────────

class ResponseSelector:
    """Вибирає дії реагування на основі класифікації."""

    def select(self, classification: dict, incident: dict) -> dict:
        attack_class = classification.get("attack_class", "unknown")
        risk_level   = classification.get("risk_level", "Medium")
        actions = RESPONSE_RULES.get(attack_class, ["ALERT", "LOG"])
        patch = PATCH_RECOMMENDATIONS.get(attack_class, "Деталі патчу не визначені — огляд коду вручну")
        urgency = self._calc_urgency(risk_level, incident)
        reasoning = self._build_reasoning(attack_class, classification, incident)
        return {
            "actions":       actions,
            "patch":         patch,
            "urgency":       urgency,
            "reasoning":     reasoning,
            "auto_remediate": risk_level == "Critical" and "BLOCK" in actions,
        }

    def _calc_urgency(self, risk_level: str, incident: dict) -> str:
        success_rate = incident.get("success_rate", 0)
        if risk_level == "Critical" and success_rate >= 60:
            return "IMMEDIATE"
        if risk_level in ("Critical", "High"):
            return "HIGH"
        if risk_level == "Medium":
            return "MEDIUM"
        return "LOW"

    def _build_reasoning(self, attack_class: str, classification: dict, incident: dict) -> str:
        mitre = classification.get("mitre", "")
        success_rate = incident.get("success_rate", 0)
        verdict = incident.get("verdict", "")
        vulns = incident.get("helios_vulns", [])
        vuln_str = f" Експлуатовані вразливості: {', '.join(vulns)}." if vulns else ""
        return (f"Атака '{attack_class}' класифікована як {classification.get('risk_level')} "
                f"(MITRE {mitre}, STRIDE: {classification.get('stride')}). "
                f"HTTP success rate: {success_rate:.0f}%, verdict: {verdict}.{vuln_str}")


# ─── 4. ImmuneMemory ──────────────────────────────────────────────────────────

class ImmuneMemory:
    """SQLite-пам'ять імунної системи про попередні інциденти."""

    def __init__(self, db_path: Path = MEMORY_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id    TEXT PRIMARY KEY,
                    attack_id      TEXT,
                    attack_class   TEXT NOT NULL,
                    stride         TEXT,
                    mitre_id       TEXT,
                    linddun        TEXT,
                    risk_level     TEXT,
                    response_actions TEXT,
                    success_rate   REAL,
                    verdict        TEXT,
                    timestamp      TEXT,
                    from_memory    INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_class ON incidents(attack_class)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp    ON incidents(timestamp)")
            conn.commit()

    def remember(self, incident: dict, classification: dict, response: dict):
        incident_id = incident.get("incident_id", f"INC-{uuid.uuid4().hex[:8].upper()}")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents
                (incident_id, attack_id, attack_class, stride, mitre_id, linddun,
                 risk_level, response_actions, success_rate, verdict, timestamp, from_memory)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                incident_id,
                incident.get("attack_id", ""),
                classification.get("attack_class", ""),
                classification.get("stride", ""),
                classification.get("mitre", ""),
                classification.get("linddun", ""),
                classification.get("risk_level", ""),
                json.dumps(response.get("actions", [])),
                incident.get("success_rate", 0),
                incident.get("verdict", ""),
                incident.get("timestamp", datetime.now(timezone.utc).isoformat()),
                int(incident.get("from_memory", False)),
            ))
            conn.commit()
        return incident_id

    def recall(self, attack_class: str) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM incidents WHERE attack_class=? ORDER BY timestamp DESC LIMIT 10",
                (attack_class,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_statistics(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            by_class = conn.execute(
                "SELECT attack_class, COUNT(*) as cnt, AVG(success_rate) as avg_rate "
                "FROM incidents GROUP BY attack_class ORDER BY cnt DESC"
            ).fetchall()
            by_risk = conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM incidents GROUP BY risk_level"
            ).fetchall()
            from_memory = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE from_memory=1"
            ).fetchone()[0]
        return {
            "total_incidents": total,
            "from_memory":     from_memory,
            "by_class":        [{"attack_class": r[0], "count": r[1], "avg_rate": round(r[2] or 0, 1)} for r in by_class],
            "by_risk":         {r[0]: r[1] for r in by_risk},
        }


# ─── 5. ImmunityEngine ────────────────────────────────────────────────────────

class ImmunityEngine:
    """
    Головний оркестратор цифрової імунної системи.
    Цикл: 🛡 Detect → 🔍 Classify → ⚡ Respond → 🧠 Learn
    """

    def __init__(self):
        self.detector   = ThreatDetector()
        self.classifier = ThreatClassifier()
        self.selector   = ResponseSelector()
        self.memory     = ImmuneMemory()
        self._incCounter = 0

    def _next_incident_id(self) -> str:
        self._incCounter += 1
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"INC-{date}-{self._incCounter:03d}"

    def _log(self, entry: dict):
        with open(RESPONSES_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _print_header(self):
        print("\n" + "=" * 70)
        print("  🛡  IMMUNE RESPONSE ENGINE — Цифрова імунна система")
        print("  Helios e-voting | Detect → Classify → Respond → Learn")
        print("=" * 70)

    def process_incident(self, incident: dict) -> dict:
        t_start = time.time()
        incident_id = self._next_incident_id()
        incident["incident_id"] = incident_id
        # 🔍 Classify
        classification = self.classifier.classify(incident)
        attack_class = classification["attack_class"]
        # 🧠 Check memory
        past_incidents = self.memory.recall(attack_class)
        from_memory    = len(past_incidents) > 0
        memory_hits    = len(past_incidents)
        if from_memory:
            prev_actions = json.loads(past_incidents[0].get("response_actions", "[]"))
            incident["from_memory"] = True
        # ⚡ Select response
        response = self.selector.select(classification, incident)
        response_ms = round((time.time() - t_start) * 1000, 1)
        result = {
            "incident_id":        incident_id,
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "attack_id":          incident.get("attack_id", ""),
            "attack_class":       attack_class,
            "stride_category":    classification["stride"],
            "mitre_technique_id": classification["mitre"],
            "linddun_category":   classification["linddun"],
            "risk_level":         classification["risk_level"],
            "vector":             classification["vector"],
            "confidence":         classification["confidence"],
            "success_rate":       incident.get("success_rate", 0),
            "verdict":            incident.get("verdict", ""),
            "response_actions":   response["actions"],
            "recommended_patch":  response["patch"],
            "urgency":            response["urgency"],
            "reasoning":          response["reasoning"],
            "response_time_ms":   response_ms,
            "from_memory":        from_memory,
            "memory_hits":        memory_hits,
            "source":             incident.get("source", "unknown"),
            "helios_vulns":       incident.get("helios_vulns", []),
            "voter_impact":       incident.get("voter_impact", {}),
        }
        # 🧠 Learn
        self.memory.remember(incident, classification, response)
        self._log(result)
        return result

    def _print_result(self, result: dict, idx: int, total: int):
        risk_colors = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        icon = "👤" if result["vector"] == "voter" else "🖥 "
        rl = risk_colors.get(result["risk_level"], "") + " " + result["risk_level"]
        mem = f"[пам'ять ×{result['memory_hits']}]" if result["from_memory"] else "[новий]"
        print(f"\n  [{idx}/{total}] {icon} {result['attack_class']}")
        print(f"  🛡 {result['incident_id']}  {rl}  {mem}")
        print(f"  🔍 MITRE: {result['mitre_technique_id']} | STRIDE: {result['stride_category']}")
        print(f"  ⚡ Дії: {', '.join(result['response_actions'])}  "
              f"терміновість: {result['urgency']}  ({result['response_time_ms']}ms)")
        print(f"  🧠 Патч: {result['recommended_patch'][:80]}...")

    def run(self):
        self._print_header()
        # ─── Збір інцидентів ─────────────────────────────────────────────────
        print("\n  🛡 DETECT — виявлення інцидентів...")
        events_incidents  = self.detector.detect_from_events(EVENTS_LOG)
        reports_incidents = self.detector.detect_from_reports(Path(REPORTS_DIR))
        # INLINE: реальні блокування проксі (превенція) → інгест у SOC-агрегацію
        inline_incidents  = self.detector.detect_from_immune_blocks(BLOCKS_LOG)
        # Дедуплікація по attack_id: репорти багатші (vulns, voter_impact),
        # тому об'єднуємо — дані з репорту доповнюють подію з логу.
        # inline-блоки мають унікальні id → не зливаються з симуляціями.
        merged = {}
        order = []
        for inc in events_incidents + reports_incidents + inline_incidents:
            aid = inc.get("attack_id", "")
            if not aid:
                order.append(id(inc))
                merged[id(inc)] = inc
                continue
            if aid in merged:
                # доповнюємо непорожніми полями (репорт перезаписує лог)
                for k, v in inc.items():
                    if v not in (None, "", [], {}):
                        merged[aid][k] = v
            else:
                merged[aid] = inc
                order.append(aid)
        all_incidents = [merged[k] for k in order]
        print(f"  Виявлено: {len(all_incidents)} інцидентів "
              f"(з логів: {len(events_incidents)}, з репортів: {len(reports_incidents)}, "
              f"inline-блоків проксі: {len(inline_incidents)}, "
              f"унікальних: {len(all_incidents)})")
        if not all_incidents:
            print("  ℹ️  Інцидентів не виявлено. Запусти red_team_agent.py або "
                  "immune_proxy.py (inline-блокування) спочатку.")
            return
        # ─── Обробка ──────────────────────────────────────────────────────────
        print(f"\n  🔍 CLASSIFY + ⚡ RESPOND + 🧠 LEARN — обробка {len(all_incidents)} інцидентів...")
        results = []
        for idx, inc in enumerate(all_incidents, 1):
            result = self.process_incident(inc)
            results.append(result)
            self._print_result(result, idx, len(all_incidents))
        # ─── Підсумок ─────────────────────────────────────────────────────────
        self._print_summary(results)
        self._save_report(results)
        # ─── Таблиця для дисертації ───────────────────────────────────────────
        diss = self._dissertation_table(results)
        print("\n" + diss)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        ire_dir = Path(REPORTS_DIR) / "ire"
        ire_dir.mkdir(parents=True, exist_ok=True)
        diss_path = ire_dir / f"ire_dissertation_table_{ts}.txt"
        diss_path.write_text(diss, encoding="utf-8")
        print(f"\n  [+] Таблиця для дисертації: {diss_path}")

    def _print_summary(self, results: list):
        from collections import Counter
        risk_counts   = Counter(r["risk_level"]   for r in results)
        action_counts = Counter(a for r in results for a in r["response_actions"])
        urgency_counts = Counter(r["urgency"]      for r in results)
        from_memory    = sum(1 for r in results if r["from_memory"])
        avg_ms         = sum(r["response_time_ms"] for r in results) / len(results) if results else 0
        print(f"\n{'='*70}")
        print("  📊 ПІДСУМОК ІМУННОЇ ВІДПОВІДІ")
        print(f"{'='*70}")
        print(f"  Всього оброблено:   {len(results)} інцидентів")
        print(f"  З пам'яті (швидко): {from_memory} ({from_memory/len(results)*100:.0f}%)")
        print(f"  Середній час:       {avg_ms:.1f}ms")
        print(f"\n  Розподіл ризику:")
        for level, icon in [("Critical","🔴"),("High","🟠"),("Medium","🟡"),("Low","🟢")]:
            if risk_counts.get(level):
                print(f"    {icon} {level}: {risk_counts[level]}")
        print(f"\n  Дії реагування:")
        for action, count in sorted(action_counts.items(), key=lambda x: -x[1]):
            print(f"    {action}: {count}")
        print(f"\n  Терміновість:")
        for urgency in ["IMMEDIATE","HIGH","MEDIUM","LOW"]:
            if urgency_counts.get(urgency):
                print(f"    {urgency}: {urgency_counts[urgency]}")
        mem_stats = self.memory.get_statistics()
        print(f"\n  🧠 Пам'ять: {mem_stats['total_incidents']} записів у БД")
        print(f"{'='*70}")

    def _save_report(self, results: list):
        from collections import Counter
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        risk_counts   = Counter(r["risk_level"]   for r in results)
        action_counts = Counter(a for r in results for a in r["response_actions"])
        mem_stats = self.memory.get_statistics()
        report = {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "engine":        "ImmunityEngine v1.0",
            "total_incidents": len(results),
            "summary": {
                "by_risk":     dict(risk_counts),
                "by_actions":  dict(action_counts),
                "from_memory": sum(1 for r in results if r["from_memory"]),
                "avg_response_ms": round(
                    sum(r["response_time_ms"] for r in results) / len(results), 1
                ) if results else 0,
            },
            "memory_stats":  mem_stats,
            "incidents":     results,
        }
        ire_dir = Path(REPORTS_DIR) / "ire"
        ire_dir.mkdir(parents=True, exist_ok=True)
        out_path = ire_dir / f"ire_report_{ts}.json"
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print(f"\n  [+] IRE звіт збережено: {out_path}")
        print(f"  [+] Лог відповідей:     {RESPONSES_LOG}")
        print(f"  [+] Пам'ять (SQLite):   {MEMORY_DB}")

    def _dissertation_table(self, results: list) -> str:
        """
        Наочна таблиця для розділу результатів дисертації: класифікація загроз
        (STRIDE/MITRE/LINDDUN) + автоматичне реагування ЦІС + рекомендовані патчі,
        агреговано за класом атаки. Зберігається у reports/ire/.
        """
        from collections import Counter

        agg = {}
        for r in results:
            ac = r["attack_class"]
            d = agg.get(ac)
            if d is None:
                d = {"stride": r.get("stride_category") or "",
                     "mitre": r.get("mitre_technique_id") or "",
                     "linddun": r.get("linddun_category") or "",
                     "actions": set(), "sources": set(), "vector": r.get("vector", ""),
                     "rank": 0, "risk": "Low", "urgency": "LOW",
                     "patch": r.get("recommended_patch", ""), "count": 0}
                agg[ac] = d
            d["count"] += 1
            d["actions"].update(r.get("response_actions", []))
            src = r.get("source", "")
            d["sources"].add("inline" if src == "inline_proxy" else "offline")
            rank = ThreatClassifier.RISK_ORDER.get(r.get("risk_level", "Low"), 1)
            if rank >= d["rank"]:
                d["rank"], d["risk"], d["urgency"] = rank, r["risk_level"], r.get("urgency", "LOW")

        rows = sorted(agg.items(), key=lambda kv: (-kv[1]["rank"], kv[0]))
        W = 140
        L = [
            "ТАБЛИЦЯ 3.4 — Класифікація загроз і автоматичне реагування ЦІС",
            "            (цикл Detect → Classify → Respond, агреговано за класом атаки)",
            "",
            f"{'№':<3} {'Клас атаки':<34} {'STRIDE':<20} {'MITRE':<11} "
            f"{'LINDDUN':<10} {'Ризик':<9} {'Термін.':<10} {'Інц':>3}  "
            f"{'Дії реагування':<24} Джерело",
            "─" * W,
        ]
        for i, (ac, d) in enumerate(rows, 1):
            actions = ",".join(sorted(d["actions"]))
            src = "/".join(sorted(d["sources"]))
            L.append(f"{i:<3} {ac:<34} {d['stride'][:19]:<20} {d['mitre']:<11} "
                     f"{d['linddun'][:9]:<10} {d['risk']:<9} {d['urgency']:<10} "
                     f"{d['count']:>3}  {actions[:24]:<24} {src}")
        L.append("─" * W)
        rc = Counter(d["risk"] for _, d in rows)
        L.append("  Розподіл ризику (за класами): "
                 + " | ".join(f"{k}:{rc[k]}" for k in ("Critical", "High", "Medium", "Low") if rc.get(k)))
        L += [
            "",
            "ТАБЛИЦЯ 3.5 — Рекомендовані контрзаходи (патчі) за класами атак",
            "─" * W,
        ]
        for i, (ac, d) in enumerate(rows, 1):
            L.append(f"{i:<3} {ac:<34} {d['patch']}")
        L += [
            "─" * W,
            "Примітки:",
            "  STRIDE / MITRE / LINDDUN — модель загроз; Ризик — найвищий серед інцидентів класу.",
            "  Дії — обʼєднання дій реагування (BLOCK/ISOLATE/ALERT/PATCH/LOG).",
            "  Джерело — inline (проксі реального часу) / offline (червона команда).",
            "  Інц — кількість оброблених інцидентів цього класу.",
        ]
        return "\n".join(L)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ImmunityEngine().run()
