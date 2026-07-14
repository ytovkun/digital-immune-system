"""
Модуль: Attack Chain Orchestrator v2
Цифрова імунна система — attack_chain.py

Запускає атаки послідовно як єдиний APT-сценарій.
Контекст накопичується між фазами: session_id, voter_uuid,
extracted tokens передаються від однієї атаки до наступної.

Два визначених ланцюжки:
  system_apt  — компрометація платформи (розвідка → доступ → фальсифікація → підрахунок)
  voter_apt   — атака на виборця (фішинг → примус → підміна девайсу → соціальна інженерія)
"""

import json
import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

import red_team_agent as rta

# ─── Конфігурація ─────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config as _load_config

_cfg = _load_config()
PROJECT_ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent))

HELIOS_BASE_URL = _cfg.get("helios", {}).get("base_url", "http://localhost:8001")
ELECTION_UUID   = _cfg.get("helios", {}).get("election_uuid", "07712c60-5b5b-4671-9ede-035cda82736a")
SCENARIOS_DIR   = str(PROJECT_ROOT / _cfg.get("paths", {}).get("scenarios_dir", "scenarios"))
REPORTS_DIR     = str(PROJECT_ROOT / _cfg.get("paths", {}).get("reports_dir", "reports"))
LOGS_DIR        = str(PROJECT_ROOT / _cfg.get("paths", {}).get("logs_dir", "logs"))

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{LOGS_DIR}/attack_chain.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("attack_chain")


# ─── Визначення ланцюжків ─────────────────────────────────────────────────────

CHAINS = {

    # ══════════════════════════════════════════════════════════════════
    # APT на платформу: розвідка → доступ → ballot stuffing → tally
    # ══════════════════════════════════════════════════════════════════
    "system_apt": {
        "name": "System APT — Election Platform Compromise",
        "description": (
            "Повний APT-ланцюжок проти платформи Helios: "
            "розвідка → підробка сесії → race condition ballot stuffing → маніпуляція tally. "
            "Контекст (session_id, voter_uuid, csrf_token) передається між фазами."
        ),
        "mitre_chain": "T1040 → T1606.001 → T1565.001 → T1565.001",
        "phases": [
            {
                "phase": 1,
                "name": "Reconnaissance",
                "attack_class": "voter_timing_deanonymization",
                "description": "Збір публічних даних: voter list, ballot board, cast_at timestamps",
                "context_provides": ["voter_uuid", "session_id"],
            },
            {
                "phase": 2,
                "name": "Initial Access — Session Forgery",
                "attack_class": "session_forgery",
                "description": "Підробка Django session cookie через SECRET_KEY='replaceme'",
                "context_uses": ["voter_uuid"],
                "context_provides": ["session_id", "csrf_token"],
            },
            {
                "phase": 3,
                "name": "Election Tampering — Ballot Stuffing",
                "attack_class": "ballot_stuffing",
                "description": "TOCTOU race condition на /cast_confirm з накопиченим session_id",
                "context_uses": ["session_id", "csrf_token", "voter_uuid"],
                "context_provides": [],
            },
            {
                "phase": 4,
                "name": "Impact — Tally Manipulation",
                "attack_class": "tally_manipulation",
                "description": "Підміна vote ciphertext перед encrypt_tally (verify_p=False)",
                "context_uses": ["session_id"],
                "context_provides": [],
            },
        ],
    },

    # ══════════════════════════════════════════════════════════════════
    # APT на виборця: фішинг → примус → JS injection → соціальна інженерія
    # ══════════════════════════════════════════════════════════════════
    "voter_apt": {
        "name": "Voter APT — Human Targeting Campaign",
        "description": (
            "Комплексна атака на виборця: фішинг credentials → примус через audit receipt → "
            "підміна бюлетеня через JS injection → соціальна інженерія 'перепроголосування'. "
            "Кожна фаза посилює наступну."
        ),
        "mitre_chain": "T1566.002 → T1530 → T1185 → T1557",
        "phases": [
            {
                "phase": 1,
                "name": "Credential Harvest",
                "attack_class": "voter_phishing_credential",
                "description": "Масовий збір voter_login_id + voter_password через клонований портал",
                "context_provides": ["voter_uuid", "session_id"],
            },
            {
                "phase": 2,
                "name": "Coercion via Receipt",
                "attack_class": "voter_coercion_receipt",
                "description": "Примус виборця розкрити audit randomness — криптографічний доказ голосу",
                "context_uses": ["voter_uuid"],
                "context_provides": [],
            },
            {
                "phase": 3,
                "name": "Device Compromise",
                "attack_class": "voter_device_js_injection",
                "description": "Man-in-Browser: підміна plaintext вибору до ElGamal-шифрування",
                "context_uses": ["session_id"],
                "context_provides": [],
            },
            {
                "phase": 4,
                "name": "Social Engineering Fallback",
                "attack_class": "voter_social_engineering_vote_change",
                "description": "Фальшивий 'технічний збій' — виборець голосує повторно на підробленому порталі",
                "context_uses": [],
                "context_provides": [],
            },
        ],
    },
}


# ─── Завантаження сценарію ────────────────────────────────────────────────────

def load_scenario(attack_class: str, prefer_adaptive: bool = False) -> dict:
    """
    Шукає сценарій по attack_class у scenarios/{vector}/ та /adaptive/.
    Якщо prefer_adaptive=True — спочатку шукає адаптивний варіант.
    """
    candidates = []
    for f in Path(SCENARIOS_DIR).rglob("*.json"):
        if "report" in f.name:
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            print(f"[!] Пропускаю пошкоджений сценарій {f.name}: {e}", file=sys.stderr)
            continue
        if d.get("attack_class") == attack_class:
            is_adaptive = "adaptive" in str(f)
            candidates.append((f.stat().st_mtime, is_adaptive, d))

    if not candidates:
        raise FileNotFoundError(f"Сценарій '{attack_class}' не знайдено у {SCENARIOS_DIR}/")

    if prefer_adaptive:
        adaptive = [(t, d) for t, ia, d in candidates if ia]
        if adaptive:
            return sorted(adaptive, reverse=True)[0][1]

    # Повертаємо найсвіжіший (adaptive або ні)
    return sorted(candidates, reverse=True)[0][2]


# ─── Лог ланцюжка ────────────────────────────────────────────────────────────

def log_chain_event(event_type: str, details: dict, severity: str = "INFO"):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "details": details,
    }
    log.info(json.dumps(entry, ensure_ascii=False))
    with open(f"{LOGS_DIR}/chain_events.jsonl", "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ─── Запуск ланцюжка ──────────────────────────────────────────────────────────

def run_chain(chain_name: str, prefer_adaptive: bool = True) -> dict:
    if chain_name not in CHAINS:
        raise ValueError(f"Невідомий ланцюжок: {chain_name}. Доступні: {list(CHAINS)}")

    chain_def = CHAINS[chain_name]
    chain_id  = f"CHAIN-{chain_name.upper()}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    print(f"\n{'='*70}")
    print(f"  ATTACK CHAIN v2 — {chain_def['name']}")
    print(f"  {chain_def['description']}")
    print(f"  MITRE chain: {chain_def['mitre_chain']}")
    print(f"  Chain ID: {chain_id}")
    print(f"  Режим: {'адаптивні сценарії' if prefer_adaptive else 'оригінальні сценарії'}")
    print(f"{'='*70}")

    log_chain_event("CHAIN_START", {
        "chain_id": chain_id,
        "chain_name": chain_name,
        "phases": len(chain_def["phases"]),
        "target": HELIOS_BASE_URL,
        "prefer_adaptive": prefer_adaptive,
    }, severity="CRITICAL")

    # Накопичений контекст — передається між фазами
    shared_context = {
        "base_url": HELIOS_BASE_URL,
        "election_uuid": ELECTION_UUID,
    }

    phase_results = []
    executed_verdicts = []
    accumulated_ioc = []

    for phase_def in chain_def["phases"]:
        phase_num  = phase_def["phase"]
        phase_name = phase_def["name"]
        attack_class = phase_def["attack_class"]
        uses    = phase_def.get("context_uses", [])
        provides = phase_def.get("context_provides", [])

        print(f"\n{'─'*70}")
        print(f"  ФАЗА {phase_num}/{len(chain_def['phases'])}: {phase_name.upper()}")
        print(f"  Клас: {attack_class}")
        print(f"  {phase_def['description']}")
        if uses:
            available = [k for k in uses if k in shared_context]
            print(f"  Використовує з контексту: {available}")
        print(f"{'─'*70}")

        log_chain_event("PHASE_START", {
            "chain_id": chain_id,
            "phase": phase_num,
            "name": phase_name,
            "attack_class": attack_class,
            "context_keys_available": list(shared_context.keys()),
        }, severity="WARNING")

        try:
            scenario = load_scenario(attack_class, prefer_adaptive=prefer_adaptive)
            is_adaptive = bool(scenario.get("adaptation_mode"))
            print(f"  {'[адаптив]' if is_adaptive else '[оригінал]'} {scenario.get('name')}")

            # Виконуємо через red_team_agent з накопиченим контекстом
            report = rta.execute_scenario(scenario, base_url=HELIOS_BASE_URL)

            # Беремо витягнутий контекст з репорту і зберігаємо в shared
            end_ctx = report.get("context_at_end", {})
            passed = []
            for key in provides:
                if key in end_ctx:
                    shared_context[key] = end_ctx[key]
                    passed.append(key)
            # Також автоматично передаємо session_id і voter_uuid якщо є
            for auto_key in ("session_id", "voter_uuid", "csrf_token"):
                if auto_key in end_ctx and auto_key not in shared_context:
                    shared_context[auto_key] = end_ctx[auto_key]
                    if auto_key not in passed:
                        passed.append(auto_key)

            if passed:
                print(f"  [→] Передано в наступну фазу: {passed}")

            verdict = report.get("verdict", "UNKNOWN")
            executed_verdicts.append(verdict)
            accumulated_ioc.extend(report.get("indicators_of_compromise", []))

            phase_result = {
                "phase":        phase_num,
                "name":         phase_name,
                "attack_class": attack_class,
                "is_adaptive":  is_adaptive,
                "verdict":      verdict,
                "http_success_rate":     report.get("http_success_rate", 0),
                "weighted_success_rate": report.get("weighted_success_rate", 0),
                "critical_executability":report.get("critical_executability", 0),
                "context_passed": passed,
                "attack_id":    report.get("attack_id"),
                "timestamp":    datetime.utcnow().isoformat(),
            }
            phase_results.append(phase_result)

            log_chain_event("PHASE_COMPLETE", {
                "chain_id":      chain_id,
                "phase":         phase_num,
                "verdict":       verdict,
                "http_rate":     report.get("http_success_rate"),
                "weighted_rate": report.get("weighted_success_rate"),
                "context_passed": passed,
            }, severity="CRITICAL" if verdict == "EXECUTED" else "WARNING")

        except FileNotFoundError as e:
            print(f"  [!] Пропускаємо фазу {phase_num}: {e}")
            phase_results.append({
                "phase": phase_num, "name": phase_name,
                "attack_class": attack_class,
                "verdict": "SKIPPED", "error": str(e),
            })
            log_chain_event("PHASE_SKIPPED", {
                "chain_id": chain_id, "phase": phase_num, "reason": str(e)
            }, severity="WARNING")

        time.sleep(0.5)

    # ─── Підсумок ланцюжка ────────────────────────────────────────────────────

    VERDICT_WEIGHT = {
        "EXECUTED": 2, "PARTIAL": 1, "BLOCKED": 0,
        "CONCEPTUAL": 0, "RECON_ONLY": 0, "SKIPPED": 0,
    }
    max_score = len(phase_results) * 2
    actual_score = sum(VERDICT_WEIGHT.get(r.get("verdict", ""), 0) for r in phase_results)
    chain_score = actual_score / max_score * 100 if max_score > 0 else 0
    chain_compromised = chain_score >= 40

    verdict_counts = {}
    for r in phase_results:
        v = r.get("verdict", "SKIPPED")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    chain_report = {
        "chain_id":          chain_id,
        "chain_name":        chain_name,
        "chain_label":       chain_def["name"],
        "executed_at":       datetime.utcnow().isoformat(),
        "prefer_adaptive":   prefer_adaptive,
        "phases_total":      len(chain_def["phases"]),
        "phase_results":     phase_results,
        "verdict_counts":    verdict_counts,
        "chain_score":       round(chain_score, 1),
        "chain_compromised": chain_compromised,
        "accumulated_ioc":   list(dict.fromkeys(accumulated_ioc)),  # унікальні, зберігаючи порядок
        "context_at_end":    {k: v for k, v in shared_context.items()
                              if k not in ("base_url",) and isinstance(v, str)},
    }

    attacks_dir = Path(REPORTS_DIR) / "attacks"
    attacks_dir.mkdir(parents=True, exist_ok=True)
    report_file = str(attacks_dir / f"{chain_id}_chain_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(chain_report, f, ensure_ascii=False, indent=2)

    log_chain_event("CHAIN_COMPLETE", {
        "chain_id":        chain_id,
        "chain_compromised": chain_compromised,
        "chain_score":     chain_score,
        "verdict_counts":  verdict_counts,
        "report_file":     report_file,
    }, severity="CRITICAL")

    VERDICT_ICONS = {
        "EXECUTED":"⚠ ","PARTIAL":"△ ","BLOCKED":"✓ ",
        "CONCEPTUAL":"~ ","RECON_ONLY":"~ ","SKIPPED":"- ",
    }
    print(f"\n{'='*70}")
    print(f"  ЛАНЦЮЖОК ЗАВЕРШЕНО: {chain_def['name']}")
    print(f"  Chain score: {chain_score:.0f}%  ({'⚠  СКОМПРОМЕТОВАНО' if chain_compromised else '✓  ВІДБИТО'})")
    print(f"\n  Фази:")
    for r in phase_results:
        v = r.get("verdict", "?")
        vi = VERDICT_ICONS.get(v, "? ")
        http = r.get("http_success_rate", 0)
        wgt  = r.get("weighted_success_rate", 0)
        adap = "[A]" if r.get("is_adaptive") else "   "
        print(f"    {adap} Фаза {r['phase']}: {r['name']:<35} {vi}{v:<12} HTTP:{http:.0f}% W:{wgt:.0f}%")
    print(f"\n  IoC накопичено: {len(chain_report['accumulated_ioc'])}")
    ctx_keys = [k for k in chain_report["context_at_end"] if k != "election_uuid"]
    if ctx_keys:
        print(f"  Контекст передано: {ctx_keys}")
    print(f"  Звіт: {report_file}")
    print(f"{'='*70}\n")

    return chain_report


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  ATTACK CHAIN v2 — Цифрова імунна система")
    print("  APT-ланцюжки атак з передачею контексту між фазами")
    print("=" * 70)
    print(f"\n  Доступні ланцюжки:")
    for name, chain in CHAINS.items():
        print(f"    {name:<15} — {chain['name']}")
    print(f"\n  Флаги: --original  (використовувати оригінальні сценарії, не адаптивні)")

    prefer_adaptive = "--original" not in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if args and args[0] in CHAINS:
        run_chain(args[0], prefer_adaptive=prefer_adaptive)
    elif args and args[0] == "all":
        for chain_name in CHAINS:
            run_chain(chain_name, prefer_adaptive=prefer_adaptive)
            time.sleep(1)
    else:
        print("\n  Використання:")
        print("    python attack_chain.py system_apt")
        print("    python attack_chain.py voter_apt")
        print("    python attack_chain.py all")
        print("    python attack_chain.py system_apt --original")
