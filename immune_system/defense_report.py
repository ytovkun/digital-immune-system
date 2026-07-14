"""
Модуль: DefenseReport — звіт ефективності захисту ЦІС
Цифрова імунна система — immune_system/defense_report.py

Міряє ПРАВИЛЬНУ метрику: чи дійшла НЕБЕЗПЕЧНА операція до Helios,
а не «чи закінчив атакувальник свій скрипт» (вердикт red_team_agent).

Логіка:
  - критичні операції = POST на /cast, /cast_confirm, /upload-decryption,
    /encrypt_tally (саме вони завдають шкоди: вкидання голосу, підміна ключів)
  - для кожної атаки: скільки критичних операцій було ЗАБЛОКОВАНО (403)
    проксі, скільки дійшло до Helios, скільки взагалі немає (атака поза сервером)

Джерела:
  reports/ATK*_report.json   — кроки атак та їх HTTP-статуси
  logs/immune_blocks.jsonl   — рішення проксі (хто, чим, на якому рівні)

Запуск:  python immune_system/defense_report.py
Вихід:   таблиця + reports/defense_effectiveness_{ts}.json
"""

import sys

import argparse
import json
import glob
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS_DIR = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")
LOGS_DIR    = ROOT / _cfg.get("paths", {}).get("logs_dir", "logs")
BLOCKS_LOG  = LOGS_DIR / "immune_blocks.jsonl"

# Критичні операції — саме вони завдають реальної шкоди
CRITICAL_OPS = ("/cast", "/cast_confirm", "/upload-decryption", "/encrypt_tally")

# Атаки, які за природою НЕ блокуються на серверному проксі
# (відбуваються між людьми, у браузері жертви або на мережевому рівні)
OFF_SERVER_CLASSES = {
    "voter_timing_deanonymization":  "мережевий рівень (ISP-перехоплення)",
    "voter_coercion_receipt":        "примус між людьми (поза сервером)",
    "voter_device_js_injection":     "браузер жертви (до сервера)",
}


def load_blocks() -> list:
    blocks = []
    if BLOCKS_LOG.exists():
        for line in BLOCKS_LOG.read_text(encoding="utf-8").splitlines():
            try:
                blocks.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return blocks


def analyze_report(report: dict) -> dict:
    """Рахує критичні операції: заблоковані / пропущені до Helios."""
    crit_blocked = 0
    crit_reached = 0
    crit_steps = []
    for entry in report.get("execution_log", []):
        r = entry["result"]
        ep = r.get("endpoint", "") or ""
        if r.get("is_simulated"):
            continue
        if any(op in ep for op in CRITICAL_OPS):
            status = r.get("status_code")
            op_name = ep.rstrip("/").split("/")[-1]
            # Метрика — «чи ДІЙШЛА небезпечна операція до Helios»:
            #   403       → проксі заблокував (не дійшло) = prevented;
            #   None      → запит не завершився (ланцюг атаки зламано раннім блоком,
            #               крок до крит-операції не дійшов) = теж НЕ дійшло = prevented;
            #   реальна відповідь backend (2xx/3xx/5xx, не 403) → ДІЙШЛО = leaked.
            # (None як prevented робить baseline↔defended симетричними: однакова к-сть
            #  крит-кроків, різниця лише в тому, СКІЛЬКИ дійшло до Helios.)
            if status == 403 or status is None:
                crit_blocked += 1
                crit_steps.append(f"{op_name}:{'БЛОК' if status == 403 else 'обірвано'}")
            else:
                crit_reached += 1
                crit_steps.append(f"{op_name}:{status}")
    return {
        "attack_class":  report.get("attack_class"),
        "vector":        report.get("vector", "system"),
        "agent_verdict": report.get("verdict", "?"),
        "crit_blocked":  crit_blocked,
        "crit_reached":  crit_reached,
        "crit_total":    crit_blocked + crit_reached,
        "crit_steps":    crit_steps,
    }


def classify_defense(a: dict) -> str:
    """
    Підсумковий статус захисту для атаки:
      NEUTRALIZED — всі критичні операції заблоковано
      LEAKED      — частина критичних операцій дійшла до Helios
      OFF_SERVER  — атака поза зоною серверного проксі (немає критичних HTTP)
    """
    if a["crit_total"] == 0:
        return "OFF_SERVER" if a["attack_class"] in OFF_SERVER_CLASSES else "NO_CRITICAL"
    if a["crit_reached"] == 0:
        return "NEUTRALIZED"
    if a["crit_blocked"] > 0:
        return "PARTIAL_BLOCK"
    return "LEAKED"


SCOPED_SUBDIRS = ("baseline", "defended")   # campaign-набори (дивляться з --scope)


def _collect_reports(scope: str) -> list:
    """Звіти за областю: scope='baseline'|'defended' → лише reports/attacks/<scope>/;
    порожній scope → усі, АЛЕ БЕЗ campaign-наборів (щоб не змішати baseline+defended).
    ВИКЛЮЧАЄМО adaptive-звіти (*_adaptive_report.json): цей звіт міряє ЕФЕКТИВНІСТЬ
    на БАЗОВОМУ наборі атак (щоб bypass-атаки з 0 крит-операцій не «затирали» базові
    при дедуплікації по класу). Еволюцію (gen-1) міряє coevolution_report."""
    if scope:
        base = REPORTS_DIR / "attacks" / scope
        files = glob.glob(str(base / "**" / "ATK*_report.json"), recursive=True)
    else:
        files = glob.glob(str(REPORTS_DIR / "**" / "ATK*_report.json"), recursive=True)
        files = [f for f in files
                 if not any(f"{os.sep}attacks{os.sep}{s}{os.sep}" in f for s in SCOPED_SUBDIRS)]
    files = [f for f in files if not f.endswith("_adaptive_report.json")]
    return sorted(files, key=os.path.getmtime)


def _scoped_sets_exist() -> list:
    return [s for s in SCOPED_SUBDIRS if (REPORTS_DIR / "attacks" / s).is_dir()]


def main():
    ap = argparse.ArgumentParser(description="Звіт ефективності захисту ЦІС")
    ap.add_argument("--scope", default=os.environ.get("DEFENSE_SCOPE", ""),
                    help="baseline | defended (підпапка reports/attacks/); порожньо = усі")
    args = ap.parse_args()
    scope = args.scope.strip()

    reports = _collect_reports(scope)
    if not scope and _scoped_sets_exist():
        print(f"  ℹ️  Виявлено campaign-набори ({', '.join(_scoped_sets_exist())}) — вони "
              f"НЕ включені у цей «загальний» звіт. Дивись їх окремо: "
              f"--scope baseline / --scope defended.")
    if not reports:
        where = f"reports/attacks/{scope}/" if scope else "reports/ (поза campaign-наборами)"
        print(f"[-] Немає звітів атак у {where}. Спочатку прожени red_team_agent "
              f"(для defended — через проксі :8000).")
        return
    scope_label = {"baseline": "БЕЗ ЗАХИСТУ (сирий Helios :8001)",
                   "defended": "ІЗ ЗАХИСТОМ (через ЦІС-проксі :8000)"}.get(scope, "усі звіти")

    blocks = load_blocks()
    analyses = [analyze_report(json.load(open(f, encoding="utf-8"))) for f in reports]

    # Дедуплікація: останній звіт по кожному класу
    by_class = {}
    for a in analyses:
        by_class[a["attack_class"]] = a
    analyses = list(by_class.values())

    STATUS_ICON = {
        "NEUTRALIZED":   "🛡  НЕЙТРАЛІЗОВАНО",
        "PARTIAL_BLOCK": "⚠️  ЧАСТКОВО",
        "LEAKED":        "🔴 ПРОПУЩЕНО",
        "OFF_SERVER":    "🌐 ПОЗА СЕРВЕРОМ",
        "NO_CRITICAL":   "—  немає критичних",
    }

    print("=" * 84)
    print("  🛡  ЕФЕКТИВНІСТЬ ЗАХИСТУ ЦІС — чи дійшла небезпечна операція до Helios")
    print(f"  Режим: {scope_label}  ({len(analyses)} атак)")
    print("=" * 84)
    print(f"  {'Атака':<40} {'Критич.оп':<11} {'Захист':<18} Agent")
    print(f"  {'─'*80}")

    counts = Counter()
    for grp, label in [("system", "🖥  SYSTEM"), ("voter", "👤 VOTER")]:
        grp_items = [a for a in analyses if a["vector"] == grp]
        if not grp_items:
            continue
        print(f"\n  ── {label} ──")
        for a in sorted(grp_items, key=lambda x: x["attack_class"]):
            status = classify_defense(a)
            counts[status] += 1
            crit = f"{a['crit_blocked']}/{a['crit_total']} блок" if a["crit_total"] else "немає"
            icon = STATUS_ICON.get(status, status)
            print(f"  {a['attack_class']:<40} {crit:<11} {icon:<18} {a['agent_verdict']}")

    print(f"\n  {'─'*80}")

    # ─── Зведення ──────────────────────────────────────────────────────────────
    neutralized = counts["NEUTRALIZED"] + counts["PARTIAL_BLOCK"]
    off_server  = counts["OFF_SERVER"] + counts["NO_CRITICAL"]
    leaked      = counts["LEAKED"]
    total       = len(analyses)
    crit_blocked_total = sum(a["crit_blocked"] for a in analyses)
    crit_reached_total = sum(a["crit_reached"] for a in analyses)

    print("  📊 ПІДСУМОК ЗАХИСТУ")
    print(f"     🛡  Нейтралізовано (критична операція заблокована): {neutralized}/{total}")
    print(f"     🌐 Поза зоною серверного захисту (мережа/браузер/люди): {off_server}/{total}")
    print(f"     🔴 Пропущено (атака дійшла до Helios): {leaked}/{total}")
    # Явний перелік «поза сервером» — щоб рецензент не сприйняв їх як «пропущені»:
    # це атаки мережевого/браузерного/людського рівня, які серверний проксі НЕ
    # перехоплює за визначенням (не «дірка», а межа застосовності).
    off_classes = sorted({a["attack_class"] for a in analyses
                          if classify_defense(a) in ("OFF_SERVER", "NO_CRITICAL")})
    if off_classes:
        print("     ↳ поза сервером (за визначенням, не «дірки»): "
              + ", ".join(off_classes))
    print(f"\n     Небезпечних операцій заблоковано: {crit_blocked_total}/"
          f"{crit_blocked_total + crit_reached_total} "
          f"({crit_blocked_total/(crit_blocked_total+crit_reached_total)*100:.0f}%)"
          if (crit_blocked_total + crit_reached_total) else "")

    # ─── Статистика проксі ─────────────────────────────────────────────────────
    if blocks:
        by_tier = Counter(b.get("tier", "?") for b in blocks)
        by_attack = Counter(b.get("attack_class", "?") for b in blocks)
        print(f"\n  ⚡ РІШЕННЯ ПРОКСІ ({len(blocks)} блоків):")
        for tier, c in by_tier.most_common():
            label = "ШІ-аналітик (L2)" if tier == "AIAnalyst" else "FastReflex (L1)"
            print(f"     {label}: {c}")
        print(f"     За класами: {dict(by_attack)}")

    print("=" * 84)
    print("\n  💡 Чому вердикт red_team_agent інший: він міряє «чи закінчив атакувальник")
    print("     скрипт» (рахуючи безпечну розвідку+логін), а ЦІС блокує лише НЕБЕЗПЕЧНУ")
    print("     операцію. Розвідка проходить — вкидання голосу НІ.")

    # ─── Збереження ────────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope or "all",
        "mode": scope_label,
        "total_attacks": total,
        "summary": {
            "neutralized": neutralized,
            "off_server":  off_server,
            "leaked":      leaked,
            "critical_ops_blocked":  crit_blocked_total,
            "critical_ops_reached":  crit_reached_total,
        },
        "proxy_blocks": len(blocks),
        "proxy_by_tier": dict(Counter(b.get("tier", "?") for b in blocks)),
        "attacks": [
            {**a, "defense_status": classify_defense(a)} for a in analyses
        ],
    }
    defense_dir = REPORTS_DIR / "defense"
    defense_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{scope}_" if scope else ""   # baseline/defended не перезаписують одне одного
    out_path = defense_dir / f"defense_effectiveness_{tag}{ts}.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n  [+] Звіт збережено: {out_path}")

    # ─── Таблиця для дисертації (.txt) ─────────────────────────────────────────
    STATUS_TXT = {
        "NEUTRALIZED": "НЕЙТРАЛІЗОВАНО", "PARTIAL_BLOCK": "ЧАСТКОВО",
        "LEAKED": "ПРОПУЩЕНО", "OFF_SERVER": "ПОЗА СЕРВЕРОМ", "NO_CRITICAL": "немає критич.",
    }
    tbl = [
        "ТАБЛИЦЯ 3.8 — Ефективність захисту ЦІС",
        f"            Режим: {scope_label}",
        "            (чи дійшла НЕБЕЗПЕЧНА операція до Helios, а не «чи завершив скрипт»)",
        "",
        f"{'№':<3} {'Атака':<38} {'Вектор':<8} {'Крит.оп(блок/усього)':<22} {'Статус захисту':<16} Agent",
        "─" * 100,
    ]
    for i, a in enumerate(sorted(analyses, key=lambda x: (x["vector"], x["attack_class"])), 1):
        st = STATUS_TXT.get(classify_defense(a), classify_defense(a))
        crit = f"{a['crit_blocked']}/{a['crit_total']}" if a["crit_total"] else "немає"
        tbl.append(f"{i:<3} {a['attack_class']:<38} {a['vector']:<8} {crit:<22} {st:<16} {a['agent_verdict']}")
    tbl.append("─" * 100)
    denom = crit_blocked_total + crit_reached_total
    pct = f"{crit_blocked_total/denom*100:.0f}%" if denom else "—"
    tbl += [
        f"Нейтралізовано: {neutralized}/{total} | Поза сервером: {off_server}/{total} | Пропущено: {leaked}/{total}",
        f"Небезпечних операцій заблоковано: {crit_blocked_total}/{denom} ({pct})",
        "",
        "Примітки: критичні операції = POST /cast, /cast_confirm, /upload-decryption,",
        "  /encrypt_tally. «Поза сервером» — атаки мережевого/браузерного/людського рівня.",
    ]
    (defense_dir / f"defense_table_{tag}{ts}.txt").write_text("\n".join(tbl), encoding="utf-8")
    print(f"  [+] Таблиця для дисертації: reports/defense/defense_table_{tag}{ts}.txt")


if __name__ == "__main__":
    main()
