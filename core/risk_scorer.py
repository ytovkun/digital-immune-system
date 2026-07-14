"""
Модуль: Risk Scorer v2
Цифрова імунна система — risk_scorer.py

Читає репорти red_team_agent v2 → розраховує числовий ризик-скор
на основі CIA + LINDDUN + MITRE ATT&CK + execution verdict.
Генерує таблиці для дисертації (розділ 3.4).

Формула:
  Risk = (CIA×0.35 + LINDDUN×0.25 + MITRE×0.15 + Execution×0.25) × Severity × 10
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config


_cfg = load_config()
PROJECT_ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent))
REPORTS_DIR = str(PROJECT_ROOT / _cfg.get("paths", {}).get("reports_dir", "reports"))

CIA_WEIGHTS = {
    "confidentiality": 0.35,
    "integrity":       0.45,
    "availability":    0.20,
}

LINDDUN_WEIGHTS = {
    "L":  0.15,
    "I":  0.20,
    "T":  0.10,
    "Td": 0.10,
    "D":  0.10,
    "Nr": 0.15,
    "Nc": 0.15,
    "U":  0.05,
}

SEVERITY_MAP = {
    "Critical": 1.00, "High": 0.75, "Medium": 0.50, "Low": 0.25, "None": 0.00,
    "C": 1.00, "Crit": 1.00,
    "H": 0.75,
    "M": 0.50, "Med": 0.50,
    "L": 0.25,
}

VERDICT_FACTOR = {
    "EXECUTED":   1.00,
    "PARTIAL":    0.65,
    "BLOCKED":    0.20,
    "CONCEPTUAL": 0.40,
    "RECON_ONLY": 0.30,
}

MITRE_BONUS_MAP = {
    "T1565": 0.20, "T1606": 0.18, "T1539": 0.15,
    "T1530": 0.15, "T1185": 0.18, "T1566": 0.12,
    "T1499": 0.10, "T1531": 0.12, "T1040": 0.08,
}


def parse_linddun(linddun_str: str) -> list:
    mapping = {
        "Linkability": "L", "Identifiability": "I", "Tracking": "T",
        "Targeted": "Td", "Detectability": "D", "Non-repudiation": "Nr",
        "Non-compliance": "Nc", "Unawareness": "U",
    }
    return [code for kw, code in mapping.items() if kw.lower() in linddun_str.lower()] or ["L"]


def cia_score(affected_cia: dict) -> float:
    s = sum(SEVERITY_MAP.get(affected_cia.get(k, "Low"), 0.25) * w
            for k, w in CIA_WEIGHTS.items())
    return round(s, 3)


def linddun_score(linddun_str: str) -> float:
    codes = parse_linddun(linddun_str)
    base = max(LINDDUN_WEIGHTS.get(c, 0.1) for c in codes)
    bonus = 0.05 * (len(codes) - 1)
    return round(min(base + bonus, 1.0), 3)


def execution_factor(report: dict) -> float:
    verdict = report.get("verdict", "")
    base = VERDICT_FACTOR.get(verdict, 0.5)
    wrate = report.get("weighted_success_rate", report.get("http_success_rate", 0))
    return round(base * 0.6 + (wrate / 100) * 0.4, 3)


def score_report(report: dict) -> dict:
    cia     = cia_score(report.get("affected_cia", {}))
    linddun = linddun_score(report.get("linddun_category", "L"))
    exec_f   = execution_factor(report)
    severity = SEVERITY_MAP.get(report.get("severity", "High"), 0.75)
    mitre_id  = report.get("mitre_technique_id", "")
    mitre_b   = next((v for k, v in MITRE_BONUS_MAP.items() if mitre_id.startswith(k)), 0.05)
    raw   = (cia * 0.35 + linddun * 0.25 + mitre_b * 0.15 + exec_f * 0.25) * severity
    score = round(raw * 10, 2)
    risk_level = (
        "CRITICAL" if score >= 7.5 else
        "HIGH"     if score >= 5.5 else
        "MEDIUM"   if score >= 3.5 else
        "LOW"
    )
    return {
        "attack_id":              report.get("attack_id"),
        "attack_class":           report.get("attack_class"),
        "name":                   report.get("name", ""),
        "vector":                 report.get("vector", "system"),
        "is_adaptive":            bool(report.get("adaptation_mode")),
        "stride_category":        report.get("stride_category", ""),
        "mitre_technique_id":     mitre_id,
        "mitre_technique_name":   report.get("mitre_technique_name", ""),
        "linddun_category":       report.get("linddun_category", ""),
        "severity_declared":      report.get("severity", ""),
        "verdict":                report.get("verdict", ""),
        "http_success_rate":      report.get("http_success_rate", 0),
        "weighted_success_rate":  report.get("weighted_success_rate", 0),
        "critical_executability": report.get("critical_executability", 0),
        "components": {
            "cia": cia, "linddun": linddun,
            "mitre_b": mitre_b, "exec_f": exec_f, "severity": severity,
        },
        "composite_score": score,
        "risk_level":      risk_level,
        "helios_vulns":    report.get("helios_vulns_exploited", []),
        "voter_impact":    report.get("voter_impact", {}),
    }


def load_and_score(include_adaptive: bool = True) -> list:
    latest = {}
    for f in sorted(Path(REPORTS_DIR).rglob("*_report.json"),
                    key=lambda x: json.load(open(x)).get("executed_at", "")):
        if "chain" in f.name:
            continue
        try:
            r = json.load(open(f, encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            print(f"[!] Пропускаю пошкоджений репорт {f.name}: {e}", file=sys.stderr)
            continue
        ac = r.get("attack_class")
        is_adaptive = bool(r.get("adaptation_mode"))
        if not include_adaptive and is_adaptive:
            continue
        if ac:
            # ключ = (клас, адаптивність): базова й адаптивна версії — окремі рядки
            latest[(ac, is_adaptive)] = r
    scores = [score_report(r) for r in latest.values()]
    # групуємо по класу, базова перед адаптивною (для порівняння еволюції)
    return sorted(scores, key=lambda x: (x["attack_class"], x["is_adaptive"]))


def print_risk_table(scores: list):
    VERDICT_ICONS = {
        "EXECUTED": "⚠ ", "PARTIAL": "△ ", "BLOCKED": "✓ ",
        "CONCEPTUAL": "~ ", "RECON_ONLY": "~ ",
    }
    RL_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    print(f"\n{'='*100}")
    print("  ТАБЛИЦЯ РИЗИКІВ — Цифрова імунна система Helios e-voting")
    print("  Формула: Risk = (CIA×0.35 + LINDDUN×0.25 + MITRE×0.15 + Exec×0.25) × Severity × 10")
    print(f"{'='*100}")
    print(f"  {'Клас атаки':<42} {'CIA':>5} {'LND':>5} {'Exec':>5} {'Score':>6}  {'Рівень':<10} Verdict")
    print(f"  {'─'*95}")
    for label, group in [('🖥  SYSTEM', [s for s in scores if s['vector'] == 'system']),
                          ('👤 VOTER',  [s for s in scores if s['vector'] == 'voter'])]:
        if not group:
            continue
        print(f"\n  ── {label} ──")
        for s in group:
            c = s['components']
            vi = VERDICT_ICONS.get(s['verdict'], '? ')
            rl = RL_ICONS.get(s['risk_level'], '') + ' ' + s['risk_level']
            tag = '[A]' if s['is_adaptive'] else '   '
            print(f"  {tag} {s['attack_class']:<42} "
                  f"{c['cia']:>5.2f} {c['linddun']:>5.2f} {c['exec_f']:>5.2f} "
                  f"{s['composite_score']:>6.2f}  {rl:<14} {vi}{s['verdict']}")
    print(f"\n  {'─'*95}")
    if scores:
        avg = sum(s['composite_score'] for s in scores) / len(scores)
        top = max(scores, key=lambda s: s['composite_score'])
        rl_counts = defaultdict(int)
        for s in scores:
            rl_counts[s['risk_level']] += 1
        print(f"  Середній скор:   {avg:.2f}/10")
        print(f"  Найвищий ризик:  {top['attack_class']} → {top['composite_score']:.2f} ({top['risk_level']})")
        print("  Розподіл: " + " | ".join(f"{k}:{v}" for k, v in sorted(rl_counts.items())))
    print(f"{'='*100}\n")


def generate_dissertation_table(scores: list) -> str:
    lines = [
        "ТАБЛИЦЯ 3.2 — Кількісна оцінка ризиків атак на систему Helios e-voting",
        "",
        f"{'№':<3} {'Клас атаки':<35} {'Вектор':<8} {'STRIDE':<18} "
        f"{'CIA':>5} {'LINDDUN':>7} {'Exec':>5} {'Score':>6}  {'Ризик':<9} Тип",
        "─" * 104,
    ]
    for i, s in enumerate(scores, 1):
        c = s['components']
        vector = 'Voter' if s['vector'] == 'voter' else 'System'
        kind = 'адапт.' if s['is_adaptive'] else 'базов.'
        lines.append(
            f"{i:<3} {s['attack_class']:<35} {vector:<8} "
            f"{s['stride_category'][:17]:<18} "
            f"{c['cia']:>5.2f} {c['linddun']:>7.2f} "
            f"{c['exec_f']:>5.2f} {s['composite_score']:>6.2f}  {s['risk_level']:<9} {kind}"
        )
    lines.append("─" * 104)
    if scores:
        avg = sum(s['composite_score'] for s in scores) / len(scores)
        lines += [
            f"{'Середнє':<72} {avg:>6.2f}", "",
            "Примітки:",
            "  Тип    — 'адапт.' = сценарій адаптовано (adaptation_mode), 'базов.' = початковий",
            "  CIA    — зважений показник CIA (Confidentiality×0.35, Integrity×0.45, Availability×0.20)",
            "  LINDDUN — показник загрози приватності (LINDDUN framework)",
            "  Exec   — фактор реального виконання (на основі verdict + weighted_success_rate)",
            "  Score  — комплексний ризик-скор за шкалою 0–10",
        ]
    return "\n".join(lines)


def print_voter_impact_table(scores: list):
    voter_scores = [s for s in scores if s['vector'] == 'voter' and s['voter_impact']]
    if not voter_scores:
        return
    print(f"\n{'='*90}")
    print("  ТАБЛИЦЯ 3.3 — Вплив атак на виборця (людино-орієнтований вектор)")
    print(f"{'='*90}")
    print(f"  {'Клас атаки':<38} {'Score':>6}  Psychological impact")
    print(f"  {'─'*85}")
    for s in voter_scores:
        vi = s['voter_impact']
        print(f"  {s['attack_class']:<38} {s['composite_score']:>6.2f}  {vi.get('psychological','—')[:55]}")
        print(f"  {'':38}        Technical: {vi.get('technical','—')[:70]}")
        print(f"  {'':38}        Scale:     {vi.get('scale','—')[:70]}")
        print()
    print(f"{'='*90}\n")


if __name__ == "__main__":
    include_adaptive = "--no-adaptive" not in sys.argv
    print("=" * 65)
    print("  RISK SCORER v2 — Цифрова імунна система")
    print("  CIA + LINDDUN + MITRE ATT&CK + Execution Verdict")
    print(f"  Адаптивні сценарії: {'включено' if include_adaptive else 'виключено'}")
    print("=" * 65)
    scores = load_and_score(include_adaptive=include_adaptive)
    if not scores:
        print("[-] Немає репортів. Спочатку запусти red_team_agent.py")
        sys.exit(1)
    print_risk_table(scores)
    print_voter_impact_table(scores)
    diss_table = generate_dissertation_table(scores)
    print(diss_table)
    ts = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    risk_dir = f"{REPORTS_DIR}/risk"
    os.makedirs(risk_dir, exist_ok=True)
    json_file = f"{risk_dir}/risk_assessment_{ts}.json"
    json.dump({
        "generated_at": datetime.utcnow().isoformat(),
        "include_adaptive": include_adaptive,
        "total": len(scores),
        "scores": scores,
        "summary": {
            "avg_score": round(sum(s['composite_score'] for s in scores) / len(scores), 2),
            **{k: sum(1 for s in scores if s['risk_level'] == k)
               for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        }
    }, open(json_file, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    txt_file = f"{risk_dir}/dissertation_table_{ts}.txt"
    open(txt_file, "w", encoding="utf-8").write(diss_table)
    print(f"\n[+] JSON: {json_file}")
    print(f"[+] Таблиця: {txt_file}")
