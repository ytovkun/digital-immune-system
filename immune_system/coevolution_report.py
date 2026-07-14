"""
Модуль: CoevolutionReport — метрика ко-еволюції «щит vs меч»
Цифрова імунна система — immune_system/coevolution_report.py

Показує ДИНАМІКУ протистояння поколінь атак і захисту — головний науковий
артефакт дисертації: GenAI-генератор мутує атаку під блокування (adaptive_generator
читає 403 → escalate/refine/bypass), а ЦІС тримає захист і вчить нові сигнатури.

Покоління:
  gen-0 (baseline) — звіти БЕЗ adaptation_mode (вихідні згенеровані атаки)
  gen-1 (adaptive) — звіти З adaptation_mode (escalate/refine/bypass під тиском блоку)

Для кожного покоління рахується частка НЕЙТРАЛІЗОВАНИХ vs ПРОПУЩЕНИХ (через
defense_report — джерело істини «дійшла критична операція до Helios чи ні»).

ВАЖЛИВО: значущі цифри виходять лише якщо атаки прогнані ЧЕРЕЗ проксі :8000
(інакше всі статуси 200 і все «пропущено»). Скрипт це детектує і підкаже.

Запуск:  python immune_system/coevolution_report.py
Вихід:   таблиця + reports/coevolution/coevolution_{ts}.json + .txt
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_loader import load_config
from defense_report import analyze_report, classify_defense

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS_DIR = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")

# Статуси, що означають «критична операція зупинена захистом»
_NEUTRALIZED = {"NEUTRALIZED", "PARTIAL_BLOCK"}
_LEAKED = {"LEAKED"}


SCOPED_SUBDIRS = ("baseline", "defended")


def _load_enriched(scope: str = "") -> list:
    """Завантажує ATK-звіти, додає generation + статус захисту.
    scope='defended'|'baseline' → лише reports/attacks/<scope>/; порожньо = усі,
    АЛЕ БЕЗ campaign-наборів (щоб не змішати baseline+defended в одній метриці)."""
    if scope:
        base = REPORTS_DIR / "attacks" / scope
        files = sorted(glob.glob(str(base / "**" / "ATK*_report.json"), recursive=True),
                       key=os.path.getmtime)
    else:
        allf = glob.glob(str(REPORTS_DIR / "**" / "ATK*_report.json"), recursive=True)
        allf = [f for f in allf
                if not any(f"{os.sep}attacks{os.sep}{s}{os.sep}" in f for s in SCOPED_SUBDIRS)]
        files = sorted(allf, key=os.path.getmtime)
    out = []
    for f in files:
        try:
            rep = json.load(open(f, encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        a = analyze_report(rep)
        a["generation"] = 1 if rep.get("adaptation_mode") else 0
        a["adaptation_mode"] = rep.get("adaptation_mode") or "baseline"
        a["status"] = classify_defense(a)
        out.append(a)
    return out


def _gen_stats(items: list) -> dict:
    """Зведення по поколінню. Головна метрика — HELD: скільки атак НЕ пропустили
    жодної небезпечної операції до Helios (crit_reached==0). Так коректно рахуються
    і bypass-атаки, що ВЗАГАЛІ уникають критичних операцій (0 крит → 0 leaked = held):
    захист змусив атаку відступити від прямої шкоди. Метрика 'block %' лишається для
    атак, що ВСЕ Ж намагались крит-операцію (де вона визначена)."""
    total = len(items)
    leaked = sum(1 for a in items if a["crit_reached"] > 0)   # ≥1 небезпечна оп дійшла
    held = total - leaked                                      # 0 небезпечних оп дійшло
    with_crit = [a for a in items if a["crit_total"] > 0]
    crit_blocked = sum(a["crit_blocked"] for a in items)
    crit_total = sum(a["crit_total"] for a in items)
    return {
        "attacks": total,
        "attacks_with_critical": len(with_crit),
        "held": held,
        "leaked": leaked,
        # neutralized_pct = held_pct (0 небезпечних операцій дійшло) — визначено ЗАВЖДИ
        "neutralized_pct": round(held / total * 100, 1) if total else None,
        "held_pct": round(held / total * 100, 1) if total else None,
        "leaked_pct": round(leaked / total * 100, 1) if total else None,
        "critical_ops_blocked": crit_blocked,
        "critical_ops_total": crit_total,
        "block_rate_pct": round(crit_blocked / crit_total * 100, 1) if crit_total else None,
    }


def main():
    ap = argparse.ArgumentParser(description="Метрика ко-еволюції захист vs атаки")
    ap.add_argument("--scope", default=os.environ.get("COEVO_SCOPE", ""),
                    help="defended | baseline (підпапка reports/attacks/); порожньо = усі")
    args = ap.parse_args()
    scope = args.scope.strip()

    items = _load_enriched(scope)
    if not items:
        where = f"reports/attacks/{scope}/" if scope else "reports/"
        print(f"[-] Немає ATK-звітів у {where}. Прожени red_team_agent "
              f"(для ко-еволюції — через проксі :8000).")
        return

    gen0 = [a for a in items if a["generation"] == 0]
    gen1 = [a for a in items if a["generation"] == 1]
    s0, s1 = _gen_stats(gen0), _gen_stats(gen1)

    any_block = sum(a["crit_blocked"] for a in items)

    print("=" * 84)
    print("  🧬 КО-ЕВОЛЮЦІЯ «ЩИТ vs МЕЧ» — динаміка поколінь атак проти ЦІС")
    print("=" * 84)
    if any_block == 0:
        print("  ⚠️  У звітах НЕМАЄ жодного 403-блоку критичної операції.")
        print("     Схоже, атаки прогнані повз проксі (проти сирого Helios :8001).")
        print("     Для значущої метрики прожени red_team ЧЕРЕЗ проксі:")
        print("       HELIOS_BASE_URL=http://localhost:8000 python core/red_team_agent.py all")
        print("-" * 84)

    hdr = f"  {'Покоління':<22}{'Атак':>6}{'Утримано':>14}{'Пропущено':>12}{'Блок крит.оп':>16}"
    print(hdr)
    print("  " + "─" * 80)
    for label, s in [("gen-0 (baseline)", s0), ("gen-1 (adaptive)", s1)]:
        if s["attacks"] == 0:
            continue
        held = f"{s['held']} ({s['held_pct']}%)" if s["held_pct"] is not None else "—"
        lk = f"{s['leaked']} ({s['leaked_pct']}%)" if s["leaked_pct"] is not None else "—"
        br = (f"{s['critical_ops_blocked']}/{s['critical_ops_total']}"
              if s["critical_ops_total"] else "немає (bypass уникає)")
        print(f"  {label:<22}{s['attacks']:>6}{held:>14}{lk:>12}{br:>16}")

    # Розбивка adaptive за режимом мутації (escalate/refine/bypass)
    if gen1:
        print("\n  ── Режими адаптації (під тиском блокувань) ──")
        by_mode = defaultdict(list)
        for a in gen1:
            by_mode[a["adaptation_mode"]].append(a)
        for mode, lst in sorted(by_mode.items()):
            sm = _gen_stats(lst)
            br = f"{sm['critical_ops_blocked']}/{sm['critical_ops_total']}" if sm["critical_ops_total"] else "немає крит."
            print(f"     {mode:<12} атак={sm['attacks']:<3} блок крит.оп={br}")

    # Класи, де захист тримається крізь покоління (по attack_class)
    print("\n  ── Стійкість захисту по класах (gen-0 → gen-1) ──")
    classes = sorted({a["attack_class"] for a in items if a["crit_total"] > 0})
    for ac in classes:
        g0 = [a for a in gen0 if a["attack_class"] == ac and a["crit_total"] > 0]
        g1 = [a for a in gen1 if a["attack_class"] == ac and a["crit_total"] > 0]
        def _br(lst):
            b = sum(x["crit_blocked"] for x in lst); t = sum(x["crit_total"] for x in lst)
            return f"{b}/{t}" if t else "—"
        if g0 or g1:
            print(f"     {ac:<40} gen0={_br(g0):<7} gen1={_br(g1):<7}")

    print("=" * 84)

    # ─── Збереження ─────────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ran_through_proxy": any_block > 0,
        "gen0": s0, "gen1": s1,
        "by_adaptation_mode": {
            m: _gen_stats([a for a in gen1 if a["adaptation_mode"] == m])
            for m in sorted({a["adaptation_mode"] for a in gen1})
        } if gen1 else {},
    }
    out_dir = REPORTS_DIR / "coevolution"
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{scope}_" if scope else ""
    (out_dir / f"coevolution_{tag}{ts}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  [+] Звіт збережено: reports/coevolution/coevolution_{tag}{ts}.json")

    # ─── Таблиця для дисертації ─────────────────────────────────────────────────
    tbl = [
        "ТАБЛИЦЯ 3.9 — Ко-еволюція захисту й атак (динаміка поколінь)",
        "",
        f"{'Покоління':<22}{'Атак':>6}{'Утримано,%':>13}{'Пропущено':>12}{'Блок крит.оп':>17}",
        "─" * 72,
    ]
    for label, s in [("gen-0 (baseline)", s0), ("gen-1 (adaptive)", s1)]:
        if s["attacks"] == 0:
            continue
        held = f"{s['held_pct']}" if s["held_pct"] is not None else "—"
        br = (f"{s['critical_ops_blocked']}/{s['critical_ops_total']}"
              if s["critical_ops_total"] else "немає (bypass уникає)")
        tbl.append(f"{label:<22}{s['attacks']:>6}{held:>13}{s['leaked']:>12}{br:>17}")
    tbl += ["─" * 72,
            "Утримано = жодна небезпечна операція не дійшла до Helios (0 витоків).",
            "Примітка: gen-1 — атаки, мутовані GenAI під тиском блокувань. bypass-варіанти",
            "  ВЗАГАЛІ уникають критичних операцій (захист змусив відступити від прямої шкоди).",
            "  Стійке утримання крізь покоління = захист генералізує, а не запам'ятовує IoC."]
    (out_dir / f"coevolution_table_{tag}{ts}.txt").write_text("\n".join(tbl), encoding="utf-8")
    print(f"  [+] Таблиця для дисертації: reports/coevolution/coevolution_table_{tag}{ts}.txt")


if __name__ == "__main__":
    main()
