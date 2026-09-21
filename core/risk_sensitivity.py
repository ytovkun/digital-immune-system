"""
Sensitivity analysis of the risk-metric weights.
Digital immune system — core/risk_sensitivity.py

The composite risk score uses author-chosen additive weights
    w = (CIA 0.35, LINDDUN 0.25, MITRE 0.15, Execution 0.25).
To show the ranking does not hinge on that exact choice, each weight is perturbed by
±0.05 in turn, the four weights are renormalized to sum 1, and every scenario's score
is recomputed. We report the max score shift and whether the risk-LEVEL ordering
changes. Reads the latest reports/risk/risk_assessment_*.json (needs its per-scenario
`components`). Run AFTER risk_scorer.py.

Usage:  python core/risk_sensitivity.py [delta]     # default delta = 0.05
Out:    console table + reports/risk/risk_sensitivity_{ts}.json
"""

import sys
import json
import glob
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
REPORTS = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent)) \
    / _cfg.get("paths", {}).get("reports_dir", "reports")
RISK_DIR = REPORTS / "risk"

BASE_W = {"cia": 0.35, "linddun": 0.25, "mitre_b": 0.15, "exec_f": 0.25}
COMPONENTS = ("cia", "linddun", "mitre_b", "exec_f")
LABELS = {"cia": "CIA", "linddun": "LINDDUN", "mitre_b": "MITRE", "exec_f": "Execution"}


def _composite(comp: dict, w: dict) -> float:
    additive = sum(comp.get(k, 0.0) * w[k] for k in COMPONENTS)
    return round(additive * comp.get("severity", 0.75) * 10, 2)


def _level(score: float) -> str:
    return ("CRITICAL" if score >= 7.5 else "HIGH" if score >= 5.5
            else "MEDIUM" if score >= 3.5 else "LOW")


def _renorm(w: dict) -> dict:
    total = sum(w.values())
    return {k: v / total for k, v in w.items()}


def main():
    delta = float(sys.argv[1]) if len(sys.argv) > 1 else 0.05
    files = sorted(glob.glob(str(RISK_DIR / "risk_assessment_*.json")))
    if not files:
        print("  ⚠️  Немає risk_assessment — спершу прожени core/risk_scorer.py")
        return
    data = json.load(open(files[-1], encoding="utf-8"))
    scores = data.get("scores", data if isinstance(data, list) else [])
    rows = [{"attack_class": s.get("attack_class"), "adaptive": s.get("is_adaptive"),
             "components": s.get("components", {})} for s in scores if s.get("components")]
    if not rows:
        print("  ⚠️  У звіті немає per-scenario `components` — перепрожени risk_scorer.py")
        return

    base = {i: _composite(r["components"], BASE_W) for i, r in enumerate(rows)}
    base_levels = {i: _level(v) for i, v in base.items()}

    print("=" * 72)
    print(f"  📐 АНАЛІЗ ЧУТЛИВОСТІ ВАГ (±{delta}, з нормалізацією до суми 1)")
    print(f"  Сценаріїв: {len(rows)}  ·  базові ваги: "
          + ", ".join(f"{LABELS[k]}={v}" for k, v in BASE_W.items()))
    print("=" * 72)
    print(f"  {'Варіація ваги':<28}{'макс |Δскору|':>14}{'змін рівня':>14}")
    print(f"  {'─'*68}")

    variants = []
    worst_shift = 0.0
    total_level_changes = 0
    for comp in COMPONENTS:
        for sign in (+1, -1):
            w = dict(BASE_W)
            w[comp] = round(w[comp] + sign * delta, 4)
            if w[comp] < 0:
                continue
            wn = _renorm(w)
            max_d = 0.0
            lvl_changes = 0
            for i, r in enumerate(rows):
                sc = _composite(r["components"], wn)
                max_d = max(max_d, abs(sc - base[i]))
                if _level(sc) != base_levels[i]:
                    lvl_changes += 1
            worst_shift = max(worst_shift, max_d)
            total_level_changes += lvl_changes
            name = f"{LABELS[comp]} {'+' if sign > 0 else '−'}{delta}"
            print(f"  {name:<28}{max_d:>14.2f}{lvl_changes:>14}")
            variants.append({"weight": comp, "sign": sign, "max_score_shift": round(max_d, 2),
                             "level_changes": lvl_changes})

    print(f"  {'─'*68}")
    print(f"  Найбільший зсув скору по всіх варіаціях: {worst_shift:.2f} (зі шкали 0–10)")
    verdict = ("стійкий: ранжування за рівнем ризику НЕ змінюється"
               if total_level_changes == 0 else
               f"є {total_level_changes} змін рівня — інтерпретувати обережно")
    print(f"  Висновок: результат {verdict}.")
    print("=" * 72)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "delta": delta, "base_weights": BASE_W, "n_scenarios": len(rows),
        "max_score_shift": round(worst_shift, 2),
        "total_level_changes": total_level_changes,
        "robust": total_level_changes == 0,
        "variants": variants,
        "source_report": Path(files[-1]).name,
    }
    RISK_DIR.mkdir(parents=True, exist_ok=True)
    (RISK_DIR / f"risk_sensitivity_{ts}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [+] Збережено: reports/risk/risk_sensitivity_{ts}.json")


if __name__ == "__main__":
    main()
