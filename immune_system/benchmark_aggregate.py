"""
Benchmark aggregator — median + spread over N benchmark runs.
Digital immune system — immune_system/benchmark_aggregate.py

L2 (the Claude judge) is non-deterministic, so a SINGLE benchmark run is not a
reportable headline (one run gave Recall 1.0/AUC 1.0, others 0.95/0.967 — reviewer).
This reads the last N benchmark_*.json reports and reports, per metric, the MEDIAN
and the [min, max] range, plus which attack classes were UNSTABLE across runs (the
probabilistic L2 part) vs stable (the deterministic L1 + backstop part).

Usage:
  # run the benchmark several times first (proxy up, reset enabled):
  for i in 1 2 3 4 5; do python immune_system/benchmark.py; done
  python immune_system/benchmark_aggregate.py [N]     # default N = last 5
Out:  console table + reports/benchmark/benchmark_aggregate_{ts}.json
"""

import sys
import json
import glob
import statistics
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
REPORTS = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent)) \
    / _cfg.get("paths", {}).get("reports_dir", "reports")
BENCH_DIR = REPORTS / "benchmark"


def _fmt(vals):
    """median [min, max] for a list of numbers."""
    if not vals:
        return "—"
    med = statistics.median(vals)
    return f"{med:.3f}  [{min(vals):.3f}, {max(vals):.3f}]"


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5
    files = sorted(glob.glob(str(BENCH_DIR / "benchmark_2*.json")))[-n:]
    if len(files) < 2:
        print(f"  ⚠️  Потрібно ≥2 прогони бенчмарку у {BENCH_DIR} "
              f"(знайдено {len(files)}). Прожени benchmark.py кілька разів.")
        return
    runs = [json.load(open(f, encoding="utf-8")) for f in files]
    print("=" * 74)
    print(f"  📊 АГРЕГАТ БЕНЧМАРКУ — {len(runs)} прогонів (медіана [min, max])")
    print("=" * 74)

    def col(path):
        out = []
        for r in runs:
            cur = r
            for k in path:
                cur = (cur or {}).get(k) if isinstance(cur, dict) else None
            if isinstance(cur, (int, float)):
                out.append(float(cur))
        return out

    rows = [
        ("Precision",        col(["metrics", "precision"])),
        ("Recall/Detection", col(["metrics", "recall"])),
        ("F1",               col(["metrics", "f1"])),
        ("FPR",              col(["metrics", "fpr"])),
        ("ROC-AUC (осн.)",   col(["roc_auc"])),
        ("ROC-AUC (комб.)",  col(["roc_auc_combined"])),
        ("Гранична Recall",  col(["borderline", "metrics", "recall"])),
    ]
    for name, vals in rows:
        print(f"  {name:<20} {_fmt(vals)}")

    apt_det = [r.get("apt_detection", {}).get("detected") for r in runs
               if isinstance(r.get("apt_detection", {}).get("detected"), int)]
    apt_tot = runs[0].get("apt_detection", {}).get("total", 3)
    if apt_det:
        print(f"  {'APT детекція':<20} медіана {int(statistics.median(apt_det))}/{apt_tot}"
              f"  [{min(apt_det)}, {max(apt_det)}]  (L2 недетермінований!)")

    # deterministic vs probabilistic: which attack classes MISSED in some runs
    unstable, stable = set(), set()
    for r in runs:
        for cls, st in (r.get("attack_by_class") or {}).items():
            if st.get("missed", 0) > 0:
                unstable.add(cls)
    for r in runs:
        for cls in (r.get("attack_by_class") or {}):
            if cls not in unstable:
                stable.add(cls)
    print("\n  ── Детермінована частина (стабільна L1/бэкстоп, ловиться щоразу) ──")
    print("     " + ", ".join(sorted(stable)) if stable else "     —")
    print("  ── Імовірнісна частина (L2, варіює між прогонами) ──")
    print("     " + (", ".join(sorted(unstable)) if unstable else "— (нічого не варіювало)"))
    print("\n  💡 Для дисертації: подавай МЕДІАНУ з діапазоном за N прогонів, а не")
    print("     один вдалий 1.000. Детермінована частина відтворювана; L2 — діапазон.")
    print("=" * 74)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_runs": len(runs),
        "runs": [Path(f).name for f in files],
        "median_range": {name: ({"median": statistics.median(v), "min": min(v),
                                 "max": max(v)} if v else None) for name, v in rows},
        "apt_detected_median": (int(statistics.median(apt_det)) if apt_det else None),
        "apt_total": apt_tot,
        "deterministic_classes": sorted(stable),
        "probabilistic_classes": sorted(unstable),
    }
    (BENCH_DIR / f"benchmark_aggregate_{ts}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [+] Збережено: reports/benchmark/benchmark_aggregate_{ts}.json")


if __name__ == "__main__":
    main()
