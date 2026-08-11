"""
Run manifest: a single record of the final run (for reproducibility of chapter 3).
Digital immune system — utils/run_manifest.py

Collects into one file: git-commit, AI model, Python version, time (UTC) and a
SUMMARY of key metrics from the latest reports. So every number in the dissertation
is tied to a concrete commit and run. Writes reports/run_manifest.json + .txt.

Run:  python utils/run_manifest.py   (standalone, or as a campaign step)
"""

import sys
import json
import glob
import subprocess
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT),
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def _latest(sub, pat):
    fs = sorted(glob.glob(str(REPORTS / sub / pat)))
    if not fs:
        return None
    try:
        return json.load(open(fs[-1], encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def collect() -> dict:
    b = _latest("benchmark", "benchmark_*.json") or {}
    dd = _latest("defense", "defense_effectiveness_defended_*.json") or {}
    db = _latest("defense", "defense_effectiveness_baseline_*.json") or {}
    co = _latest("coevolution", "coevolution_defended_*.json") or {}
    mt = _latest("metrics", "metrics_summary_*.json") or {}

    bm = b.get("metrics", {})
    apt = b.get("apt_detection", {})
    sec = {k: v.get("value") for k, v in (mt.get("security_tests", {}) or {}).items()}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "python": sys.version.split()[0],
        "ai_model": _cfg.get("claude", {}).get("model", "?"),
        "election_uuid": _cfg.get("helios", {}).get("election_uuid", "?"),
        "reproducibility_note": (
            "ШІ-залежні результати (APT, гранична вибірка) виносить живий Claude — "
            "можлива варіативність ±ε між прогонами; L1-детекція та payload-бэкстоп "
            "детерміновані. Сирі рішення проксі — logs/immune_blocks.jsonl."),
        "key_metrics": {
            "benchmark": {
                "samples": b.get("samples"),
                "precision": bm.get("precision"), "recall": bm.get("recall"),
                "f1": bm.get("f1"), "fpr": bm.get("fpr"),
                "roc_auc": b.get("roc_auc"),
                "roc_auc_combined": b.get("roc_auc_combined"),
                "apt": f"{apt.get('detected')}/{apt.get('total')}",
            },
            "defense": {
                "baseline_blocked": db.get("summary", {}).get("critical_ops_blocked"),
                "baseline_reached": db.get("summary", {}).get("critical_ops_reached"),
                "defended_blocked": dd.get("summary", {}).get("critical_ops_blocked"),
                "defended_reached": dd.get("summary", {}).get("critical_ops_reached"),
                "defended_leaked": dd.get("summary", {}).get("leaked"),
            },
            "coevolution": {
                "gen0_held_pct": co.get("gen0", {}).get("held_pct"),
                "gen1_held_pct": co.get("gen1", {}).get("held_pct"),
                "adaptation_modes": list((co.get("by_adaptation_mode", {}) or {}).keys()),
            },
            "security_tests": sec,
        },
    }


def main():
    man = collect()
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "run_manifest.json").write_text(
        json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")

    km = man["key_metrics"]
    lines = [
        "=" * 68,
        "  RUN-МАНІФЕСТ — фінальний прогін ЦІС (для відтворюваності)",
        "=" * 68,
        f"  Час (UTC):   {man['generated_at']}",
        f"  Git commit:  {man['git_commit']}",
        f"  Модель ШІ:   {man['ai_model']}",
        f"  Python:      {man['python']}",
        "  " + "─" * 64,
        f"  Бенчмарк:    P={km['benchmark']['precision']} R={km['benchmark']['recall']} "
        f"F1={km['benchmark']['f1']} FPR={km['benchmark']['fpr']} "
        f"AUC={km['benchmark']['roc_auc']} (комб.{km['benchmark']['roc_auc_combined']})",
        f"  APT:         {km['benchmark']['apt']}",
        f"  Захист:      baseline {km['defense']['baseline_blocked']}/"
        f"{(km['defense']['baseline_blocked'] or 0)+(km['defense']['baseline_reached'] or 0)} → "
        f"defended {km['defense']['defended_blocked']}/"
        f"{(km['defense']['defended_blocked'] or 0)+(km['defense']['defended_reached'] or 0)} "
        f"(leaked={km['defense']['defended_leaked']})",
        f"  Ко-еволюція: gen0 held={km['coevolution']['gen0_held_pct']}% "
        f"gen1 held={km['coevolution']['gen1_held_pct']}% "
        f"modes={km['coevolution']['adaptation_modes']}",
        "  " + "─" * 64,
        "  " + man["reproducibility_note"],
        "=" * 68,
    ]
    txt = "\n".join(lines)
    (REPORTS / "run_manifest.txt").write_text(txt, encoding="utf-8")
    print(txt)
    print("\n  [+] Маніфест: reports/run_manifest.json + .txt")


if __name__ == "__main__":
    main()
