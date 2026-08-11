"""
Unit tests for newer framework logic (no live servers):
  - benchmark borderline stress set + roc_auc
  - the 'held' metric in co-evolution (incl. bypass attacks without crit ops)
  - exclusion of adaptive reports from defense_report
  - decide_adaptation_mode (escalate/refine/bypass)
Run:  pytest tests/ -v
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))


# ─── Borderline stress set + ROC-AUC ──────────────────────────────────────────

def test_borderline_dataset_balanced_and_valid():
    import benchmark as b
    ds = b.build_borderline()
    assert len(ds) >= 10
    legit = sum(1 for x in ds if x["label"] == "legit")
    attack = sum(1 for x in ds if x["label"] == "attack")
    assert legit >= 4 and attack >= 4          # збалансовано
    need = {"label", "method", "path", "headers", "body", "why", "browser", "auth"}
    for it in ds:                              # структура сумісна із send()
        assert need <= set(it)


def test_roc_auc_perfect_separation():
    import benchmark as b
    assert b.roc_auc([(1, 0.9), (1, 0.8), (0, 0.1), (0, 0.0)]) == 1.0


def test_roc_auc_partial_overlap_below_one():
    import benchmark as b
    auc = b.roc_auc([(1, 0.9), (1, 0.4), (0, 0.5), (0, 0.1)])
    assert 0.5 < auc < 1.0                      # перекриття → реалістичний AUC


# ─── Co-evolution: the 'held' metric (0 dangerous ops reached) ────────────────

def _item(crit_total, crit_blocked, crit_reached):
    return {"crit_total": crit_total, "crit_blocked": crit_blocked,
            "crit_reached": crit_reached}


def test_held_metric_all_blocked():
    import coevolution_report as cr
    s = cr._gen_stats([_item(2, 2, 0), _item(1, 1, 0)])
    assert s["held"] == 2 and s["leaked"] == 0 and s["held_pct"] == 100.0
    assert s["critical_ops_blocked"] == 3 and s["critical_ops_total"] == 3


def test_held_metric_bypass_zero_critical():
    # bypass attacks WITHOUT crit ops → held 100% (0 reached), block_rate undefined
    import coevolution_report as cr
    s = cr._gen_stats([_item(0, 0, 0), _item(0, 0, 0), _item(0, 0, 0)])
    assert s["held"] == 3 and s["held_pct"] == 100.0
    assert s["block_rate_pct"] is None
    assert s["neutralized_pct"] == 100.0       # визначено навіть без крит-операцій


def test_held_metric_counts_leak():
    import coevolution_report as cr
    s = cr._gen_stats([_item(2, 1, 1), _item(1, 1, 0)])   # перша пропустила 1 оп
    assert s["leaked"] == 1 and s["held"] == 1 and s["held_pct"] == 50.0


# ─── Defense: exclusion of adaptive reports ───────────────────────────────────

def test_defense_excludes_adaptive_reports(tmp_path, monkeypatch):
    import defense_report as dr
    att = tmp_path / "attacks" / "defended"
    att.mkdir(parents=True)
    (att / "ATK-1_report.json").write_text("{}", encoding="utf-8")
    (att / "ATK-1_adaptive_report.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(dr, "REPORTS_DIR", tmp_path)
    files = dr._collect_reports("defended")
    assert len(files) == 1 and files[0].endswith("ATK-1_report.json")   # без adaptive


# ─── adaptive_generator: mutation mode selection ──────────────────────────────

def test_decide_adaptation_mode_thresholds():
    import adaptive_generator as ag
    assert ag.decide_adaptation_mode({"http_success_rate": 80, "steps_real_http": 5})[0] == "escalate"
    assert ag.decide_adaptation_mode({"http_success_rate": 50, "steps_real_http": 5})[0] == "refine"
    assert ag.decide_adaptation_mode({"http_success_rate": 20, "steps_real_http": 5})[0] == "bypass"
    assert ag.decide_adaptation_mode({"http_success_rate": 0, "steps_real_http": 0})[0] == "simulate_only"
