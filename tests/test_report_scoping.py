"""
Unit tests for baseline vs defended report separation (--scope) and red_team subdirs.
Verifies that a "bare" (no scope) run does NOT mix campaign sets.
Run:  pytest tests/ -v
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))

import defense_report as dr
import coevolution_report as cr


# ─── analyze_report: honest execution classification (login page / 302 / None) ──

def _step(endpoint, status, preview="", simulated=False):
    return {"result": {"endpoint": endpoint, "status_code": status,
                       "response_preview": preview, "is_simulated": simulated}}


def _report(steps, attack_class="ballot_stuffing"):
    return {"attack_class": attack_class, "vector": "system", "execution_log": steps}


def test_login_page_200_is_not_executed():
    # a private-election access page (200 + Helios shell) must count as NOT executed
    shell = '<!DOCTYPE html><html class="no-js"><title>Log In to View Election</title>'
    a = dr.analyze_report(_report([_step("/helios/e/abc/cast", 200, shell)]))
    assert a["crit_reached"] == 0
    assert a["crit_other"] == 1
    assert dr.classify_defense(a) == "NO_CRITICAL"


def test_redirect_302_is_not_executed():
    a = dr.analyze_report(_report([_step("/helios/e/abc/cast", 302, "")]))
    assert a["crit_reached"] == 0 and a["crit_other"] == 1


def test_real_json_dump_counts_as_executed():
    # a non-shell 2xx (real data disclosure) IS a genuine executed critical op
    a = dr.analyze_report(_report([_step("/helios/e/abc/cast", 200,
                                         '[{"vote_hash": "abc"}]')]))
    assert a["crit_reached"] == 1


def test_none_status_not_credited_without_prior_dis_block():
    # a failed request (status None) with NO preceding DIS block is NOT a DIS block
    a = dr.analyze_report(_report([_step("/helios/e/abc/cast", None, "")]))
    assert a["crit_blocked"] == 0 and a["crit_other"] == 1


def test_none_status_credited_after_dis_block():
    dis = _step("/helios/e/abc/cast", 403, "Digital Immune System: blocked")
    later = _step("/helios/e/abc/cast_confirm", None, "")
    a = dr.analyze_report(_report([dis, later]))
    assert a["crit_blocked"] == 2   # the 403 + the chain-broken None


def _mk(p: Path, name: str):
    p.mkdir(parents=True, exist_ok=True)
    (p / name).write_text(json.dumps({"attack_class": "x", "execution_log": []}),
                          encoding="utf-8")


def _setup(tmp_path):
    attacks = tmp_path / "attacks"
    _mk(attacks, "ATK-flat_report.json")                 # легасі-плаский звіт
    _mk(attacks / "baseline", "ATK-b_report.json")       # campaign baseline
    _mk(attacks / "defended", "ATK-d_report.json")       # campaign defended
    return attacks


# ─── defense_report ───────────────────────────────────────────────────────────

def test_defense_scope_baseline_only(tmp_path, monkeypatch):
    _setup(tmp_path)
    monkeypatch.setattr(dr, "REPORTS_DIR", tmp_path)
    files = dr._collect_reports("baseline")
    assert len(files) == 1 and files[0].endswith("ATK-b_report.json")


def test_defense_scope_defended_only(tmp_path, monkeypatch):
    _setup(tmp_path)
    monkeypatch.setattr(dr, "REPORTS_DIR", tmp_path)
    files = dr._collect_reports("defended")
    assert len(files) == 1 and files[0].endswith("ATK-d_report.json")


def test_defense_no_scope_excludes_campaign_sets(tmp_path, monkeypatch):
    _setup(tmp_path)
    monkeypatch.setattr(dr, "REPORTS_DIR", tmp_path)
    files = dr._collect_reports("")
    # no scope — only flat legacy, WITHOUT baseline/defended (no mixing)
    assert len(files) == 1 and files[0].endswith("ATK-flat_report.json")
    assert set(dr._scoped_sets_exist()) == {"baseline", "defended"}


# ─── coevolution_report ───────────────────────────────────────────────────────

def test_coevolution_scope_isolated(tmp_path, monkeypatch):
    _setup(tmp_path)
    monkeypatch.setattr(cr, "REPORTS_DIR", tmp_path)
    assert len(cr._load_enriched("baseline")) == 1
    assert len(cr._load_enriched("defended")) == 1
    # no scope — campaign sets excluded, only the flat one remains
    assert len(cr._load_enriched("")) == 1
