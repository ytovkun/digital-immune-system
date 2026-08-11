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
