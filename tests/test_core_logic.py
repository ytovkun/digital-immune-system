"""
Unit tests for the pure logic of core/ modules (no servers or Claude calls):
  - risk_scorer        : scoring formulas (CIA/LINDDUN/execution/composite)
  - attack_generator   : JSON sanitization and recovery, catalog validation
  - red_team_agent     : context interpolation and step-success evaluation
Run:  pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import risk_scorer as rs
import attack_generator as ag
import red_team_agent as rta


# ═══ risk_scorer ══════════════════════════════════════════════════════════════

def test_cia_score_all_critical_is_one():
    # weights 0.35+0.45+0.20 = 1.0, Critical=1.0 → sum 1.0
    assert rs.cia_score({"confidentiality": "Critical", "integrity": "Critical",
                         "availability": "Critical"}) == 1.0


def test_cia_score_defaults_low_when_missing():
    # missing keys → Low (0.25) → 0.25 * (0.35+0.45+0.20) = 0.25
    assert rs.cia_score({}) == 0.25


def test_parse_linddun_maps_keywords():
    assert rs.parse_linddun("I — Identifiability") == ["I"]
    assert "Nr" in rs.parse_linddun("Non-repudiation + Tracking")
    assert rs.parse_linddun("щось невідоме") == ["L"]   # дефолт


def test_linddun_score_single_vs_multi():
    single = rs.linddun_score("Identifiability")          # base I=0.20
    multi  = rs.linddun_score("Identifiability + Tracking")  # +0.05 бонус
    assert multi > single


def test_execution_factor_executed_full():
    assert rs.execution_factor({"verdict": "EXECUTED",
                                "weighted_success_rate": 100}) == 1.0


def test_execution_factor_blocked_low():
    # BLOCKED base 0.20, 0 success → 0.12
    assert rs.execution_factor({"verdict": "BLOCKED",
                                "http_success_rate": 0}) == 0.12


def test_score_report_bounds_and_level():
    report = {
        "attack_class": "ballot_stuffing", "verdict": "EXECUTED",
        "weighted_success_rate": 100, "severity": "Critical",
        "mitre_technique_id": "T1565.001", "linddun_category": "Linkability",
        "affected_cia": {"confidentiality": "High", "integrity": "Critical",
                         "availability": "High"},
    }
    out = rs.score_report(report)
    assert 0 <= out["composite_score"] <= 10
    assert out["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    # critical, executed attack with high CIA → should be high risk
    assert out["risk_level"] in ("CRITICAL", "HIGH")


def test_score_report_blocked_lower_than_executed():
    base = {
        "attack_class": "x", "severity": "Critical",
        "mitre_technique_id": "T1565", "linddun_category": "Linkability",
        "affected_cia": {"confidentiality": "Critical", "integrity": "Critical",
                         "availability": "Critical"},
    }
    executed = rs.score_report({**base, "verdict": "EXECUTED",
                                "weighted_success_rate": 100})
    blocked = rs.score_report({**base, "verdict": "BLOCKED",
                               "weighted_success_rate": 0})
    assert executed["composite_score"] > blocked["composite_score"]


# ═══ attack_generator ═════════════════════════════════════════════════════════

def test_sanitize_json_removes_trailing_comma():
    import json
    fixed = ag._sanitize_json('{"a": 1, "b": [1, 2,]}')
    assert json.loads(fixed) == {"a": 1, "b": [1, 2]}


def test_sanitize_json_strips_line_comments():
    import json
    raw = '{\n  "a": 1, // коментар\n  "b": 2\n}'
    assert json.loads(ag._sanitize_json(raw)) == {"a": 1, "b": 2}


def test_repair_truncated_json_closes_brackets():
    import json
    repaired = ag._repair_truncated_json('{"a": 1, "items": [10, 20')
    obj = json.loads(repaired)
    assert obj["a"] == 1 and obj["items"] == [10, 20]


def test_repair_truncated_ignores_brackets_in_strings():
    import json
    repaired = ag._repair_truncated_json('{"note": "value with [ and { inside"')
    assert json.loads(repaired)["note"] == "value with [ and { inside"


def test_generate_unknown_class_raises():
    import pytest
    with pytest.raises(ValueError):
        ag.generate_attack_scenario("totally_unknown_class")


def test_attack_catalog_structure():
    assert len(ag.ATTACK_CATALOG) >= 10
    for name, info in ag.ATTACK_CATALOG.items():
        assert info["vector"] in ("system", "voter")
        assert "stride" in info and "linddun" in info


# ═══ red_team_agent ═══════════════════════════════════════════════════════════

def test_interpolate_replaces_placeholder():
    assert rta.interpolate("/helios/{uuid}/view", {"uuid": "abc"}) == "/helios/abc/view"


def test_interpolate_non_string_passthrough():
    assert rta.interpolate(42, {"x": "y"}) == 42


def test_interpolate_dict_nested():
    ctx = {"uuid": "E1", "tok": "T1"}
    out = rta.interpolate_dict(
        {"url": "/e/{uuid}", "items": ["{tok}", 5], "n": 3}, ctx)
    assert out == {"url": "/e/E1", "items": ["T1", 5], "n": 3}


def test_evaluate_step_success_403_fails():
    ok, reason = rta.evaluate_step_success("GET", "/x", 403, "body", "", {})
    assert ok is False and "403" in reason


def test_evaluate_step_success_200_ok():
    ok, _ = rta.evaluate_step_success("GET", "/x", 200, "a fairly long body", "", {})
    assert ok is True


def test_evaluate_step_success_200_empty_fails():
    ok, _ = rta.evaluate_step_success("GET", "/x", 200, "  ", "", {})
    assert ok is False


def test_evaluate_step_success_local_simulated():
    ok, reason = rta.evaluate_step_success("LOCAL", None, None, "", "", {})
    assert ok is True and "SIMULATED" in reason


def test_evaluate_step_success_server_error_fails():
    ok, _ = rta.evaluate_step_success("GET", "/x", 500, "boom", "", {})
    assert ok is False
