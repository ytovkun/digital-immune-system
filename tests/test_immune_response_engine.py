"""
Unit-тести Immune Response Engine (offline-агрегація) — без БД-оркестратора:
  - ThreatClassifier  : класифікація STRIDE/MITRE/LINDDUN + рівень ризику
  - ResponseSelector  : вибір дій реагування
  - detect_from_immune_blocks : ІНТЕГРАЦІЯ inline-проксі → offline-двигун
Запуск:  pytest tests/ -v
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import immune_response_engine as ire


# ═══ ThreatClassifier ═════════════════════════════════════════════════════════

def test_classify_known_class():
    c = ire.ThreatClassifier().classify(
        {"attack_class": "ballot_stuffing", "verdict": "EXECUTED",
         "success_rate": 90, "weighted_rate": 90})
    assert c["stride"] == "Tampering"
    assert c["mitre"].startswith("T1565")
    assert c["risk_level"] in ("Critical", "High", "Medium", "Low")


def test_classify_blocked_lowers_risk():
    base = {"attack_class": "manipulation"}
    executed = ire.ThreatClassifier().classify(
        {**base, "verdict": "EXECUTED", "success_rate": 90, "weighted_rate": 90})
    blocked = ire.ThreatClassifier().classify(
        {**base, "verdict": "BLOCKED", "success_rate": 0, "weighted_rate": 0})
    order = ire.ThreatClassifier.RISK_ORDER
    assert order[blocked["risk_level"]] <= order[executed["risk_level"]]


def test_classify_unknown_infers_signature():
    c = ire.ThreatClassifier().classify(
        {"attack_class": "unknown", "name": "ballot race cast stuffing"})
    # за ключовими словами має зматчити сигнатуру (не дефолт T0000 завжди)
    assert "mitre" in c and c["risk_level"] in ("Critical", "High", "Medium", "Low")


# ═══ ResponseSelector ═════════════════════════════════════════════════════════

def test_response_selector_known_actions():
    cls = {"attack_class": "ballot_stuffing", "risk_level": "Critical",
           "stride": "Tampering", "mitre": "T1565.001"}
    r = ire.ResponseSelector().select(cls, {"success_rate": 80})
    assert "BLOCK" in r["actions"]
    assert r["urgency"] in ("IMMEDIATE", "HIGH", "MEDIUM", "LOW")
    assert r["auto_remediate"] is True   # Critical + BLOCK


def test_response_selector_unknown_defaults():
    cls = {"attack_class": "no_such_class", "risk_level": "Medium"}
    r = ire.ResponseSelector().select(cls, {"success_rate": 10})
    assert r["actions"] == ["ALERT", "LOG"]


# ═══ ІНТЕГРАЦІЯ: inline-проксі → offline-двигун ═══════════════════════════════

def _write_blocks(lines):
    p = Path(tempfile.mktemp(suffix=".jsonl"))
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return p


def test_detect_from_immune_blocks_ingests_only_blocks():
    p = _write_blocks([
        {"tier": "FastReflex", "verdict": "BLOCK", "method": "POST",
         "path": "/helios/elections/x/cast", "client_ip": "9.9.9.9",
         "attack_class": "ballot_stuffing", "reason": "race", "signal": "concurrency",
         "timestamp": "2026-06-08T00:00:00"},
        {"tier": "AIAnalyst", "verdict": "ALLOW"},   # не блок → ігнор
    ])
    inc = ire.ThreatDetector().detect_from_immune_blocks(p)
    p.unlink()
    assert len(inc) == 1
    assert inc[0]["source"] == "inline_proxy"
    assert inc[0]["verdict"] == "BLOCKED"
    assert inc[0]["is_successful"] is False
    assert inc[0]["attack_id"].startswith("INLINE-")


def test_detect_from_immune_blocks_unique_ids():
    p = _write_blocks([
        {"tier": "FastReflex", "verdict": "BLOCK", "method": "GET",
         "path": "/a", "client_ip": "1.1.1.1", "attack_class": "x",
         "timestamp": "2026-06-08T00:00:01"},
        {"tier": "FastReflex", "verdict": "BLOCK", "method": "GET",
         "path": "/b", "client_ip": "1.1.1.1", "attack_class": "x",
         "timestamp": "2026-06-08T00:00:02"},
    ])
    inc = ire.ThreatDetector().detect_from_immune_blocks(p)
    p.unlink()
    assert len({i["attack_id"] for i in inc}) == 2   # різні інциденти не зливаються


def test_detect_from_immune_blocks_missing_file():
    inc = ire.ThreatDetector().detect_from_immune_blocks(Path("/no/such/file.jsonl"))
    assert inc == []


def test_inline_block_flows_through_classify_and_respond():
    p = _write_blocks([
        {"tier": "AIAnalyst", "verdict": "BLOCK", "method": "POST",
         "path": "/helios/elections/x/encrypt_tally", "client_ip": "7.7.7.7",
         "attack_class": "tally_manipulation", "reason": "early tally",
         "confidence": 0.95, "timestamp": "2026-06-08T00:00:00"},
    ])
    inc = ire.ThreatDetector().detect_from_immune_blocks(p)[0]
    p.unlink()
    cls = ire.ThreatClassifier().classify(inc)
    resp = ire.ResponseSelector().select(cls, inc)
    assert cls["mitre"].startswith("T1565")
    assert isinstance(resp["actions"], list) and resp["actions"]
