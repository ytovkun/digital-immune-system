"""
Unit-тести довготривалої імунної памʼяті (PersistentMemory).
Запуск:  pytest tests/ -v
"""

import sys
import time
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))
from ai_analyst import PersistentMemory


def _tmpdb():
    return Path(tempfile.mktemp(suffix=".db"))


def test_store_and_load():
    db = _tmpdb()
    m = PersistentMemory(db)
    m.store("sig1", {"verdict": "BLOCK", "attack_class": "sqli",
                     "confidence": 0.9, "reasoning": "r"}, time.time() + 100)
    loaded = m.load_valid(time.time())
    assert len(loaded) == 1
    assert loaded[0][0] == "sig1"
    assert loaded[0][1]["verdict"] == "BLOCK"
    os.remove(db)


def test_survives_restart():
    db = _tmpdb()
    PersistentMemory(db).store("s", {"verdict": "BLOCK", "attack_class": "x",
                                     "confidence": 1.0, "reasoning": "r"}, time.time() + 100)
    # «рестарт» — нове зʼєднання
    m2 = PersistentMemory(db)
    assert m2.count() == 1
    os.remove(db)


def test_expired_not_loaded():
    db = _tmpdb()
    m = PersistentMemory(db)
    m.store("old", {"verdict": "BLOCK", "attack_class": "x",
                    "confidence": 1.0, "reasoning": "r"}, time.time() - 1)  # протерміновано
    assert len(m.load_valid(time.time())) == 0
    os.remove(db)


def test_prune_expired():
    db = _tmpdb()
    m = PersistentMemory(db)
    m.store("a", {"verdict": "BLOCK", "attack_class": "x",
                  "confidence": 1.0, "reasoning": "r"}, time.time() - 1)
    m.store("b", {"verdict": "BLOCK", "attack_class": "x",
                  "confidence": 1.0, "reasoning": "r"}, time.time() + 100)
    m.prune_expired(time.time())
    assert m.count() == 1   # лише непротермінований лишився
    os.remove(db)
