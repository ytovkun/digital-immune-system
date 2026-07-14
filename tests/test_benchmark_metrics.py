"""
Unit-тести метрик бенчмарку: ROC-AUC та точки ROC (за threat_score),
інтервал Вілсона. Чиста математика, без серверів.
Запуск:  pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))
import benchmark as b


def test_roc_auc_perfect_separation():
    pairs = [(1, 0.9), (1, 1.0), (0, 0.0), (0, 0.1)]
    assert b.roc_auc(pairs) == 1.0


def test_roc_auc_ties_half():
    assert b.roc_auc([(1, 0.5), (0, 0.5)]) == 0.5   # рівні скори → 0.5


def test_roc_auc_none_when_single_class():
    assert b.roc_auc([(1, 0.9), (1, 0.8)]) is None
    assert b.roc_auc([(0, 0.1), (0, 0.2)]) is None


def test_roc_points_in_unit_square():
    pts = b.roc_points([(1, 0.9), (1, 1.0), (0, 0.0), (0, 0.1)])
    assert pts
    assert all(0.0 <= fp <= 1.0 and 0.0 <= tp <= 1.0 for fp, tp, _ in pts)


def test_wilson_interval_bounds():
    lo, hi = b.wilson_interval(40, 40)   # 40/40 успіхів
    assert 0.0 <= lo <= hi <= 1.0
    assert lo > 0.8   # нижня межа висока навіть за 100%
