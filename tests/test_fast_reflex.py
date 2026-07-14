"""
Unit-тести FastReflex (Уровень 1) — без живих серверів.
Запуск:  pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))
from fast_reflex import FastReflex, CONCURRENCY_THRESHOLD, MAX_TRACKED_KEYS


def make():
    return FastReflex()


# ─── Сигнатурні блоки L1 ──────────────────────────────────────────────────────

def test_devlogin_post_blocked():
    d = make().evaluate("POST", "/auth/devlogin/login", {}, "1.1.1.1", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "impersonation"


def test_devlogin_get_not_blocked():
    # GET форми devlogin — не атака
    d = make().evaluate("GET", "/auth/devlogin/login", {}, "1.1.1.1", "s")
    assert d["verdict"] != "BLOCK"


def test_csrf_external_referer_blocked():
    d = make().evaluate("POST", "/helios/elections/x/trustees/u/upload-decryption",
                        {"Referer": "http://evil.com/x"}, "1.1.1.1", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "csrf_trustee_takeover"


def test_csrf_local_referer_goes_to_inspect():
    d = make().evaluate("POST", "/helios/elections/x/trustees/u/upload-decryption",
                        {"Referer": "http://localhost:8000/x"}, "1.1.1.1", "s")
    assert d["verdict"] == "INSPECT"


# ─── Concurrency (race condition) ─────────────────────────────────────────────

def test_concurrency_blocks_after_threshold():
    r = make()
    verdicts = [r.evaluate("POST", "/helios/elections/x/cast", {}, "1.1.1.1", "sess")["verdict"]
                for _ in range(CONCURRENCY_THRESHOLD + 2)]
    # перші (THRESHOLD-1) не блок, далі — блок
    assert verdicts[0] != "BLOCK"
    assert "BLOCK" in verdicts[CONCURRENCY_THRESHOLD - 1:]


# ─── Rate-limit лише на POST логіну (фікс false-positive) ─────────────────────

def test_login_get_not_rate_limited():
    r = make()
    blocked = sum(1 for _ in range(30)
                  if r.evaluate("GET", "/helios/x/password_voter_login", {},
                                "2.2.2.2", "s")["verdict"] == "BLOCK")
    assert blocked == 0   # GET форми логіну ніколи не блокується


def test_login_post_rate_limited():
    r = make()
    verdicts = [r.evaluate("POST", "/auth/password/login", {}, "3.3.3.3", "s")["verdict"]
                for _ in range(15)]
    assert "BLOCK" in verdicts   # флуд логіну блокується


def test_ballots_harvest_rate_limited():
    # масовий збір бюлетенів (timing-деанон recon) → блок за rate
    r = make()
    verdicts = [r.evaluate("GET", f"/helios/elections/x/ballots/h{i}", {},
                           "7.7.7.7", "s")["verdict"] for i in range(30)]
    assert "BLOCK" in verdicts


# ─── Обучаемый L1: ШІ синтезує сигнатуру → миттєвий блок (adaptive→innate) ────

def test_learned_signature_blocks_at_l1():
    r = make()
    # до навчання новий патерн проходить (не BLOCK)
    d0 = r.evaluate("GET", "/helios/x/foo?w=zzqx", {}, "8.8.8.8", "s")
    assert d0["verdict"] != "BLOCK"
    # ШІ навчив L1 сигнатурі
    assert r.add_learned_signature("zzqx", "novel_attack") is True
    d1 = r.evaluate("GET", "/helios/x/foo?w=zzqx", {}, "8.8.8.8", "s")
    assert d1["verdict"] == "BLOCK"
    assert d1["attack_class"] == "novel_attack"
    assert "learned" in d1["signal"]


def test_learned_signature_rejects_too_short():
    r = make()
    assert r.add_learned_signature("ab", "x") is False    # <4 символів — відхилено
    assert r.add_learned_signature("", "x") is False


# ─── ОДНОЗНАЧНІ payload → детермінований L1-БЛОК (0мс, без ШІ) ────────────────

def test_path_traversal_blocked_at_l1():
    d = make().evaluate("GET", "/helios/elections/x/../../etc/passwd", {}, "4.4.4.4", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "path_traversal"


def test_sql_injection_blocked_at_l1():
    # «' OR '» — однозначна SQL-тавтологія → L1 блокує сам
    d = make().evaluate("GET", "/helios/x/voters/?q=1' OR '1'='1", {}, "4.4.4.4", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "sql_injection"


def test_xss_script_blocked_at_l1():
    d = make().evaluate("GET", "/helios/x/view?m=<script>alert(1)</script>", {}, "4.4.4.4", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "xss"


# ─── ВИСОКОРИЗИКОВІ admin/verb/tally → детермінований L1-БЛОК (стабільно) ─────

def test_dangerous_verb_blocked_at_l1():
    # DELETE/PUT/PATCH до /helios/ — виборець не робить → детермінований блок
    d = make().evaluate("DELETE", "/helios/elections/x/ballots/h", {}, "4.4.4.4", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "dangerous_verb"


def test_admin_lifecycle_blocked_at_l1():
    d = make().evaluate("POST", "/helios/elections/x/keygenerator", {}, "4.4.4.4", "s")
    assert d["verdict"] == "BLOCK"
    assert d["attack_class"] == "admin_lifecycle"


def test_tally_ops_blocked_at_l1():
    for ep in ("encrypt_tally", "freeze", "combine_decryptions"):
        d = make().evaluate("POST", f"/helios/elections/x/{ep}", {}, "4.4.4.4", "s")
        assert d["verdict"] == "BLOCK", ep


def test_cast_still_goes_to_ai():
    # голос виборця — НЕ детермінований блок, рішення за ШІ (виборці голосують)
    d = make().evaluate("POST", "/helios/elections/x/cast", {}, "4.4.4.4", "s")
    assert d["verdict"] == "INSPECT"


def test_get_login_page_is_allowed():
    # GET форми логіну — лише показ форми → ALLOW (не на ШІ, без FP)
    d = make().evaluate("GET", "/helios/elections/x/password_voter_login", {}, "4.4.4.4", "s")
    assert d["verdict"] == "ALLOW"


def test_single_post_login_allowed():
    # одиночна спроба логіну → ALLOW на L1 (флуд стереже rate-limit, бот — темп-фільтр)
    d = make().evaluate("POST", "/auth/password/login", {}, "4.4.4.4", "s")
    assert d["verdict"] == "ALLOW"


def test_legit_apostrophe_not_l1_blocked():
    # апостроф у прізвищі (O'Brien) — НЕ однозначний payload → не L1-блок (FP=0),
    # йде на ШІ (INSPECT), який вирішить що це легіт
    d = make().evaluate("GET", "/helios/x/voters/?q=o'brien", {}, "4.4.4.4", "s")
    assert d["verdict"] == "INSPECT"      # не BLOCK на L1


def test_normal_request_allowed():
    d = make().evaluate("GET", "/helios/elections/x/view", {}, "5.5.5.5", "s")
    assert d["verdict"] == "ALLOW"
    assert d["signal"] is None


# ─── Латентність L1 — суб-мілісекундна ────────────────────────────────────────

def test_latency_is_submillisecond():
    d = make().evaluate("GET", "/helios/elections/x/view", {}, "6.6.6.6", "s")
    assert d["latency_ms"] < 5.0   # рефлекс має бути швидким


# ─── Евікція пам'яті (захист від memory-DoS) ──────────────────────────────────

def test_memory_eviction_caps_keys():
    r = make()
    # генеруємо багато унікальних IP → ключі мають евіктитись
    for i in range(MAX_TRACKED_KEYS + 5000):
        r.evaluate("GET", "/helios/x/voters/", {}, f"10.0.{i//256}.{i%256}", "s")
    # після евікції словники не безмежні
    assert len(r._rate_windows) <= MAX_TRACKED_KEYS + 2000
