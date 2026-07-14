"""
Unit-тести посилення проксі (v6-hardening):
  #1 payload-бэкстоп у ТІЛІ (ШІ не обдурити)
  #2 fingerprint-антиген проти ротації IP
  #3 інспекція відповідей (анти-ексфільтрація)
  #5 _client_ip бере перший IP ланцюга XFF
  #6 circuit-breaker валідації сесій
  #8 Prometheus-endpoint
Запуск:  pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))

import immune_proxy as proxy
import threat_patterns as tp


# ─── #1 Детермінований payload-бэкстоп (path АБО тіло) ────────────────────────

def test_hard_payload_present_in_body():
    # SQLi/SSTI у ТІЛІ (L1 матчить лише path і пропустив би) → бэкстоп ловить
    assert tp.hard_payload_present("/helios/x/cast", "choice=1 UNION SELECT pwd")
    assert tp.hard_payload_present("/helios/x/cast", "v={{7*7}}")
    assert tp.hard_payload_present("/helios/x/cast", "x=<script>alert(1)</script>")


def test_hard_payload_fp_safe_on_legit_text():
    # вільний текст виборця НЕ має тригерити (FP=0): три крапки, hex, апостроф
    assert not tp.hard_payload_present("/helios/x/cast", "comment=wait... soon")
    assert not tp.hard_payload_present("/helios/x/cast", "note=color 0xFF nice")
    assert not tp.hard_payload_present("/helios/x/cast", "name=O'Brien")
    assert not tp.hard_payload_present("/helios/x/view", "choice=candidate_A")


def test_classify_hard_payload():
    assert tp.classify_hard_payload("/x", "union select") == "sql_injection"
    assert tp.classify_hard_payload("/x", "{{7*7}}") == "template_injection"
    assert tp.classify_hard_payload("/x", "hello world") is None


def test_body_backstop_blocks_despite_ai_allow(monkeypatch):
    # ГАРАНТІЯ: навіть якщо ШІ скаже ALLOW, payload у ТІЛІ → детермінований BLOCK.
    called = {"ai": False}

    def fake_allow(*a, **kw):
        called["ai"] = True
        return {"verdict": "ALLOW", "attack_class": None, "confidence": 0.0,
                "reasoning": "ai fooled", "from_cache": False, "latency_ms": 0.1}

    monkeypatch.setattr(proxy.analyst, "analyze", fake_allow)
    proxy._actor_history.clear()
    c = proxy.app.test_client()
    r = c.post("/helios/elections/abc/cast",
               headers={"X-Forwarded-For": "203.0.113.7"},
               data="choice=1 UNION SELECT password FROM voters")
    assert r.status_code == 403                     # бэкстоп заблокував
    body = r.get_json()
    assert body["attack_class"] == "sql_injection"
    assert called["ai"] is False                    # ШІ навіть не запитали (детерм. до нього)


# ─── #5 _client_ip — перший IP ланцюга XFF ────────────────────────────────────

def test_parse_client_ip_takes_first_hop():
    assert proxy._parse_client_ip("1.2.3.4, 10.0.0.1, 10.0.0.2", "9.9.9.9") == "1.2.3.4"
    assert proxy._parse_client_ip("  5.5.5.5  ", "9.9.9.9") == "5.5.5.5"


def test_parse_client_ip_fallback_to_remote():
    assert proxy._parse_client_ip(None, "9.9.9.9") == "9.9.9.9"
    assert proxy._parse_client_ip("", "9.9.9.9") == "9.9.9.9"
    assert proxy._parse_client_ip(None, None) == "127.0.0.1"


# ─── #2 Fingerprint-антиген: кореляція ротації IP ─────────────────────────────

def test_fingerprint_distinct_ips_counts_rotation():
    import time
    proxy._fp_history.clear()
    now = time.time()
    fp = "fp:test123"
    for i in range(6):                      # один відбиток — 6 різних IP за секунди
        proxy._record_fingerprint(fp, f"10.0.0.{i}", now)
    assert proxy._fp_distinct_ips(fp, now) == 6     # ротація IP видима за антигеном


def test_fingerprint_distinct_ips_isolated_per_fp():
    import time
    proxy._fp_history.clear()
    now = time.time()
    proxy._record_fingerprint("fp:A", "1.1.1.1", now)
    proxy._record_fingerprint("fp:B", "2.2.2.2", now)
    assert proxy._fp_distinct_ips("fp:A", now) == 1
    assert proxy._fp_distinct_ips("fp:unknown", now) == 0


def test_client_fingerprint_stable_and_distinct():
    c = proxy.app.test_client()
    # відбиток детермінований для однакових заголовків
    with proxy.app.test_request_context("/", headers={"User-Agent": "Browser/1"}):
        from flask import request
        fp1 = proxy._client_fingerprint(request.headers)
    with proxy.app.test_request_context("/", headers={"User-Agent": "Browser/1"}):
        from flask import request
        fp2 = proxy._client_fingerprint(request.headers)
    with proxy.app.test_request_context("/", headers={"User-Agent": "curl/8"}):
        from flask import request
        fp3 = proxy._client_fingerprint(request.headers)
    assert fp1 == fp2 and fp1.startswith("fp:")
    assert fp1 != fp3                       # інший клієнт → інший антиген


# ─── #4 Єдине джерело темп-логіки ─────────────────────────────────────────────

def test_recent_distinct_endpoints_single_source():
    import time
    proxy._actor_history.clear()
    now = time.time()
    for ep in ("/a", "/b", "/c"):
        proxy._record_request("z", "GET", ep, now)
    assert len(proxy._recent_distinct_endpoints("z", now)) == 3
    assert proxy._nonhuman_tempo("z", now) is False
    proxy._record_request("z", "GET", "/d", now)
    assert proxy._nonhuman_tempo("z", now) is True   # 4-й різний → бот-темп


# ─── #3 Інспекція відповідей (анти-ексфільтрація) ─────────────────────────────

def test_exfil_verdict_flags_large_dump():
    big = proxy.EXFIL_SOFT_BYTES + 1
    assert proxy._exfil_verdict("/helios/x/voters/", "GET", big) == "flag"
    assert proxy._exfil_verdict("/helios/x/ballots/", "GET", big) == "flag"


def test_exfil_verdict_ignores_normal_and_nonlist():
    assert proxy._exfil_verdict("/helios/x/voters/", "GET", 100) == ""     # малий
    assert proxy._exfil_verdict("/helios/x/view", "GET", 10**7) == ""      # не list-endpoint
    assert proxy._exfil_verdict("/helios/x/voters/", "POST", 10**7) == ""  # не GET


def test_exfil_verdict_hard_block_when_enabled(monkeypatch):
    monkeypatch.setattr(proxy, "EXFIL_HARD_BYTES", 1000)
    assert proxy._exfil_verdict("/helios/x/voters/", "GET", 2000) == "block"


# ─── #6 Circuit-breaker валідації сесій ───────────────────────────────────────

def test_circuit_breaker_opens_after_failures():
    import time
    now = time.time()
    proxy._helios_cb["fails"] = 0
    proxy._helios_cb["open_until"] = 0.0
    assert proxy._cb_is_open(now) is False
    for _ in range(proxy.HELIOS_CB_FAIL_THRESHOLD):
        proxy._cb_record_fail(now)
    assert proxy._cb_is_open(now) is True            # розімкнено після N збоїв
    # поза вікном — знову замкнено
    assert proxy._cb_is_open(now + proxy.HELIOS_CB_OPEN_SEC + 1) is False


def test_circuit_breaker_success_resets_fails():
    import time
    now = time.time()
    proxy._helios_cb["fails"] = 0
    proxy._helios_cb["open_until"] = 0.0
    proxy._cb_record_fail(now)
    proxy._cb_record_fail(now)
    proxy._cb_record_success()
    assert proxy._helios_cb["fails"] == 0            # успіх скинув лічильник
    proxy._cb_record_fail(now)                        # ще не поріг
    assert proxy._cb_is_open(now) is False


def test_validate_session_short_circuits_when_breaker_open():
    import time
    now = time.time()
    # розмикаємо ланцюг → валідація має повернути False БЕЗ виклику Helios
    proxy._helios_cb["open_until"] = now + 100
    proxy._session_cache.clear()
    assert proxy._validate_session("somesid", "/helios/elections/abc/view") is False
    proxy._helios_cb["open_until"] = 0.0              # прибираємо за собою


# ─── #8 Prometheus-endpoint ───────────────────────────────────────────────────

def test_prometheus_metrics_endpoint():
    c = proxy.app.test_client()
    r = c.get("/__immune__/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers.get("Content-Type", "")
    txt = r.get_data(as_text=True)
    assert "dis_requests_total" in txt
    assert "dis_blocked_ai_total" in txt
    assert "# TYPE dis_requests_total counter" in txt


def test_exfil_suspected_in_stats_json():
    c = proxy.app.test_client()
    body = c.get("/__immune__/stats").get_json()
    assert "exfil_suspected" in body          # узгодженість із Prometheus/метриками


# ─── Гігієна: verbose-блоки (демо vs прод) ────────────────────────────────────

def test_block_response_verbose_on_exposes_details():
    proxy.VERBOSE_BLOCKS = True
    r = proxy.make_block_response({"attack_class": "sql_injection", "reason": "x"}, "FastReflex")
    import json
    body = json.loads(r.get_data(as_text=True))
    assert body["attack_class"] == "sql_injection"
    assert body["blocked_by"] == "FastReflex"


def test_block_response_verbose_off_hides_details(monkeypatch):
    monkeypatch.setattr(proxy, "VERBOSE_BLOCKS", False)
    r = proxy.make_block_response({"attack_class": "sql_injection", "reason": "x"}, "FastReflex")
    import json
    body = json.loads(r.get_data(as_text=True))
    assert "attack_class" not in body          # у проді не підказуємо ЩО спрацювало
    assert "reason" not in body
    assert body["error"].startswith("Forbidden")   # лишається мінімальна 403


# ─── Бэкстоп тіла сканує ГЛИБШЕ за 2КБ-превʼю ШІ ──────────────────────────────

def test_backstop_catches_payload_beyond_ai_preview(monkeypatch):
    # payload за зміщенням >AI_BODY_PREVIEW (2КБ) у ТІЛІ — превʼю ШІ його не бачить,
    # але бэкстоп читає до BACKSTOP_BODY_BYTES і ловить детерміновано.
    monkeypatch.setattr(proxy.analyst, "analyze",
                        lambda *a, **k: {"verdict": "ALLOW", "attack_class": None,
                                         "confidence": 0.0, "reasoning": "", "from_cache": False})
    proxy._actor_history.clear()
    padding = "x" * 3000                         # > 2КБ превʼю
    c = proxy.app.test_client()
    r = c.post("/helios/elections/abc/cast",
               headers={"X-Forwarded-For": "203.0.113.9"},
               data=f"note={padding} UNION SELECT secret")
    assert r.status_code == 403                  # спіймано попри зміщення >2КБ
