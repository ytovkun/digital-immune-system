"""
Unit tests for proxy hardening (v6-hardening):
  #1 payload backstop in the BODY (the AI cannot be tricked)
  #2 fingerprint antigen against IP rotation
  #3 response inspection (anti-exfiltration)
  #5 _client_ip takes the first IP of the XFF chain
  #6 circuit breaker for session validation
  #8 Prometheus endpoint
Run:  pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))

import immune_proxy as proxy
import threat_patterns as tp


# ─── #1 Deterministic payload backstop (path OR body) ─────────────────────────

def test_hard_payload_present_in_body():
    # SQLi/SSTI in the BODY (L1 matches only the path and would pass it) → backstop catches
    assert tp.hard_payload_present("/helios/x/cast", "choice=1 UNION SELECT pwd")
    assert tp.hard_payload_present("/helios/x/cast", "v={{7*7}}")
    assert tp.hard_payload_present("/helios/x/cast", "x=<script>alert(1)</script>")


def test_hard_payload_fp_safe_on_legit_text():
    # a voter's free text must NOT trigger (FP=0): ellipsis, hex, apostrophe
    assert not tp.hard_payload_present("/helios/x/cast", "comment=wait... soon")
    assert not tp.hard_payload_present("/helios/x/cast", "note=color 0xFF nice")
    assert not tp.hard_payload_present("/helios/x/cast", "name=O'Brien")
    assert not tp.hard_payload_present("/helios/x/view", "choice=candidate_A")


def test_classify_hard_payload():
    assert tp.classify_hard_payload("/x", "union select") == "sql_injection"
    assert tp.classify_hard_payload("/x", "{{7*7}}") == "template_injection"
    assert tp.classify_hard_payload("/x", "hello world") is None


def test_body_backstop_blocks_despite_ai_allow(monkeypatch):
    # GUARANTEE: even if the AI says ALLOW, a payload in the BODY → deterministic BLOCK.
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
    assert r.status_code == 403                     # the backstop blocked it
    body = r.get_json()
    assert body["attack_class"] == "sql_injection"
    assert called["ai"] is False                    # the AI was not even asked (deterministic before it)


# ─── #5 _client_ip — the first IP of the XFF chain ────────────────────────────

def test_parse_client_ip_takes_rightmost_trusted_hop():
    # take the LAST trusted hop's entry (rightmost), NOT the spoofable leftmost —
    # otherwise an attacker forges the first XFF element to evade per-IP tracking
    assert proxy._parse_client_ip("1.2.3.4, 10.0.0.1, 10.0.0.2", "9.9.9.9") == "10.0.0.2"
    assert proxy._parse_client_ip("  5.5.5.5  ", "9.9.9.9") == "5.5.5.5"   # single value → that value
    # with 2 trusted hops in front, take the 2nd entry from the right
    assert proxy._parse_client_ip("1.2.3.4, 10.0.0.1, 10.0.0.2", "9", trusted_hops=2) == "10.0.0.1"


def test_parse_client_ip_fallback_to_remote():
    assert proxy._parse_client_ip(None, "9.9.9.9") == "9.9.9.9"
    assert proxy._parse_client_ip("", "9.9.9.9") == "9.9.9.9"
    assert proxy._parse_client_ip(None, None) == "127.0.0.1"


# ─── #2 Fingerprint antigen: IP rotation correlation ──────────────────────────

def test_fingerprint_distinct_ips_counts_rotation():
    import time
    proxy._fp_history.clear()
    now = time.time()
    fp = "fp:test123"
    for i in range(6):                      # one fingerprint — 6 different IPs in seconds
        proxy._record_fingerprint(fp, f"10.0.0.{i}", now)
    assert proxy._fp_distinct_ips(fp, now) == 6     # IP rotation visible via the antigen


# ─── Ballot-ownership antibody (stolen-credential vote manipulation) ──────────

def test_ballot_ownership_blocks_overwrite_from_new_source():
    proxy._ballot_owner.clear()
    # first legitimate cast from the voter's own source → learned as SELF, allowed
    assert proxy.ballot_ownership_verdict("elec1", "voter4", "203.0.113.20") == ""
    # same source re-voting (voter changes their mind) → still allowed
    assert proxy.ballot_ownership_verdict("elec1", "voter4", "203.0.113.20") == ""
    # a DIFFERENT source overwriting voter4's ballot → takeover → BLOCK
    assert proxy.ballot_ownership_verdict("elec1", "voter4", "198.51.100.7") == "block"
    # a different voter is independent
    assert proxy.ballot_ownership_verdict("elec1", "voter5", "198.51.100.7") == ""


def test_reset_endpoint_clears_ballot_ownership(monkeypatch):
    # REGRESSION: the reset endpoint must actually clear ownership (it previously
    # 500'd on a missing `os` import, so FPR reset silently failed → legit voters
    # false-blocked). Guard the whole path: gate + clearing.
    monkeypatch.setenv("DIS_TEST_RESET_ENABLED", "1")
    proxy._ballot_owner[("E", "v4")] = "1.1.1.1"
    proxy._session_voter["sid"] = ("v4", "E", 1.0)
    c = proxy.app.test_client()
    r = c.post("/__immune__/reset")
    assert r.status_code == 200                       # not 500 (the os-import regression)
    body = r.get_json()
    assert body["reset"] is True and body["ballot_owners_cleared"] >= 1
    assert len(proxy._ballot_owner) == 0 and len(proxy._session_voter) == 0


def test_reset_endpoint_disabled_without_flag(monkeypatch):
    monkeypatch.delenv("DIS_TEST_RESET_ENABLED", raising=False)
    c = proxy.app.test_client()
    assert c.post("/__immune__/reset").status_code == 403   # gated off by default


def test_ballot_ownership_fail_open_without_attribution():
    proxy._ballot_owner.clear()
    # no voter identity or no election → cannot attribute → must NOT block (fail-open)
    assert proxy.ballot_ownership_verdict("elec1", "", "1.1.1.1") == ""
    assert proxy.ballot_ownership_verdict("", "voter4", "1.1.1.1") == ""


def test_ballot_ownership_end_to_end_through_proxy(monkeypatch):
    """Integration: a GET /cast_confirm teaches the proxy the voter; the legit commit
    from the victim's source is allowed and binds ownership; a second commit for the
    SAME voter from a DIFFERENT source is blocked as vote_manipulation."""
    from flask import Response as FResp
    proxy._ballot_owner.clear()
    proxy._session_voter.clear()
    monkeypatch.setattr(proxy, "VERBOSE_BLOCKS", True)
    proxy._actor_history.clear()

    def fake_forward(path):
        # GET cast_confirm → the Helios confirm page naming the voter; POST → 302 commit
        if request.method == "GET":
            return FResp('<p>You are logged in as <u>voterX</u></p>', status=200)
        return FResp("", status=302)

    from flask import request
    monkeypatch.setattr(proxy, "forward_to_helios", fake_forward)
    monkeypatch.setattr(proxy.analyst, "analyze",
                        lambda *a, **k: {"verdict": "ALLOW", "attack_class": None,
                                         "confidence": 0.0, "reasoning": "", "from_cache": False})
    c = proxy.app.test_client()
    ep = "/helios/elections/c88cfaeb-abc0-4440-a165-a77cab2951f2/cast_confirm"

    # victim establishes ownership from their own address
    c.set_cookie("sessionid", "sid-victim", domain="localhost")
    c.get(ep, headers={"X-Forwarded-For": "203.0.113.20"})
    r1 = c.post(ep, headers={"X-Forwarded-For": "203.0.113.20"})
    assert r1.status_code == 302                      # legit commit allowed

    # attacker: same voter (learned via their own confirm GET), different source
    c.set_cookie("sessionid", "sid-attacker", domain="localhost")
    c.get(ep, headers={"X-Forwarded-For": "198.51.100.66"})
    r2 = c.post(ep, headers={"X-Forwarded-For": "198.51.100.66"})
    assert r2.status_code == 403                      # takeover blocked
    assert r2.get_json()["attack_class"] == "vote_manipulation"


def test_extract_voter_id_from_confirm_page():
    html = '<p>You are logged in as <u>voter4 name</u><br /><br /></p>'
    assert proxy._extract_voter_id(html) == "voter4 name"
    assert proxy._extract_voter_id("<p>nothing here</p>") == ""


def test_session_voter_memory_roundtrip():
    import time
    proxy._session_voter.clear()
    now = time.time()
    proxy._remember_session_voter("sid123", "voter4", "elec1", now)
    vid, elec = proxy._voter_for_session("sid123", now)
    assert vid == "voter4" and elec == "elec1"
    # expired entry is not returned
    assert proxy._voter_for_session("sid123", now + proxy.SESSION_VOTER_TTL + 1) == ("", "")


def test_fp_rotation_fast_distinguishes_crowd_from_apt():
    import time
    proxy._fp_history.clear()
    now = time.time()
    # legit CROWD: many voters sharing a browser fingerprint, spread over the minute
    # (one IP every 3s) — high distinct-IP count but NOT a fast burst → not flagged
    fp_crowd = "fp:crowd"
    for i in range(12):
        proxy._record_fingerprint(fp_crowd, f"203.0.113.{i}", now - (36 - i * 3))
    assert proxy._fp_distinct_ips(fp_crowd, now) >= 10       # high over the minute
    assert proxy._fp_rotation_fast(fp_crowd, now) is False   # but NOT a fast rotation
    # APT: one fingerprint cycling many IPs within a few seconds → flagged
    fp_apt = "fp:apt"
    for i in range(6):
        proxy._record_fingerprint(fp_apt, f"10.0.0.{i}", now - i)   # 6 IPs in 6s
    assert proxy._fp_rotation_fast(fp_apt, now) is True


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
    # the fingerprint is deterministic for identical headers
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
    assert fp1 != fp3                       # a different client → a different antigen


# ─── #4 Single source of the tempo logic ──────────────────────────────────────

def test_recent_distinct_endpoints_single_source():
    import time
    proxy._actor_history.clear()
    now = time.time()
    for ep in ("/a", "/b", "/c"):
        proxy._record_request("z", "GET", ep, now)
    assert len(proxy._recent_distinct_endpoints("z", now)) == 3
    assert proxy._nonhuman_tempo("z", now) is False
    proxy._record_request("z", "GET", "/d", now)
    assert proxy._nonhuman_tempo("z", now) is True   # 4th different → bot tempo


# ─── #3 Response inspection (anti-exfiltration) ───────────────────────────────

def test_exfil_verdict_flags_large_dump():
    big = proxy.EXFIL_SOFT_BYTES + 1
    assert proxy._exfil_verdict("/helios/x/voters/", "GET", big) == "flag"
    assert proxy._exfil_verdict("/helios/x/ballots/", "GET", big) == "flag"


def test_exfil_verdict_ignores_normal_and_nonlist():
    assert proxy._exfil_verdict("/helios/x/voters/", "GET", 100) == ""     # small
    assert proxy._exfil_verdict("/helios/x/view", "GET", 10**7) == ""      # not a list endpoint
    assert proxy._exfil_verdict("/helios/x/voters/", "POST", 10**7) == ""  # not GET


def test_exfil_verdict_hard_block_when_enabled(monkeypatch):
    monkeypatch.setattr(proxy, "EXFIL_HARD_BYTES", 1000)
    assert proxy._exfil_verdict("/helios/x/voters/", "GET", 2000) == "block"


# ─── #6 Circuit breaker for session validation ────────────────────────────────

def test_circuit_breaker_opens_after_failures():
    import time
    now = time.time()
    proxy._helios_cb["fails"] = 0
    proxy._helios_cb["open_until"] = 0.0
    assert proxy._cb_is_open(now) is False
    for _ in range(proxy.HELIOS_CB_FAIL_THRESHOLD):
        proxy._cb_record_fail(now)
    assert proxy._cb_is_open(now) is True            # opened after N failures
    # outside the window — closed again
    assert proxy._cb_is_open(now + proxy.HELIOS_CB_OPEN_SEC + 1) is False


def test_circuit_breaker_success_resets_fails():
    import time
    now = time.time()
    proxy._helios_cb["fails"] = 0
    proxy._helios_cb["open_until"] = 0.0
    proxy._cb_record_fail(now)
    proxy._cb_record_fail(now)
    proxy._cb_record_success()
    assert proxy._helios_cb["fails"] == 0            # success reset the counter
    proxy._cb_record_fail(now)                        # not the threshold yet
    assert proxy._cb_is_open(now) is False


def test_validate_session_short_circuits_when_breaker_open():
    import time
    now = time.time()
    # open the circuit → validation must return False WITHOUT calling Helios
    proxy._helios_cb["open_until"] = now + 100
    proxy._session_cache.clear()
    assert proxy._validate_session("somesid", "/helios/elections/abc/view") is False
    proxy._helios_cb["open_until"] = 0.0              # clean up after ourselves


# ─── #8 Prometheus endpoint ───────────────────────────────────────────────────

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
    assert "exfil_suspected" in body          # consistency with Prometheus/metrics


# ─── Hygiene: verbose blocks (demo vs prod) ───────────────────────────────────

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
    assert "attack_class" not in body          # in prod we do not hint WHAT triggered
    assert "reason" not in body
    assert body["error"].startswith("Forbidden")   # a minimal 403 remains


# ─── The body backstop scans DEEPER than the AI's 2KB preview ─────────────────

def test_backstop_catches_payload_beyond_ai_preview(monkeypatch):
    # a payload at an offset >AI_BODY_PREVIEW (2KB) in the BODY — the AI preview does not see it,
    # but the backstop reads up to BACKSTOP_BODY_BYTES and catches it deterministically.
    monkeypatch.setattr(proxy.analyst, "analyze",
                        lambda *a, **k: {"verdict": "ALLOW", "attack_class": None,
                                         "confidence": 0.0, "reasoning": "", "from_cache": False})
    proxy._actor_history.clear()
    padding = "x" * 3000                         # > 2KB preview
    c = proxy.app.test_client()
    r = c.post("/helios/elections/abc/cast",
               headers={"X-Forwarded-For": "203.0.113.9"},
               data=f"note={padding} UNION SELECT secret")
    assert r.status_code == 403                  # caught despite the >2KB offset
