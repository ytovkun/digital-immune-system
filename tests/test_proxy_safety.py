"""
Unit tests for proxy forwarding safety (#9 path-escape / SSRF).
We test the _safe_backend_url logic without starting servers.
Run:  pytest tests/ -v
"""

import sys
from pathlib import Path

# importing immune_proxy requires env_loader + neighboring modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "immune_system"))

import immune_proxy as proxy


def test_normal_path_allowed():
    url = proxy._safe_backend_url("helios/elections/x/view")
    assert url is not None
    assert url.startswith(proxy.HELIOS_BACKEND)


def test_absolute_url_in_path_rejected():
    assert proxy._safe_backend_url("http://evil.com/x") is None


def test_protocol_relative_rejected():
    assert proxy._safe_backend_url("//evil.com/x") is None


def test_path_traversal_escape_rejected():
    assert proxy._safe_backend_url("../../../etc/passwd") is None


def test_backslash_rejected():
    assert proxy._safe_backend_url("helios\\..\\x") is None


def test_inner_dotdot_normalized_but_stays_on_backend():
    # ../ inside, but does not escape the root → stays on the backend host
    url = proxy._safe_backend_url("helios/elections/../x/view")
    if url is not None:
        from urllib.parse import urlsplit
        assert urlsplit(url).netloc == proxy._BACKEND_HOST


def test_default_model_single_source():
    # #10: the default model — a single source
    from ai_analyst import DEFAULT_MODEL, AIAnalyst
    import inspect
    sig = inspect.signature(AIAnalyst.__init__)
    assert sig.parameters["model"].default == DEFAULT_MODEL


def test_max_content_length_configured():
    # #3: protection against giant bodies — MAX_CONTENT_LENGTH is set
    assert proxy.app.config.get("MAX_CONTENT_LENGTH") is not None
    assert proxy.app.config["MAX_CONTENT_LENGTH"] > 0


def test_session_cookie_not_called_authenticated():
    # #2: a cookie is no longer fed to the AI as 'authenticated' (a spoofable signal)
    import ai_analyst
    src = (Path(__file__).resolve().parent.parent / "immune_system" / "ai_analyst.py").read_text()
    # the prompt must not claim "session authenticated" as a trusted signal
    assert "session_cookie_present" in src
    assert "НЕ валідована" in src


# ─── PII redaction in the log (ballot secrecy) ────────────────────────────────

def test_redact_pii_masks_voter_uuid():
    uuid = "c88cfaeb-abc0-4440-a165-a77cab2951f2"
    out = proxy._redact_pii(f"/helios/elections/{uuid}/voters/{uuid}/")
    assert "/voters/{voter}/" in out
    # election uuid (public) remains, voter uuid (PII) — masked
    assert f"/elections/{uuid}/" in out
    assert out.count(uuid) == 1


def test_redact_pii_masks_ballot_hash():
    out = proxy._redact_pii("/helios/elections/x/ballots/AbC123hashvalue")
    assert "/ballots/{ballot}" in out
    assert "AbC123hashvalue" not in out


def test_redact_pii_keeps_voters_list():
    # a voters list without an id — nothing to mask
    assert proxy._redact_pii("/helios/elections/x/voters/") == "/helios/elections/x/voters/"


def test_log_decision_redacts_path(tmp_path, monkeypatch):
    import json
    logf = tmp_path / "blocks.jsonl"
    monkeypatch.setattr(proxy, "BLOCKS_LOG", logf)
    proxy.log_decision({"path": "/helios/elections/e/voters/SECRETVOTERID/", "verdict": "BLOCK"})
    written = json.loads(logf.read_text().strip())
    assert "SECRETVOTERID" not in written["path"]
    assert "{voter}" in written["path"]


# ─── Log rotation (protection against unbounded growth) ───────────────────────

def test_rotate_when_oversized(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_LOG_BYTES", 100)
    logf = tmp_path / "blocks.jsonl"
    logf.write_text("x" * 200)   # over the limit
    proxy._rotate_if_needed(logf)
    assert (tmp_path / "blocks.jsonl.1").exists()   # rotated to .1
    assert not logf.exists()                         # original freed


def test_no_rotate_when_small(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_LOG_BYTES", 10_000)
    logf = tmp_path / "blocks.jsonl"
    logf.write_text("small")
    proxy._rotate_if_needed(logf)
    assert logf.exists()
    assert not (tmp_path / "blocks.jsonl.1").exists()


# ─── Security headers (voter browser protection) ──────────────────────────────

def test_security_headers_injected():
    c = proxy.app.test_client()
    r = c.get("/__immune__/stats")
    assert r.headers.get("X-Frame-Options") == "DENY"            # anti-clickjacking
    assert r.headers.get("X-Content-Type-Options") == "nosniff"  # anti-MIME-sniff
    assert "Content-Security-Policy" in r.headers                # anti-XSS/CDN-inject
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers.get("Referrer-Policy") == "no-referrer"


# ─── Timestamp coarsening (privacy: against timing-deanon) ────────────────────

def test_coarsen_timestamps_rounds_to_hour():
    out = proxy._coarsen_timestamps(b'{"cast_at": "2026-06-09T09:38:42.123456"}')
    assert b"2026-06-09T09:00:00" in out
    assert b"09:38:42" not in out


def test_coarsen_timestamps_safe_on_binary():
    raw = b"\xff\xfe\x00garbage"
    assert proxy._coarsen_timestamps(raw) == raw   # does not fail on non-UTF8


# ─── threat_score in the header (for ROC in the benchmark) ────────────────────

def test_url_encoded_payload_blocked_after_decode():
    # a %-encoded SQLi/SSTI must be caught (the proxy decodes the path for detection)
    c = proxy.app.test_client()
    assert c.get("/helios/elections/x/voters/?q=1%20UNION%20SELECT%20pwd").status_code == 403
    assert c.get("/helios/elections/x/view?n=%7B%7B7%2A7%7D%7D").status_code == 403


def test_immune_score_header_on_block():
    # L1 block of devlogin → 403 with X-Immune-Score=1.0 (no network needed)
    c = proxy.app.test_client()
    r = c.post("/auth/devlogin/login")
    assert r.status_code == 403
    assert r.headers.get("X-Immune-Score") == "1.0"


# ─── Behavioral trajectory (context for the AI) ───────────────────────────────

def test_endpoint_label_masks_uuid():
    lbl = proxy._endpoint_label("/helios/elections/c88cfaeb-abc0-4440-a165-a77cab2951f2/cast")
    assert "{id}" in lbl and "c88cfaeb" not in lbl


def test_trajectory_records_sequence_and_masks():
    import time
    proxy._actor_history.clear()
    now = time.time()
    u = "c88cfaeb-abc0-4440-a165-a77cab2951f2"
    proxy._record_request("actorA", "GET", f"/helios/elections/{u}/view", now - 3)
    proxy._record_request("actorA", "GET", f"/helios/elections/{u}/voters/", now - 2)
    proxy._record_request("actorA", "POST", f"/helios/elections/{u}/cast", now)
    summ = proxy._trajectory_summary("actorA", now)
    assert "{id}" in summ                      # UUID masked (no PII)
    assert "/voters/" in summ and "/cast" in summ
    assert "3 кроків" in summ                  # the sequence is summarized


def test_trajectory_single_request_has_no_history():
    import time
    proxy._actor_history.clear()
    now = time.time()
    proxy._record_request("solo", "GET", "/helios/x/view", now)
    assert "перший запит" in proxy._trajectory_summary("solo", now)


def test_nonhuman_tempo_detection():
    import time
    proxy._actor_history.clear()
    now = time.time()
    for ep in ("a", "b", "c"):                      # 3 different endpoints
        proxy._record_request("xx", "GET", f"/{ep}", now)
    assert proxy._nonhuman_tempo("xx", now) is False
    proxy._record_request("xx", "GET", "/d", now)   # 4th different → bot tempo
    assert proxy._nonhuman_tempo("xx", now) is True


def test_nonhuman_tempo_escalates_to_ai(monkeypatch):
    # Non-human tempo before a voter action → NOT a hard block, but ESCALATION to the AI (INSPECT).
    # In e-voting a false block = disenfranchisement, so the AI decides, seeing the
    # trajectory. We verify: the AI is CALLED with the nonhuman_tempo=True flag.
    import time
    seen = {}

    def fake_analyze(method, path, headers, body, behavior):
        seen.update(behavior)
        return {"verdict": "BLOCK", "attack_class": "election_integrity_apt",
                "confidence": 0.95, "reasoning": "recon-sweep→login", "from_cache": False}

    monkeypatch.setattr(proxy.analyst, "analyze", fake_analyze)
    proxy._actor_history.clear()
    now = time.time()
    for dt, ep in [(1.5, "view"), (1.0, "voters"), (0.5, "ballots"), (0.2, "trustees")]:
        proxy._record_request("9.9.9.9", "GET", f"/helios/x/{ep}", now - dt)
    c = proxy.app.test_client()
    r = c.post("/auth/password/login", headers={"X-Forwarded-For": "9.9.9.9"},
               data="voter_id=v&password=x")
    assert seen.get("nonhuman_tempo") is True        # tempo passed to the AI as a signal
    assert r.status_code == 403                       # the AI decided to block recon→login


def test_apt_trajectory_shows_recon_then_action():
    # multi-step APT: fast recon + action → the AI sees the FULL sequence
    import time
    proxy._actor_history.clear()
    now = time.time()
    u = "c88cfaeb-abc0-4440-a165-a77cab2951f2"
    for dt, ep in [(0.4, "view"), (0.3, "voters/"), (0.2, "ballots/"), (0.1, "trustees/")]:
        proxy._record_request("apt", "GET", f"/helios/elections/{u}/{ep}", now - dt)
    proxy._record_request("apt", "POST", "/auth/password/login", now)   # final action
    summ = proxy._trajectory_summary("apt", now)
    for ep in ("view", "voters/", "ballots/", "trustees/"):
        assert ep in summ                       # all recon in the trajectory
    assert "password/login" in summ             # + the final action
    assert "5 кроків" in summ
    assert "НЕЛЮДСЬКИЙ ТЕМП" in summ            # explicit deterministic bot signal


# ─── Authorization of /__immune__/stats ───────────────────────────────────────

def test_stats_token_enforced_when_set(monkeypatch):
    monkeypatch.setattr(proxy, "STATS_TOKEN", "secret")
    c = proxy.app.test_client()
    assert c.get("/__immune__/stats").status_code == 403
    assert c.get("/__immune__/stats?token=secret").status_code == 200
    assert c.get("/__immune__/stats",
                 headers={"X-Stats-Token": "secret"}).status_code == 200
