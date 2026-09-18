"""
Module 3: Red Team Agent v2
Digital immune system — red_team_agent.py

Executes JSON attack scenarios with real HTTP requests to Helios.
Key v2 improvements:
  - Context between steps: context_extract pulls data from responses
  - LOCAL/NETWORK steps: honest evaluation (not always success=True)
  - Success is determined by endpoint specifics, not only status_code
  - Voter-vector: logs the human impact separately
  - Detailed analysis of Helios responses (JSON + HTML parsing)
"""

import json
import os
import re
import sys
import time
import itertools
import logging
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin
from typing import Optional


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config


_cfg = load_config()
PROJECT_ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent))

HELIOS_BASE_URL = os.environ.get("HELIOS_BASE_URL",
    _cfg.get("helios", {}).get("base_url", "http://localhost:8001"))
# Report isolation by run mode: baseline (against raw Helios) vs defended
# (through the DIS proxy). Lets us keep "without defense" and "with defense"
# separate and compare. Empty subdir → old behavior (reports/attacks/).
REPORT_SUBDIR = os.environ.get("REDTEAM_REPORT_SUBDIR", "")
DEFENDED_RUN  = os.environ.get("REDTEAM_DEFENDED", "").lower() in ("1", "true", "yes")
ELECTION_UUID   = _cfg.get("helios", {}).get("election_uuid", "07712c60-5b5b-4671-9ede-035cda82736a")
SCENARIOS_DIR   = str(PROJECT_ROOT / _cfg.get("paths", {}).get("scenarios_dir", "scenarios"))
REPORTS_DIR     = str(PROJECT_ROOT / _cfg.get("paths", {}).get("reports_dir", "reports"))
LOGS_DIR        = str(PROJECT_ROOT / _cfg.get("paths", {}).get("logs_dir", "logs"))
STEP_DELAY      = _cfg.get("run", {}).get("step_delay_sec", 0.3)
HTTP_TIMEOUT    = _cfg.get("run", {}).get("http_timeout_sec", 10)

# Neutral browser UA (env-overridable). MUST NOT self-identify as the red-team
# harness: a "RedTeamAgent" UA leaks into the L2 prompt and lets the model block by
# the marker rather than by attack semantics (contaminates the campaign — reviewer #3).
REDTEAM_UA = os.environ.get(
    "REDTEAM_UA",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

# Distinct source IP per scenario (via X-Forwarded-For): each scenario is a DIFFERENT
# attacker, so rate/tempo/L2-budget/trajectory do NOT accumulate across scenarios
# (that accumulation was a stand artifact, not real defense strength). A fixed
# REDTEAM_XFF overrides this (all scenarios from one IP) if ever needed.
_scenario_ip_counter = itertools.count(11)


def _next_scenario_ip() -> str:
    return os.environ.get("REDTEAM_XFF") or f"198.51.100.{next(_scenario_ip_counter) % 250 + 1}"


# ─── B-full: valid-ballot bridge (stolen-credential vote manipulation, §5.8) ──
# A BUILD_BALLOT step crafts a cryptographically valid Helios ballot by invoking
# exploits/build_valid_ballot.py under the HELIOS venv (it needs Django + helios
# models, which the DIS venv does not have). The ballot JSON is stored in context
# so a subsequent POST /cast can submit it as {encrypted_vote}.
HELIOS_HOME = os.path.expanduser(os.environ.get("HELIOS_HOME", "~/helios-server"))
HELIOS_PY   = os.environ.get("HELIOS_PY", os.path.join(HELIOS_HOME, ".venv/bin/python"))
_BALLOT_BUILDER = str(PROJECT_ROOT / "exploits" / "build_valid_ballot.py")


def build_valid_ballot(election_uuid: str, choice: int = 0, question: int = 0) -> Optional[str]:
    """Return a verified ballot JSON string, or None if the bridge is unavailable
    (e.g. HELIOS venv/checkout missing) so the scenario degrades gracefully."""
    if not (os.path.exists(HELIOS_PY) and os.path.exists(_BALLOT_BUILDER)):
        logging.warning("build_valid_ballot: HELIOS_PY or builder missing (%s) — "
                        "skipping (set HELIOS_HOME/HELIOS_PY)", HELIOS_PY)
        return None
    try:
        env = dict(os.environ, HELIOS_HOME=HELIOS_HOME)
        out = subprocess.run(
            [HELIOS_PY, _BALLOT_BUILDER, "--uuid", election_uuid,
             "--choice", str(choice), "--question", str(question)],
            capture_output=True, text=True, timeout=60, env=env)
        if out.returncode != 0 or not out.stdout.strip():
            logging.warning("build_valid_ballot failed (rc=%s): %s",
                            out.returncode, out.stderr.strip()[-300:])
            return None
        return out.stdout.strip()
    except (subprocess.SubprocessError, OSError) as e:
        logging.warning("build_valid_ballot subprocess error: %s", e)
        return None

# Neutralize leftover LLM context-placeholders like "<from step1>" / "<csrftoken step3>"
# (unresolved cross-step references the generator emitted) so they do not leak into the
# request or the L2 prompt. Targeted at angle-brackets containing "stepN" — never matches
# a real XSS payload like "<script>" or "<svg onload=…>".
_CONTEXT_PLACEHOLDER_RE = re.compile(r"<[^>]*step\s*\d[^>]*>", re.I)

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{LOGS_DIR}/red_team.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("red_team")


# ─── Structured log ─────────────────────────────────────────────────────────────

MAX_LOG_BYTES = 50 * 1024 * 1024   # ротація attack_events.jsonl за розміром
LOG_BACKUPS   = 5


def _rotate_if_needed(path: Path):
    """Rotate the log by size (file → file.1 → … → file.N) against unbounded growth."""
    try:
        if not (path.exists() and path.stat().st_size >= MAX_LOG_BYTES):
            return
        oldest = path.with_name(path.name + f".{LOG_BACKUPS}")
        if oldest.exists():
            oldest.unlink()
        for i in range(LOG_BACKUPS - 1, 0, -1):
            src = path.with_name(path.name + f".{i}")
            if src.exists():
                src.rename(path.with_name(path.name + f".{i + 1}"))
        path.rename(path.with_name(path.name + ".1"))
    except OSError as e:
        log.warning("Ротація журналу %s не вдалася: %s", path.name, e)


def log_event(event_type: str, details: dict, severity: str = "INFO"):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "severity": severity,
        "details": details,
    }
    log.info(json.dumps(entry, ensure_ascii=False))
    events_path = Path(LOGS_DIR) / "attack_events.jsonl"
    _rotate_if_needed(events_path)
    with open(events_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ─── Extracting context from a response ───────────────────────────────────────

def extract_from_response(resp: requests.Response, extract_spec: dict, context: dict):
    """
    Extract values from the response according to the context_extract spec.
    Supports: json_key, regex, cookie_name, header_name.
    """
    # NOTE: do NOT early-return on an empty extract_spec — the automatic token
    # extraction below (csrfmiddlewaretoken, Helios csrf_token, sessionid) must run
    # on every response so later steps have the tokens even without an explicit spec.
    extract_spec = extract_spec or {}

    extracted = {}
    text = resp.text

    # Try to parse JSON
    resp_json = None
    try:
        resp_json = resp.json()
    except ValueError:
        pass   # response is not JSON — that's fine (HTML/redirect), not an error

    for key, spec in extract_spec.items():
        val = None

        if isinstance(spec, str):
            # cookie
            # Normalize the non-standard prefixes that Claude generates
            # cookie_name: → cookie:
            if spec.startswith("cookie_name:"):
                spec = "cookie:" + spec[12:]
            # xpath: → ignore (unsupported, return None)
            elif spec.startswith(("xpath:", "static:", "local_var:", "local_array:",
                                   "smtp", "file:", "stdout:", "smtp_", "browser ",
                                   "DOM:", "window.", "http_status:")):
                val = None
            # JSONPath $[*].field → convert to json_key
            elif spec.startswith("$"):
                clean = re.sub(r'[\$\[\]\*]', '', spec).strip(". ")
                spec = "json_key:" + clean

            if val is None and spec.startswith("cookie:"):
                cookie_name = spec[7:].strip()
                val = resp.cookies.get(cookie_name)
                if not val:
                    set_cookie = resp.headers.get("Set-Cookie", "")
                    m = re.search(rf"{cookie_name}=([^;]+)", set_cookie)
                    val = m.group(1) if m else None

            # header
            elif spec.startswith("header:"):
                val = resp.headers.get(spec[7:].strip())

            # regex
            elif spec.startswith("regex:"):
                pattern = spec[6:].strip()
                try:
                    m = re.search(pattern, text, re.DOTALL)
                    if m:
                        val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                except re.error:
                    val = None

            # json / json_key — support both prefixes
            elif spec.startswith(("json:", "json_key:")) and resp_json:
                raw_path = spec.split(":", 1)[1].strip()
                clean_path = re.sub(r'\[.*?\]', '', raw_path).strip(" .")
                parts = [p for p in clean_path.split(".") if p]
                cur = resp_json
                for part in parts:
                    if isinstance(cur, dict):
                        cur = cur.get(part)
                    elif isinstance(cur, list):
                        cur = cur[0].get(part) if cur and isinstance(cur[0], dict) else None
                    else:
                        cur = None
                    if cur is None:
                        break
                val = str(cur) if cur is not None else None

            # simple regex fallback — only if val is not set yet
            elif val is None and spec and not spec.startswith(
                    ("cookie:", "header:", "regex:", "json:", "json_key:")):
                try:
                    m = re.search(spec, text, re.DOTALL)
                    if m:
                        val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                except re.error:
                    val = None

        if val is not None:
            extracted[key] = val
            context[key] = val

    # Automatic: Django CSRF token (csrfmiddlewaretoken)
    if "csrf_token" not in context:
        m = re.search(r'csrfmiddlewaretoken["\s]+value=["\']([^"\']+)', text)
        if m:
            context["csrf_token"] = m.group(1)
            extracted["csrf_token"] = m.group(1)

    # Automatic: Helios' OWN custom CSRF field (name="csrf_token"), distinct from
    # Django's csrfmiddlewaretoken. cast_confirm's check_csrf() compares POST
    # 'csrf_token' to session['csrf_token'] — sending the Django one raises 500.
    m2 = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)', text)
    if m2:
        context["helios_csrf"] = m2.group(1)
        extracted["helios_csrf"] = m2.group(1)

    # Automatic: sessionid
    sid = resp.cookies.get("sessionid")
    if sid:
        context["session_id"] = sid
        extracted["session_id"] = sid

    # Automatic: the first voter UUID from the JSON response
    if resp_json and isinstance(resp_json, list) and len(resp_json) > 0:
        first = resp_json[0]
        if isinstance(first, dict):
            for field in ("uuid", "voter_uuid", "id"):
                if field in first:
                    context.setdefault("voter_uuid", str(first[field]))
                    extracted.setdefault("voter_uuid", str(first[field]))
                    break
            # Automatic: vote_hash and cast_at from the ballot board
            if "vote_hash" in first:
                context.setdefault("vote_hash", str(first["vote_hash"]))
                extracted.setdefault("vote_hash", str(first["vote_hash"]))
            if "cast_at" in first:
                context.setdefault("cast_at", str(first["cast_at"]))
                extracted.setdefault("cast_at", str(first["cast_at"]))

    return extracted


# ─── Substituting context into strings ────────────────────────────────────────

def interpolate(value, context: dict):
    if not isinstance(value, str):
        return value
    for k, v in context.items():
        if isinstance(v, str):
            value = value.replace(f"{{{k}}}", v)
    # drop unresolved cross-step placeholders ("<from step1>") so they neither hit
    # the wire nor the L2 prompt; XSS payloads (no "stepN") are untouched
    value = _CONTEXT_PLACEHOLDER_RE.sub("", value)
    return value


def interpolate_dict(d, context: dict):
    if isinstance(d, dict):
        return {k: interpolate_dict(v, context) for k, v in d.items()}
    if isinstance(d, list):
        return [interpolate_dict(i, context) for i in d]
    if isinstance(d, str):
        return interpolate(d, context)
    return d


# ─── Step success evaluation ──────────────────────────────────────────────────

def evaluate_step_success(
    method: str,
    endpoint: Optional[str],
    status_code: Optional[int],
    response_text: str,
    expected_result: str,
    extracted: dict,
) -> tuple[bool, str]:
    """
    Returns (success: bool, reason: str).
    Logic stricter than 'status in [200,302]'.
    """
    # LOCAL / NETWORK steps — evaluate by extracted or mark as SIMULATED
    if method in ("LOCAL", "NETWORK"):
        has_artifacts = len(extracted) > 0
        reason = "SIMULATED — artifacts extracted" if has_artifacts else "SIMULATED — no artifacts (conceptual step)"
        return True, reason  # LOCAL steps always pass as a simulation — but we mark it

    if status_code is None:
        return False, "no response (connection error)"

    if status_code >= 500:
        return False, f"server error {status_code}"

    if status_code == 403:
        return False, "403 Forbidden — access denied"

    if status_code == 401:
        return False, "401 Unauthorized"

    if status_code == 404:
        return False, "404 Not Found"

    # /cast with MultiValueDictKeyError — a real Helios error when encrypted_vote is missing
    if "MultiValueDictKeyError" in response_text:
        return False, "Helios: missing encrypted_vote field in POST body"

    # Successful response
    if status_code in (200, 201, 302):
        # Check whether we got useful content
        if status_code == 200 and len(response_text.strip()) < 10:
            return False, "200 but empty response"
        return True, f"HTTP {status_code} OK"

    return False, f"HTTP {status_code} — unexpected"


# ─── Executing a single step ──────────────────────────────────────────────────

def execute_step(session: requests.Session, step: dict, context: dict) -> dict:
    method = (step.get("method") or "GET").upper()
    endpoint = step.get("endpoint")
    payload = step.get("payload", {}) or {}
    action = step.get("action", "")
    step_num = step.get("step", 0)
    phase = step.get("phase", "")
    extract_spec = step.get("context_extract", {}) or {}
    attacker_note = step.get("attacker_note", "")

    # Substitute context into the endpoint and payload
    if endpoint:
        endpoint = interpolate(endpoint, context)
    payload = interpolate_dict(payload, context)

    result = {
        "step": step_num,
        "phase": phase,
        "action": action,
        "method": method,
        "endpoint": endpoint,
        "attacker_note": attacker_note,
        "status_code": None,
        "success": False,
        "success_reason": "",
        "is_simulated": method in ("LOCAL", "NETWORK"),
        "response_preview": "",
        "response_length": 0,
        "extracted": {},
        "error": None,
    }

    # BUILD_BALLOT: craft a cryptographically valid ballot (no HTTP) and stash it in
    # context for a later POST /cast. This is the crux of the B-full stolen-credential
    # experiment — see build_valid_ballot() / exploits/build_valid_ballot.py.
    if method == "BUILD_BALLOT":
        store_as = step.get("store_as", "encrypted_vote")
        choice = int(step.get("choice", 0))
        question = int(step.get("question", 0))
        ballot = build_valid_ballot(context.get("election_uuid", ELECTION_UUID),
                                    choice=choice, question=question)
        extracted = {}
        if ballot:
            context[store_as] = ballot
            extracted[store_as] = f"<valid ballot {len(ballot)}B, choice={choice}>"
            result["success"], result["success_reason"] = True, "valid ballot crafted"
            result["response_preview"] = f"[BUILD_BALLOT] {len(ballot)}B verified ballot"
        else:
            result["success"], result["success_reason"] = False, "ballot bridge unavailable"
            result["response_preview"] = "[BUILD_BALLOT] bridge unavailable (HELIOS venv?)"
        result["extracted"] = extracted
        return result

    # LOCAL / NETWORK steps do not make HTTP requests
    if method in ("LOCAL", "NETWORK") or not endpoint:
        extracted = {}
        # If there is a payload with artifacts — log them
        if payload:
            result["response_preview"] = f"[{method}] Artifacts: {json.dumps(payload, ensure_ascii=False)[:200]}"
        result["success"], result["success_reason"] = evaluate_step_success(
            method, None, None, "", step.get("expected_result", ""), extracted
        )
        result["extracted"] = extracted
        return result

    url = endpoint if endpoint.startswith("http") else urljoin(HELIOS_BASE_URL, endpoint)

    try:
        headers = {}
        if context.get("csrf_token"):
            headers["X-CSRFToken"] = context["csrf_token"]

        # Per-step redirect control. Helios' election-scoped password_voter_login
        # sets the voter session on the 302 response, then redirects to SECURE_URL_HOST
        # (:8000). Following that in a baseline run (proxy down / different host) would
        # error out the step even though the auth cookie is already set. A login step
        # sets "follow_redirects": false to keep the session and skip the bounce.
        follow = step.get("follow_redirects", True)

        if method == "GET":
            resp = session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=follow)
        elif method == "POST":
            # Add CSRF to the form data if present
            if context.get("csrf_token") and "csrfmiddlewaretoken" not in payload:
                payload["csrfmiddlewaretoken"] = context["csrf_token"]
            resp = session.post(url, data=payload, timeout=HTTP_TIMEOUT,
                                allow_redirects=follow, headers=headers)
        else:
            resp = session.request(method, url, data=payload,
                                   timeout=HTTP_TIMEOUT, headers=headers,
                                   allow_redirects=follow)

        result["status_code"] = resp.status_code
        result["response_length"] = len(resp.text)
        result["response_preview"] = resp.text[:400]

        extracted = extract_from_response(resp, extract_spec, context)
        result["extracted"] = extracted

        result["success"], result["success_reason"] = evaluate_step_success(
            method, endpoint, resp.status_code,
            resp.text, step.get("expected_result", ""), extracted
        )

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"ConnectionError: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout (>10s)"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Executing a scenario ───────────────────────────────────────────────────────

def execute_scenario(scenario: dict, base_url: str = None) -> dict:
    attack_id = scenario.get("attack_id", "UNKNOWN")
    attack_class = scenario.get("attack_class", "unknown")
    vector = scenario.get("vector", "system")
    name = scenario.get("name", "Unknown Attack")
    steps = scenario.get("steps", [])
    complexity = scenario.get("complexity", "?")
    # an adaptive scenario has adaptation_mode (escalate/refine/bypass/simulate_only)
    adaptation_mode = scenario.get("adaptation_mode")
    is_adaptive = bool(adaptation_mode)

    vector_icon = "👤 VOTER" if vector == "voter" else "🖥  SYSTEM"
    print(f"\n{'='*65}")
    print(f"  RED TEAM AGENT v2 — {vector_icon}")
    print(f"  {name}")
    print(f"  STRIDE: {scenario.get('stride_category')} | "
          f"MITRE: {scenario.get('mitre_technique_id')} | "
          f"LINDDUN: {scenario.get('linddun_category')}")
    print(f"  Complexity: {complexity} | Steps: {len(steps)}")
    print(f"{'='*65}")

    log_event("ATTACK_START", {
        "attack_id": attack_id,
        "attack_class": attack_class,
        "vector": vector,
        "name": name,
        "stride": scenario.get("stride_category"),
        "mitre": scenario.get("mitre_technique_id"),
        "linddun": scenario.get("linddun_category"),
        "severity": scenario.get("severity"),
        "complexity": complexity,
        "steps_total": len(steps),
    }, severity="WARNING")

    session = requests.Session()
    # neutral UA + a distinct source IP per scenario (no self-marking, no cross-scenario
    # accumulation of rate/tempo/budget) — see REDTEAM_UA / _next_scenario_ip
    src_ip = _next_scenario_ip()
    session.headers.update({"User-Agent": REDTEAM_UA, "X-Forwarded-For": src_ip})

    # Base context — substituted into the {placeholders} of all steps
    voters  = _cfg.get("helios", {}).get("voters", {})
    v_uuids  = _cfg.get("helios", {}).get("voter_uuids", {})
    # Take the first not-yet-voted one as the target (voter4/voter5)
    target_login = list(voters.keys())[3] if len(voters) >= 4 else (list(voters.keys())[0] if voters else "voter1")
    target_pwd   = voters.get(target_login, "")
    target_uuid  = v_uuids.get(target_login, "")

    context = {
        "base_url":       base_url or HELIOS_BASE_URL,
        "election_uuid":  ELECTION_UUID,
        # Real credentials from config — substituted into step payloads
        "voter_id":       target_login,
        "voter_login_id": target_login,
        "password":       target_pwd,
        "voter_password": target_pwd,
        "voter_uuid":     target_uuid,
        # All voters separately
        **{f"voter{i+1}_login": login for i, login in enumerate(voters.keys())},
        **{f"voter{i+1}_password": pwd   for i, pwd   in enumerate(voters.values())},
        **{f"voter{i+1}_uuid":    uid    for i, uid    in enumerate(v_uuids.values())},
    }

    execution_log = []
    steps_real_success = 0  # real HTTP successes
    steps_simulated   = 0  # LOCAL/NETWORK steps
    steps_failed      = 0

    for step in steps:
        step_num     = step.get("step", 0)
        action      = step.get("action", "")
        phase       = step.get("phase", "")
        expected    = step.get("expected_result", "")
        attacker_note = step.get("attacker_note", "")

        # Multi-actor support in one scenario (e.g. B-full: the victim votes first to
        # establish ballot ownership, THEN the attacker overwrites from another source).
        # "new_session": drop cookies (a different actor). "x_forwarded_for": switch the
        # source IP from this step onward.
        if step.get("new_session"):
            session = requests.Session()
            session.headers.update({"User-Agent": REDTEAM_UA, "X-Forwarded-For": src_ip})
        if step.get("x_forwarded_for"):
            src_ip = interpolate(str(step["x_forwarded_for"]), context)
            session.headers["X-Forwarded-For"] = src_ip
            context["src_ip"] = src_ip

        print(f"\n  [{step_num:02d}] [{phase}] {action}")
        endpoint_display = step.get("endpoint") or "LOCAL"
        if endpoint_display and len(endpoint_display) > 60:
            endpoint_display = endpoint_display[:57] + "..."
        print(f"       {step.get('method','?')} {endpoint_display}")
        if attacker_note:
            print(f"       note: {attacker_note[:80]}")

        result = execute_step(session, step, context)

        # Print the result
        if result["is_simulated"]:
            print(f"       ~ SIMULATED: {result['success_reason']}")
            steps_simulated += 1
        elif result["success"]:
            print(f"       ✓ {result['success_reason']} | len={result['response_length']}")
            steps_real_success += 1
        else:
            err = result.get("error") or result["success_reason"]
            print(f"       ✗ FAILED: {err}")
            steps_failed += 1

        if result["extracted"]:
            keys = list(result["extracted"].keys())
            print(f"       → extracted: {keys}")

        log_event("ATTACK_STEP", {
            "attack_id": attack_id,
            "step": step_num,
            "phase": phase,
            "action": action,
            "result": result,
            "expected": expected,
        }, severity="WARNING" if result["success"] else "INFO")

        execution_log.append({
            "step": step_num,
            "phase": phase,
            "action": action,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        })

        time.sleep(STEP_DELAY)

    # ─── Result computation ─────────────────────────────────────────────────────

    # 1. Base http_success_rate (only real HTTP steps)
    real_steps = len(steps) - steps_simulated
    if real_steps > 0:
        http_success_rate = steps_real_success / real_steps * 100
    else:
        http_success_rate = 0.0

    # 2. Phase-weighted success rate
    # Critical phases weigh more — they determine whether the attack really worked
    PHASE_WEIGHTS = {
        "Reconnaissance": 0.3,
        "Weaponization":  0.0,   # always a simulation — not counted
        "Delivery":       0.5,
        "Exploitation":   2.0,
        "Installation":   1.5,
        "C2":             1.0,
        "Action":         2.0,
        "Impact":         2.0,
        "Collection":     0.5,
        "Defense Evasion": 0.3,
        "Exfiltration":   1.0,
        "Unknown":        0.5,
    }
    CRITICAL = {"Exploitation", "Installation", "C2", "Action", "Impact"}

    weighted_num = 0.0
    weighted_den = 0.0
    critical_real_ok   = 0
    critical_real_fail = 0
    critical_simulated = 0

    for entry in execution_log:
        r = entry["result"]
        phase = (entry.get("phase") or "Unknown").strip()
        w = PHASE_WEIGHTS.get(phase, 0.5)

        if r.get("is_simulated"):
            if phase in CRITICAL:
                critical_simulated += 1
            # simulated ones do not add to the weighted score
        else:
            weighted_den += w
            if r["success"]:
                weighted_num += w
                if phase in CRITICAL:
                    critical_real_ok += 1
            else:
                if phase in CRITICAL:
                    critical_real_fail += 1

    weighted_success_rate = (weighted_num / weighted_den * 100) if weighted_den > 0 else 0.0

    # 3. Executability — what share of critical steps was real HTTP (not simulation)
    critical_total = critical_real_ok + critical_real_fail + critical_simulated
    if critical_total > 0:
        critical_executability = (critical_real_ok + critical_real_fail) / critical_total * 100
    else:
        critical_executability = 0.0

    # 4. Verdict — an honest assessment
    if critical_total == 0:
        # no critical steps at all
        verdict = "RECON_ONLY"
    elif critical_simulated == critical_total:
        # all critical steps simulated
        verdict = "CONCEPTUAL"
    elif critical_real_ok == 0 and critical_real_fail > 0:
        verdict = "BLOCKED"
    elif weighted_success_rate >= 60 and critical_executability >= 50:
        verdict = "EXECUTED"
    elif weighted_success_rate >= 30:
        verdict = "PARTIAL"
    else:
        verdict = "BLOCKED"

    # Backward compatibility
    attack_successful = verdict == "EXECUTED"

    voter_impact = scenario.get("voter_impact", {})

    VERDICT_LABELS = {
        "EXECUTED":    "⚠  ВИКОНАНА",
        "PARTIAL":     "△  ЧАСТКОВА",
        "BLOCKED":     "✓  ЗАБЛОКОВАНА",
        "CONCEPTUAL":  "~  КОНЦЕПТУАЛЬНА (критичні фази симульовані)",
        "RECON_ONLY":  "~  ТІЛЬКИ РОЗВІДКА",
    }

    report = {
        "attack_id": attack_id,
        "attack_class": attack_class,
        "vector": vector,
        "name": name,
        "target_url": HELIOS_BASE_URL,   # куди били (для розрізнення baseline/defended)
        "defended": DEFENDED_RUN,        # True = прогін ЧЕРЕЗ ЦІС-проксі
        "complexity": complexity,
        "stride_category": scenario.get("stride_category"),
        "mitre_technique_id": scenario.get("mitre_technique_id"),
        "mitre_technique_name": scenario.get("mitre_technique_name"),
        "linddun_category": scenario.get("linddun_category"),
        "severity": scenario.get("severity"),
        "adaptation_mode": adaptation_mode,
        "adaptation_reason": scenario.get("adaptation_reason"),
        "executed_at": datetime.utcnow().isoformat(),
        "steps_total": len(steps),
        "steps_real_http": real_steps,
        "steps_simulated": steps_simulated,
        "steps_real_success": steps_real_success,
        "steps_failed": steps_failed,
        "http_success_rate": round(http_success_rate, 1),
        "weighted_success_rate": round(weighted_success_rate, 1),
        "critical_executability": round(critical_executability, 1),
        "critical_real_ok": critical_real_ok,
        "critical_real_fail": critical_real_fail,
        "critical_simulated": critical_simulated,
        "verdict": verdict,
        "attack_successful": attack_successful,
        "voter_impact": voter_impact,
        "helios_vulns_exploited": scenario.get("helios_vulns_exploited", []),
        "indicators_of_compromise": scenario.get("indicators_of_compromise", []),
        "detection_gaps": scenario.get("detection_gaps", []),
        "affected_cia": scenario.get("affected_cia", {}),
        "execution_log": execution_log,
        "context_at_end": {
            k: v for k, v in context.items()
            if k not in ("base_url",) and isinstance(v, str) and len(v) < 200
        },
    }

    attacks_dir = Path(REPORTS_DIR) / "attacks"
    if REPORT_SUBDIR:
        attacks_dir = attacks_dir / REPORT_SUBDIR   # baseline/ or defended/
    attacks_dir.mkdir(parents=True, exist_ok=True)
    # mark adaptive reports in the name (_adaptive_report.json) to distinguish them
    suffix = "_adaptive" if is_adaptive else ""
    report_file = str(attacks_dir / f"{attack_id}{suffix}_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    outcome = VERDICT_LABELS.get(verdict, verdict)
    print(f"\n{'='*65}")
    print(f"  VERDICT: {outcome}")
    print(f"  HTTP rate:    {steps_real_success}/{real_steps} ({http_success_rate:.0f}%)  [всі HTTP-кроки]")
    print(f"  Weighted:     {weighted_success_rate:.0f}%  [з урахуванням ваги фаз]")
    print(f"  Executability:{critical_executability:.0f}%  [критичні фази = реальний HTTP]")
    print(f"  Simulated:    {steps_simulated}/{len(steps)}  [LOCAL/NETWORK кроки]")
    if voter_impact:
        print(f"  Voter impact: {voter_impact.get('psychological', '')[:60]}")
    vulns = scenario.get("helios_vulns_exploited", [])
    if vulns:
        print(f"  Vulns used: {', '.join(vulns)}")
    print(f"  Звіт: {report_file}")
    print(f"{'='*65}\n")

    log_event("ATTACK_COMPLETE", {
        "attack_id": attack_id,
        "vector": vector,
        "verdict": verdict,
        "attack_successful": attack_successful,
        "http_success_rate": http_success_rate,
        "weighted_success_rate": weighted_success_rate,
        "steps_simulated": steps_simulated,
        "report_file": report_file,
    }, severity="CRITICAL" if attack_successful else "WARNING")

    return report


# ─── Running a group of scenarios ─────────────────────────────────────────────

def run_scenarios_from_dir(directory: str) -> list:
    p = Path(directory)
    if not p.exists():
        print(f"[-] Директорія не знайдена: {directory}")
        return []

    # Search recursively
    files = sorted(p.rglob("*.json"))
    # Exclude only reports
    files = [f for f in files if "report" not in f.name]

    if not files:
        print(f"[-] Сценаріїв не знайдено у {directory}")
        return []

    print(f"[*] Знайдено {len(files)} сценаріїв")
    reports = []
    for f in files:
        with open(f, encoding="utf-8") as fp:
            scenario = json.load(fp)
        report = execute_scenario(scenario)
        reports.append(report)
        time.sleep(0.5)

    return reports


def print_summary(reports: list):
    if not reports:
        return

    VERDICT_LABELS = {
        "EXECUTED":   "⚠ ",
        "PARTIAL":    "△ ",
        "BLOCKED":    "✓ ",
        "CONCEPTUAL": "~ ",
        "RECON_ONLY": "~ ",
    }

    print("\n" + "=" * 75)
    print("  ЗВЕДЕННЯ")
    print("=" * 75)
    print(f"  {'Атака':<42} {'HTTP':>5} {'Weighted':>9} {'Exec%':>6}  Verdict")
    print("  " + "-" * 71)

    for r in reports:
        icon = "👤" if r.get("vector") == "voter" else "🖥 "
        ac = r.get("attack_class", "?")[:40]
        http  = r.get("http_success_rate", 0)
        wrate = r.get("weighted_success_rate", 0)
        exec_val = r.get("critical_executability", 0)
        verdict = r.get("verdict", "?")
        vi = VERDICT_LABELS.get(verdict, "? ")
        print(f"  {icon} {ac:<42} {http:>4.0f}% {wrate:>8.0f}% {exec_val:>5.0f}%  {vi}{verdict}")

    print("  " + "-" * 71)
    all_v = [r.get("verdict") for r in reports]
    counts = {v: all_v.count(v) for v in set(all_v)}
    parts = [f"{VERDICT_LABELS.get(v,'')}{v}: {c}" for v, c in sorted(counts.items())]
    print("  " + " | ".join(parts))
    print("=" * 75)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 65)
    print("  RED TEAM AGENT v2 — Цифрова імунна система")
    print("  System attacks + Voter (human-targeted) attacks")
    print("=" * 65)

    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ("voter", "system"):
            subdir = f"{SCENARIOS_DIR}/{arg}"
            reports = run_scenarios_from_dir(subdir)
            print_summary(reports)

        elif arg == "adaptive":
            # Only adaptive scenarios (from all vectors)
            adaptive_files = sorted(Path(SCENARIOS_DIR).rglob("*_adaptive.json"))
            if not adaptive_files:
                print("[-] Адаптивних сценаріїв не знайдено. Спочатку запусти adaptive_generator.py")
                sys.exit(1)
            print(f"[*] Знайдено {len(adaptive_files)} адаптивних сценаріїв")
            reports = []
            for f in adaptive_files:
                with open(f, encoding="utf-8") as fp:
                    scenario = json.load(fp)
                report = execute_scenario(scenario)
                reports.append(report)
            print_summary(reports)

        elif arg in ("voter/adaptive", "system/adaptive"):
            # Adaptive scenarios of a specific vector
            vec = arg.split("/")[0]
            adaptive_files = sorted((Path(SCENARIOS_DIR) / vec / "adaptive").rglob("*_adaptive.json"))
            if not adaptive_files:
                print(f"[-] Адаптивних сценаріїв для '{vec}' не знайдено")
                sys.exit(1)
            print(f"[*] Знайдено {len(adaptive_files)} адаптивних сценаріїв [{vec}]")
            reports = []
            for f in adaptive_files:
                with open(f, encoding="utf-8") as fp:
                    scenario = json.load(fp)
                report = execute_scenario(scenario)
                reports.append(report)
            print_summary(reports)

        elif arg == "all":
            reports = run_scenarios_from_dir(SCENARIOS_DIR)
            print_summary(reports)

        elif arg.endswith(".json"):
            with open(arg, encoding="utf-8") as f:
                scenario = json.load(f)
            execute_scenario(scenario)

        else:
            # Search by attack_class
            matched = None
            for f in Path(SCENARIOS_DIR).rglob("*.json"):
                if "report" in f.name:
                    continue
                with open(f, encoding="utf-8") as fp:
                    s = json.load(fp)
                if s.get("attack_class") == arg:
                    matched = s
                    break
            if matched:
                execute_scenario(matched)
            else:
                print(f"[-] Сценарій '{arg}' не знайдено")
                sys.exit(1)
    else:
        reports = run_scenarios_from_dir(SCENARIOS_DIR)
        print_summary(reports)
