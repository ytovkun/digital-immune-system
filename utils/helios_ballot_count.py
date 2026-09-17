"""
Ballot counter: an independent measure of the voting state before/after a run.
Digital immune system — utils/helios_ballot_count.py

Counts cast ballots from Helios' ballots/ JSON API — an independent, DB-agnostic
ground truth. Purpose: give the baseline an HONEST outcome metric. Instead of only
"attack got HTTP 200", we show whether the ballot count actually changed (ballot
stuffing / double vote) or stayed put.

Our election is PRIVATE, so the voters/ and ballots/ JSON APIs are gated by
@election_view: they return JSON only after an election-scoped voter login
(POST voter_id/password to .../password_voter_login). An anonymous GET just gets
the "Log In to View Election" HTML. So we log in as a real voter (creds from
config.local.json) first, then read ballots/. ballot_list returns the LAST cast
vote per voter who has voted → len = number of voters who cast a ballot.

Usage (a campaign wraps the baseline between two calls):
  python utils/helios_ballot_count.py --label before   # snapshot before the attacks
  python utils/helios_ballot_count.py --label after     # snapshot after the attacks
  python utils/helios_ballot_count.py --diff            # before vs after → delta

Target: RAW Helios :8001 by default (the source of truth, no defense in the path).
Override: env BALLOT_TARGET=http://host:port.
Writes reports/ballots/ballots_{label}.json (+ prints a one-line summary).
"""

import os
import re
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import requests
from env_loader import load_config

_cfg = load_config()
_helios = _cfg.get("helios", {})
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
OUT_DIR = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports") / "ballots"
BASE_URL = os.environ.get("BALLOT_TARGET", _helios.get("base_url", "http://localhost:8001"))
UUID = _helios.get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")
BALLOTS_URL = f"{BASE_URL}/helios/elections/{UUID}/ballots/?limit=500"
VOTERS_URL = f"{BASE_URL}/helios/elections/{UUID}/voters/?limit=500"
LOGIN_URL = f"{BASE_URL}/helios/elections/{UUID}/password_voter_login"

_CSRF_RE = re.compile(r'csrfmiddlewaretoken["\']?\s*value=["\']([^"\']+)')


def _voter_login(session: requests.Session) -> str:
    """Log in as a real voter for THIS (private) election so ballots/ returns JSON.

    Returns "" on success, or a human-readable reason on failure.
    """
    voters = _helios.get("voters", {})
    creds = [(vid, pwd) for vid, pwd in voters.items()
             if pwd and "set-in-config" not in str(pwd)]
    if not creds:
        return "no voter credentials in config.local.json"
    voter_id, password = creds[0]
    try:
        tok_m = _CSRF_RE.search(session.get(LOGIN_URL, timeout=10).text)
        # election-scoped login: sets session['CURRENT_VOTER_ID'] → view access.
        # Do NOT follow the redirect — it points at SECURE_URL_HOST (the proxy).
        session.post(LOGIN_URL, timeout=10, allow_redirects=False,
                     headers={"Referer": LOGIN_URL},
                     data={"voter_id": voter_id, "password": password,
                           "csrfmiddlewaretoken": tok_m.group(1) if tok_m else "",
                           "return_url": ""})
    except requests.exceptions.RequestException as e:
        return f"login failed: {e}"
    return ""


def count_ballots() -> dict:
    """Count cast ballots from the ballots/ JSON API (after an election-scoped login)."""
    result = {"target": BASE_URL, "voted_count": None, "voters_total": None,
              "distinct_voters": None, "raw_status": None, "source": None}
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    login_err = _voter_login(session)
    if login_err:
        result["error"] = login_err
        return result
    try:
        r = session.get(BALLOTS_URL, timeout=10, allow_redirects=False)
        result["raw_status"] = r.status_code
        try:
            ballots = r.json()
        except ValueError:
            result["source"] = "html"     # still the login page → not authorized
            result["error"] = "ballots/ did not return JSON (voter login rejected?)"
            return result
        if isinstance(ballots, list):
            result["source"] = "json"
            result["voted_count"] = len(ballots)   # one entry per voter who cast
            result["distinct_voters"] = len({b.get("voter_uuid") for b in ballots})
            # per-voter vote_hash — the ONLY reliable signal for a vote CHANGE /
            # re-cast by the same voter (count stays equal, but the hash flips).
            result["hashes"] = {b.get("voter_uuid"): b.get("vote_hash")
                                for b in ballots if b.get("voter_uuid")}
        # voters/ roster size — for the "X of N voters cast" denominator
        try:
            roster = session.get(VOTERS_URL, timeout=10, allow_redirects=False).json()
            if isinstance(roster, list):
                result["voters_total"] = len(roster)
        except (ValueError, requests.exceptions.RequestException):
            pass
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    return result


def _snapshot_path(label: str) -> Path:
    return OUT_DIR / f"ballots_{label}.json"


def _load(label: str):
    p = _snapshot_path(label)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def do_diff():
    before, after = _load("before"), _load("after")
    if not before or not after:
        print("  ⚠️  Немає обох знімків (before/after). Спершу зроби обидва виміри.")
        return 1
    b, a = before.get("voted_count"), after.get("voted_count")
    print("=" * 60)
    print("  📊 БЮЛЕТЕНІ: before vs after")
    print("=" * 60)
    print(f"  До атак:    {b}")
    print(f"  Після атак: {a}")
    if isinstance(b, int) and isinstance(a, int):
        delta = a - b
        print(f"  Δ (приріст): {delta:+d}")
        if delta > 0:
            print("  🔴 Кількість бюлетенів ЗРОСЛА — можливе накидання/подвійний голос.")
        else:
            print("  ✅ Кількість бюлетенів НЕ зросла — накидання не зафіксовано.")
    else:
        print("  ⚠️  Лічильник недоступний (не-JSON список?) — порівняння неможливе.")

    # vote_hash comparison — catches vote CHANGE / re-cast (same voter, count equal
    # but hash flips). This is the ground truth for integrity harm, not the count.
    hb, ha = before.get("hashes") or {}, after.get("hashes") or {}
    if hb or ha:
        changed = [v for v in hb if v in ha and hb[v] != ha[v]]
        added   = [v for v in ha if v not in hb]
        removed = [v for v in hb if v not in ha]
        print("  ── vote_hash ──")
        if not (changed or added or removed):
            print("  ✅ Жоден vote_hash не змінився — підміни/зміни голосу НЕ зафіксовано.")
        else:
            if changed:
                print(f"  🔴 ЗМІНЕНО голос у {len(changed)} виборця(ів) — підміна голосу!")
                for v in changed:
                    print(f"       {v}: {hb[v]} → {ha[v]}")
            if added:
                print(f"  🟡 Нові голоси: {len(added)} (voter_uuid: {', '.join(added)})")
            if removed:
                print(f"  🟠 Зникли голоси: {len(removed)}")
    print("=" * 60)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Count Helios ballots (public list).")
    ap.add_argument("--label", help="snapshot name, e.g. before / after")
    ap.add_argument("--diff", action="store_true", help="compare before vs after")
    args = ap.parse_args()

    if args.diff:
        sys.exit(do_diff())

    snap = count_ballots()
    snap["label"] = args.label or "adhoc"
    snap["timestamp"] = datetime.now(timezone.utc).isoformat()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = _snapshot_path(snap["label"])
    out.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")

    vc = snap.get("voted_count")
    vt = snap.get("voters_total")
    where = f"{vc}/{vt}" if isinstance(vt, int) else f"{vc}"
    print(f"  [{snap['label']}] проголосувало: {where}  "
          f"(HTTP {snap.get('raw_status')}, {snap.get('source')})  → {out.name}")
    if vc is None:
        print(f"  ⚠️  Лічильник недоступний: {snap.get('error', 'невідома причина')}")
        print("     (перевір, що Helios працює і в config.local.json є паролі виборців)")


if __name__ == "__main__":
    main()
