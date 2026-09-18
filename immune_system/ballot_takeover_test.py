"""
Ballot-takeover detection test — the immune system DETECTS a stolen-credential vote
change (B-full) via the ballot-ownership antibody.
Digital immune system — immune_system/ballot_takeover_test.py

Scenario (both through the DIS proxy :8000):
  1. The REAL voter casts their ballot from their own address (IP_A). The immune
     system binds that voter's ballot to IP_A as "self".
  2. An ATTACKER with the STOLEN password submits a cryptographically valid ballot
     for the SAME voter from a DIFFERENT address (IP_B) — a vote overwrite.
  → The proxy recognises a non-self actor overwriting the ballot and BLOCKS it
     (403, attack_class=vote_manipulation).

This is the honest answer to "can the immune system catch B-full?": not by the
payload (there is none) but by the ANOMALY of a ballot being overwritten by a
different source than the one that cast it.

Prerequisites: Helios :8001, immune_proxy :8000 (AI enabled). The ballot bridge
needs the HELIOS venv (see exploits/build_valid_ballot.py).
Run:  python immune_system/ballot_takeover_test.py
"""

import sys
import re
import json
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
from env_loader import load_config
from _sec_result import save_security_result
try:
    from red_team_agent import build_valid_ballot
except Exception:                                        # noqa: BLE001
    build_valid_ballot = None

_cfg = load_config()
PROXY = "http://localhost:8000"
UUID  = _cfg.get("helios", {}).get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")
VOTERS = _cfg.get("helios", {}).get("voters", {})
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

VICTIM_IP   = "203.0.113.77"    # the real voter's address (self)
ATTACKER_IP = "198.51.100.66"   # the attacker's address (non-self)


def _csrf(session, url):
    m = re.search(r'csrfmiddlewaretoken["\']?\s*value=["\']([^"\']+)', session.get(url).text)
    return m.group(1) if m else ""


def cast_full_flow(voter_id: str, password: str, src_ip: str, choice: int) -> dict:
    """Log in (election-scoped) and cast a VALID ballot through the proxy from src_ip.
    Returns {'blocked': bool, 'status': int, 'attack_class': str|None}."""
    s = requests.Session()
    s.headers.update({"User-Agent": BROWSER_UA, "X-Forwarded-For": src_ip})
    lu = f"{PROXY}/helios/elections/{UUID}/password_voter_login"
    tok = _csrf(s, lu)
    s.post(lu, data={"voter_id": voter_id, "password": password,
                     "csrfmiddlewaretoken": tok, "return_url": ""},
           headers={"Referer": lu}, allow_redirects=False, timeout=15)
    ballot = build_valid_ballot(UUID, choice=choice) if build_valid_ballot else \
        json.dumps({"answers": [{"choices": [choice]}]})
    vt = _csrf(s, f"{PROXY}/helios/elections/{UUID}/view")
    s.post(f"{PROXY}/helios/elections/{UUID}/cast",
           data={"encrypted_vote": ballot, "csrfmiddlewaretoken": vt},
           headers={"Referer": f"{PROXY}/helios/elections/{UUID}/vote"},
           allow_redirects=False, timeout=15)
    confirm = s.get(f"{PROXY}/helios/elections/{UUID}/cast_confirm")
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)', confirm.text)
    helios_csrf = m.group(1) if m else ""
    r = s.post(f"{PROXY}/helios/elections/{UUID}/cast_confirm",
               data={"csrf_token": helios_csrf},
               headers={"Referer": f"{PROXY}/helios/elections/{UUID}/cast_confirm"},
               allow_redirects=False, timeout=15)
    blocked = (r.status_code == 403 and "Immune" in r.text)
    ac = None
    if blocked:
        try:
            ac = r.json().get("attack_class")
        except ValueError:
            ac = "?"
    return {"blocked": blocked, "status": r.status_code, "attack_class": ac, "session": s}


VOTER_UUIDS = _cfg.get("helios", {}).get("voter_uuids", {})


def _read_vote_hash(voter_id: str, password: str, src_ip: str):
    """Read the victim's current vote_hash — ground truth for whether the vote was
    actually changed. Uses a FRESH election-scoped login and reads RAW Helios :8001
    directly (bypass the proxy: its exfil/coarsen handling can rewrite the ballots
    response, and a read is not part of the attack we are measuring)."""
    vu = VOTER_UUIDS.get(voter_id)
    base = "http://localhost:8001"
    s = requests.Session()
    s.headers.update({"User-Agent": BROWSER_UA, "X-Forwarded-For": src_ip})
    lu = f"{base}/helios/elections/{UUID}/password_voter_login"
    try:
        tok = _csrf(s, lu)
        s.post(lu, data={"voter_id": voter_id, "password": password,
                         "csrfmiddlewaretoken": tok, "return_url": ""},
               headers={"Referer": lu}, allow_redirects=False, timeout=15)
        r = s.get(f"{base}/helios/elections/{UUID}/ballots/?limit=500",
                  allow_redirects=False, timeout=10)
        for b in r.json():
            if b.get("voter_uuid") == vu:
                return b.get("vote_hash")
    except (ValueError, requests.exceptions.RequestException):
        pass
    return None


def main():
    print("=" * 78)
    print("  🧪 BALLOT-TAKEOVER — чи ловить ЦІС підміну голосу вкраденими даними")
    print("  Легіт-голос (self) → атака з іншого джерела (non-self) за того ж виборця")
    print("=" * 78)

    try:
        requests.get(PROXY, timeout=3)
    except requests.exceptions.ConnectionError:
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py (з ключем ШІ)")
        return
    if build_valid_ballot is None:
        print("\n  ⚠️  Міст валідного бюлетеня недоступний (HELIOS venv?) — тест некоректний")

    creds = [(vid, pwd) for vid, pwd in VOTERS.items()
             if pwd and "set-in-config" not in str(pwd)]
    if not creds:
        print("\n  ❌ Немає облікових даних виборців у config.local.json")
        return
    voter_id, password = creds[-1]     # use the last voter as the victim

    print(f"\n  ▶ КРОК 1 — легітимний голос виборця {voter_id} з {VICTIM_IP} (self)")
    legit = cast_full_flow(voter_id, password, VICTIM_IP, choice=0)
    print(f"    {'🔴 заблоковано (неочікувано!)' if legit['blocked'] else '✅ пройшов'}  "
          f"(HTTP {legit['status']})")
    hash_before = _read_vote_hash(voter_id, password, VICTIM_IP)
    print(f"    vote_hash жертви після легіт-голосу: {str(hash_before)[:24]}…")
    time.sleep(1.0)

    print(f"\n  ▶ КРОК 2 — АТАКА: ті самі вкрадені дані, ІНШЕ джерело {ATTACKER_IP} (non-self)")
    attack = cast_full_flow(voter_id, password, ATTACKER_IP, choice=1)
    if attack["blocked"]:
        print(f"    🛡  ЗАБЛОКОВАНО ЦІС  → {attack['attack_class']}  (HTTP {attack['status']})")
    else:
        print(f"    🔴 ПРОПУЩЕНО — підміну голосу не виявлено  (HTTP {attack['status']})")

    # ground truth: did the ballot actually change? (fresh read, may be unavailable)
    hash_after = _read_vote_hash(voter_id, password, VICTIM_IP)
    if hash_before is None or hash_after is None:
        hash_state = None          # could not verify — do NOT fail detection on it
        hash_txt = "n/a (не вдалося прочитати)"
    elif hash_before == hash_after:
        hash_state = True
        hash_txt = "НЕ ЗМІНЕНО ✅ (цілісність збережена)"
    else:
        hash_state = False
        hash_txt = "ЗМІНЕНО 🔴"
    print(f"    vote_hash жертви після атаки:       {str(hash_after)[:24]}…  → {hash_txt}")

    print("\n" + "=" * 78)
    # primary evidence = the block; the vote_hash confirms it but its absence
    # (read failure) must not turn a real block into "not detected"
    detected = (not legit["blocked"]) and attack["blocked"] \
        and attack["attack_class"] == "vote_manipulation" and hash_state is not False
    if detected:
        print("  ✅ ЦІС ОПОЗНАВ атаку: легітимний голос пройшов, а перезапис бюлетеня")
        print("     з іншого джерела заблоковано як vote_manipulation (ballot-ownership).")
    elif legit["blocked"]:
        print("  ⚠️  Легітимний голос заблоковано — хибне спрацювання, тест некоректний.")
    else:
        print("  ⚠️  Атаку НЕ виявлено — перевір, що легіт-голос пройшов через проксі ПЕРШИМ")
        print("     (bootstrap ownership) і що атакуюче джерело відрізняється.")
    print("=" * 78)

    _hash_label = {True: "незмінний (цілісність)", False: "ЗМІНЕНО", None: "n/a"}[hash_state]
    save_security_result(
        key="ballot_takeover", label="Виявлення підміни голосу (ballot-ownership)",
        value="виявлено" if detected else "не виявлено",
        detail=(f"легіт={'пройшов' if not legit['blocked'] else 'заблок.'}, "
                f"атака={'блок vote_manipulation' if attack['blocked'] else 'пройшла'}, "
                f"vote_hash={_hash_label}"),
        passed=detected, source="ballot_takeover_test.py")


if __name__ == "__main__":
    main()
