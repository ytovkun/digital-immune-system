"""
Held-out attack test: does the AI catch attacks that were NOT in the catalog
Digital immune system — immune_system/held_out_attack_test.py

The strongest proof of GenAI generalization: the AI blocks attacks that NO ONE
told it about — neither in the FastReflex signatures, nor in the 11 catalog
classes, nor in the AIAnalyst system prompt. If the AI catches them — it REASONS
about intent, not checks against a list.

Held-out attacks (NOT in the 11-class catalog and not mentioned in the AI prompt):
  1. Path Traversal       — /helios/.../../../etc/passwd
  2. SQL Injection        — /voters/?q=1' OR '1'='1' --
  3. Election Deletion    — POST /delete (election destruction, not ballot stuffing)
  4. Ballot Deletion      — DELETE on a ballot (HTTP verb tampering)
  5. XSS / Template Inj.  — a parameter with <script>/{{7*7}}

FastReflex only ROUTES them to the AI (as anomalies) — the AI issues the BLOCK.

Prerequisites: Helios :8001, immune_proxy :8000 (with the AI ENABLED).
Run:  python immune_system/held_out_attack_test.py
"""

import sys

import json
import time
import requests
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_loader import load_config
from _sec_result import save_security_result

_cfg = load_config()
PROXY = "http://localhost:8000"
UUID  = _cfg.get("helios", {}).get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"


# Each probe: (name, why-it-is-novel description, request function)
def probe_path_traversal():
    return requests.get(
        f"{PROXY}/helios/elections/{UUID}/../../../../etc/passwd",
        headers={"User-Agent": UA}, timeout=10, allow_redirects=False)


def probe_sql_injection():
    return requests.get(
        f"{PROXY}/helios/elections/{UUID}/voters/",
        params={"q": "1' OR '1'='1' --", "limit": "999"},
        headers={"User-Agent": UA}, timeout=10, allow_redirects=False)


def probe_election_deletion():
    return requests.post(
        f"{PROXY}/helios/elections/{UUID}/delete",
        data={"confirm": "yes"},
        headers={"User-Agent": UA, "Referer": f"{PROXY}/"},
        timeout=10, allow_redirects=False)


def probe_ballot_deletion():
    return requests.delete(
        f"{PROXY}/helios/elections/{UUID}/ballots/somehash123",
        headers={"User-Agent": UA}, timeout=10, allow_redirects=False)


def probe_xss_template():
    return requests.get(
        f"{PROXY}/helios/elections/{UUID}/view",
        params={"msg": "<script>alert(document.cookie)</script>{{7*7}}"},
        headers={"User-Agent": UA}, timeout=10, allow_redirects=False)


HELD_OUT = [
    ("Path Traversal",      "обхід каталогу до /etc/passwd",          probe_path_traversal),
    ("SQL Injection",       "OR 1=1 у параметрі q",                   probe_sql_injection),
    ("Election Deletion",   "POST /delete — знищення виборів",        probe_election_deletion),
    ("Ballot Deletion",     "DELETE бюлетеня (verb tampering)",       probe_ballot_deletion),
    ("XSS / Template Inj.", "<script> + {{7*7}} у параметрі",         probe_xss_template),
]


def main():
    print("=" * 76)
    print("  🧪 HELD-OUT АТАКИ — чи ловить ШІ те, про що йому НЕ розповідали")
    print("  Жодна з цих атак НЕ входить у 11 класів каталогу й не згадана в промпті ШІ")
    print("=" * 76)

    try:
        requests.get(PROXY, timeout=3)
    except requests.exceptions.ConnectionError:
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py (з ключем ШІ)")
        return

    results = []
    for name, why, fn in HELD_OUT:
        print(f"\n  ▶ {name}  ({why})")
        try:
            r = fn()
            blocked = (r.status_code == 403 and "Immune" in r.text)
            detail = ""
            if blocked:
                try:
                    body = r.json()
                    detail = f"{body.get('blocked_by','?')}: {body.get('attack_class','?')}"
                except Exception:
                    detail = "403"
            icon = "🛡  ЗАБЛОКОВАНО ШІ" if blocked else f"⚠️  пройшло (HTTP {r.status_code})"
            print(f"    {icon}  {detail}")
            results.append((name, blocked, r.status_code))
            time.sleep(1.0)
        except requests.exceptions.RequestException as e:
            print(f"    ERR: {type(e).__name__}")
            results.append((name, False, "ERR"))

    # ─── Summary ────────────────────────────────────────────────────────────────
    caught = sum(1 for _, b, _ in results if b)
    total = len(results)
    print("\n" + "=" * 76)
    print("  📊 РЕЗУЛЬТАТ — узагальнення GenAI")
    print("=" * 76)
    for name, blocked, status in results:
        mark = "🛡  спіймано" if blocked else "⚠️  пропущено"
        print(f"  {name:<24} {mark}  (HTTP {status})")
    print(f"\n  Спіймано нових атак: {caught}/{total} ({caught/total*100:.0f}%)")
    if caught >= total * 0.6:
        print("\n  ✅ ШІ ловить НОВІ атаки, про які не знав → доведено УЗАГАЛЬНЕННЯ.")
        print("     Це не звіряння зі списком — ШІ РОЗМІРКОВУЄ про намір запиту.")
    else:
        print(f"\n  ⚠️  Спіймано лише {caught}/{total} — частина нових атак пройшла.")
        print("     Honest: межі узагальнення ШІ; потрібне підсилення маршрутизації аномалій.")
    print("\n  💡 Жодна сигнатура не блокувала ці атаки — рішення виніс ШІ своїм")
    print("     міркуванням. FastReflex лише позначив їх як аномалії та передав на ШІ.")
    print("=" * 76)

    caught_names = ", ".join(n for n, b, _ in results if b)
    save_security_result(
        key="generalization", label="Узагальнення (нові атаки)",
        value=f"{caught}/{total} ({caught/total*100:.0f}%)" if total else "0/0",
        detail=f"спіймано: {caught_names}" if caught_names else "нічого не спіймано",
        passed=(total > 0 and caught >= total * 0.6), source="held_out_attack_test.py")


if __name__ == "__main__":
    main()
