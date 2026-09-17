"""
Antibody persistence across a proxy restart (section 5.4.3).
Digital immune system — immune_system/persistence_test.py

Proves that synthesized verdicts (antibodies) survive a restart of the proxy
PROCESS: they live not only in the in-memory cache but also in SQLite
(ai_antibodies). After a restart the repeat attack is caught WITHOUT a model
call (api_calls does not grow) — immunity is not reset to zero.

Two phases (a restart of immune_proxy happens between them):
  --phase arm     : send a NOVEL anomaly → L2 blocks it and synthesizes an
                    antibody (slow, a model call); records intermediate state.
  --phase verify  : AFTER the restart — replay the SAME attack; the block must
                    come from memory (api_calls delta = 0), fast.

IMPORTANT: antibodies have a TTL (CACHE_TTL_SEC = 5 min). The restart + verify
must be done within that window, otherwise load_valid will not return them.

Prerequisites: Helios :8001, immune_proxy :8000 (with the AI ENABLED).
Run (restart the proxy BEFORE arm — a fresh process forgets in-memory L1
signatures from prior runs, so the novel anomaly reaches the AI):
      # (re)start immune_proxy.py   → fresh L1 state
      python immune_system/persistence_test.py --phase arm
      # ...restart immune_proxy.py again within 5 min...
      python immune_system/persistence_test.py --phase verify
Out:  reports/persistence/persistence_{ts}.json
"""

import sys
import json
import time
import argparse
import requests
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")
PERSIST_DIR = REPORTS / "persistence"
STATE_FILE = PERSIST_DIR / "_arm_state.json"
TTL_SEC = 300.0   # CACHE_TTL_SEC — the antibody window; verify must be within it

PROXY = "http://localhost:8000"
UUID = _cfg.get("helios", {}).get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def _stats() -> dict:
    try:
        return requests.get(f"{PROXY}/__immune__/stats", timeout=3).json()
    except requests.exceptions.RequestException:
        return {}


def _send(path: str) -> dict:
    """Send one request from a browser-like client; return status/latency/tier."""
    s = requests.Session()
    s.headers.update({"User-Agent": BROWSER_UA, "X-Forwarded-For": "203.0.113.201"})
    t0 = time.perf_counter()
    try:
        r = s.get(f"{PROXY}{path}", timeout=30, allow_redirects=False)
    except requests.exceptions.RequestException:
        return {"status": None, "latency_ms": None, "blocked": False, "tier": "?"}
    ms = round((time.perf_counter() - t0) * 1000, 1)
    blocked = r.status_code in (400, 403)
    tier = "?"
    if blocked:
        try:
            tier = r.json().get("blocked_by", "?")
        except (ValueError, TypeError):
            tier = "?"
    return {"status": r.status_code, "latency_ms": ms, "blocked": blocked, "tier": tier}


def _antibodies(st: dict) -> int:
    return st.get("ai_analyst", {}).get("persistent_antibodies", 0)


def _api_calls(st: dict) -> int:
    return st.get("ai_analyst", {}).get("api_calls", 0)


# ─── Phase ARM: synthesize an antibody before the restart ─────────────────────

def arm():
    print("=" * 74)
    print("  🧬 ПЕРСИСТЕНТНІСТЬ АНТИТІЛ — фаза ARM (до перезапуску)")
    print("=" * 74)
    st0 = _stats()
    if not st0:
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py (з ключем ШІ).")
        return
    if not st0.get("ai_analyst", {}).get("enabled"):
        print("\n  ⚠️  ШІ вимкнено — антитіло не синтезується. Запусти проксі з ANTHROPIC_API_KEY.")
        return

    # a UNIQUE anomaly per run → guarantees a fresh model call (not an old cache hit)
    token = datetime.now(timezone.utc).strftime("%H%M%S")
    path = f"/helios/elections/{UUID}/view?c=<div onmouseover=persist{token}()>"

    ab_before, calls_before = _antibodies(st0), _api_calls(st0)
    print(f"\n  Антитіл у БД до атаки:   {ab_before}")
    print(f"  Патерн (нова аномалія):  ...onmouseover=persist{token}()")
    print("  Надсилаю (перша зустріч → аналізує ШІ, синтезує антитіло)...")
    r = _send(path)
    st1 = _stats()
    ab_after, calls_after = _antibodies(st1), _api_calls(st1)

    print(f"\n  Результат:  HTTP {r['status']}  ({r['tier']})  {r['latency_ms']} мс")
    print(f"  Викликів ШІ: {calls_before} → {calls_after}  (+{calls_after - calls_before})")
    print(f"  Антитіл у БД: {ab_before} → {ab_after}  (+{ab_after - ab_before})")

    ok = r["blocked"] and ab_after > ab_before and calls_after > calls_before
    if not ok:
        # Diagnose WHY no fresh synthesis happened (the common case: a long-running
        # proxy already LEARNED this anomaly's L1 signature in a prior run, so the
        # request is caught deterministically by L1 without a model call).
        if r["blocked"] and calls_after == calls_before and r["tier"] == "FastReflex":
            print("\n  ⚠️  Заблоковано на L1 (вивчена сигнатура з ПОПЕРЕДНЬОГО прогону) — "
                  "ШІ не викликано, нове антитіло не синтезоване.")
            print("  🔧 FIX: ПЕРЕЗАПУСТИ immune_proxy.py і повтори --phase arm.")
            print("     Свіжий процес забуває L1-сигнатури (вони лише в памʼяті), тож нова")
            print("     аномалія піде на ШІ й синтезує антитіло. (L2-антитіла в SQLite —")
            print("     саме їх ми й перевіряємо у фазі verify; на них це не впливає.)")
        elif r["blocked"] and calls_after == calls_before:
            print("\n  ⚠️  Заблоковано з КЕШУ (антитіло вже було з попереднього прогону) — "
                  "ШІ не викликано.")
            print("  🔧 FIX: перезапусти проксі і повтори --phase arm (або зачекай TTL 5хв).")
        else:
            print("\n  ⚠️  Не заблоковано / не додано в БД. Перевір, що ШІ увімкнено (ANTHROPIC_API_KEY).")
        return

    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({
        "armed_at": datetime.now(timezone.utc).isoformat(),
        "armed_ts": time.time(),
        "token": token, "path": path,
        "arm_status": r["status"], "arm_latency_ms": r["latency_ms"], "arm_tier": r["tier"],
        "antibodies_after_arm": ab_after,
        "learned_signatures_after_arm": st1.get("fast_reflex", {}).get("learned_signatures", 0),
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n  ✅ Антитіло синтезовано й записано у SQLite.")
    print("  " + "─" * 70)
    print(f"  ДАЛІ (в межах {TTL_SEC:.0f}с / {TTL_SEC/60:.0f} хв — поки не сплив TTL):")
    print("    1. ПЕРЕЗАПУСТИ immune_proxy.py (Ctrl+C → знову запусти)")
    print("    2. Одразу: python immune_system/persistence_test.py --phase verify")
    print("=" * 74)


# ─── Phase VERIFY: after the restart, the repeat must come from memory ─────────

def verify():
    print("=" * 74)
    print("  🧬 ПЕРСИСТЕНТНІСТЬ АНТИТІЛ — фаза VERIFY (після перезапуску)")
    print("=" * 74)
    if not STATE_FILE.exists():
        print("\n  ❌ Немає стану фази ARM. Спочатку прожени --phase arm.")
        return
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    age = time.time() - state.get("armed_ts", 0)
    st0 = _stats()
    if not st0:
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py.")
        return

    loaded = st0.get("ai_analyst", {}).get("loaded_on_start", 0)
    calls_before = _api_calls(st0)
    print(f"\n  Час від ARM:              {age:.0f}с  "
          + ("✓ у межах TTL" if age < TTL_SEC else "⚠️ TTL СПЛИВ — антитіла могли не завантажитись"))
    print(f"  Антитіл завантажено при старті (loaded_on_start): {loaded}")
    print(f"  Викликів ШІ у НОВОМУ процесі:                     {calls_before}")

    print("\n  Повторюю ТУ САМУ атаку (має ловитись із памʼяті, без ШІ)...")
    r = _send(state["path"])
    st1 = _stats()
    calls_after = _api_calls(st1)
    delta = calls_after - calls_before

    print(f"\n  Результат:  HTTP {r['status']}  ({r['tier']})  {r['latency_ms']} мс")
    print(f"  Викликів ШІ: {calls_before} → {calls_after}  (Δ={delta})")

    from_memory = r["blocked"] and delta == 0 and loaded > 0
    speedup = None
    if state.get("arm_latency_ms") and r["latency_ms"]:
        speedup = round(state["arm_latency_ms"] / r["latency_ms"], 1) if r["latency_ms"] else None

    print("  " + "─" * 70)
    if from_memory:
        print("  ✅ ІМУНІТЕТ ПЕРЕЖИВ ПЕРЕЗАПУСК: повторну атаку заблоковано БЕЗ виклику ШІ")
        print(f"     (антитіло відновлено з SQLite; {loaded} завантажено при старті).")
    else:
        print("  ⚠️  Не підтверджено: або не заблоковано, або ШІ викликано (Δ>0), "
              "або TTL сплив. Повтори ARM→restart→VERIFY у межах 5 хв.")
    print("=" * 74)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "persistence_confirmed": from_memory,
        "ttl_sec": TTL_SEC,
        "seconds_between_phases": round(age, 1),
        "arm": {
            "status": state.get("arm_status"), "latency_ms": state.get("arm_latency_ms"),
            "tier": state.get("arm_tier"), "antibodies_after": state.get("antibodies_after_arm"),
        },
        "verify": {
            "loaded_on_start": loaded,
            "api_calls_before": calls_before, "api_calls_after": calls_after,
            "api_calls_delta": delta,
            "status": r["status"], "latency_ms": r["latency_ms"], "tier": r["tier"],
        },
        "speedup_vs_first_encounter": speedup,
    }
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    (PERSIST_DIR / f"persistence_{ts}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  [+] Збережено: reports/persistence/persistence_{ts}.json")


def main():
    ap = argparse.ArgumentParser(description="Antibody persistence across proxy restart (5.4.3)")
    ap.add_argument("--phase", required=True, choices=["arm", "verify"],
                    help="arm — до перезапуску; verify — після")
    args = ap.parse_args()
    (arm if args.phase == "arm" else verify)()


if __name__ == "__main__":
    main()
