"""
Re-detection через імунну пам'ять (розділ 5.1).
Цифрова імунна система — immune_system/redetection_test.py

Демонструє adaptive→innate immunity: НОВИЙ підозрілий патерн ЦІС спершу аналізує
ШІ (L2, ~секунди) і синтезує сигнатуру; ПОВТОРНА поява того самого патерну ловиться
миттєво рефлексом L1 (вивчена сигнатура / кеш-антитіло, ~0мс). Міряє прискорення
повторного виявлення — ефект «імунної пам'яті».

Кожен патерн надсилається кілька разів; фіксуємо латентність і рівень (L1/L2) на
кожній зустрічі. Передумови: Helios :8001, immune_proxy :8000 (з УВІМКНЕНИМ ШІ).
Запуск:  python immune_system/redetection_test.py
Вихід:   таблиця + reports/redetection/redetection_{ts}.json
"""

import sys
import json
import time
import requests
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")
PROXY = "http://localhost:8000"
UUID = _cfg.get("helios", {}).get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

REPEATS = 3   # скільки разів надсилати кожен патерн (1-ша = новизна, далі — пам'ять)

# Патерни-аномалії, що маршрутизуються на ШІ (не hard-block L1), аби ШІ синтезував
# сигнатуру, а L1 навчився й ловив повторні миттєво.
# Патерни-аномалії, що маршрутизуються на ШІ (НЕ hard-block L1): ШІ блокує й повертає
# signature-токен, L1 його вчить → повторні ловляться миттєво (re-detection пам'ять).
PATTERNS = [
    (f"/helios/elections/{UUID}/view?c=<div onmouseover=alert(1)>", "XSS onmouseover"),
    (f"/helios/elections/{UUID}/view?c=<iframe src=//evil.example>", "iframe injection"),
    (f"/helios/elections/{UUID}/view?c=<img src=x onerror=steal()>", "img onerror"),
    (f"/helios/elections/{UUID}/voters/?f=<b onload=x()>", "onload handler"),
]


def _stats():
    try:
        return requests.get(f"{PROXY}/__immune__/stats", timeout=3).json()
    except requests.exceptions.RequestException:
        return {}


def _send(path, ip):
    s = requests.Session()
    s.headers.update({"User-Agent": BROWSER_UA, "X-Forwarded-For": ip})
    t0 = time.perf_counter()
    try:
        r = s.get(f"{PROXY}{path}", timeout=30, allow_redirects=False)
    except requests.exceptions.RequestException:
        return None
    ms = (time.perf_counter() - t0) * 1000
    blocked = r.status_code in (400, 403)
    tier = "?"
    if blocked:
        try:
            tier = r.json().get("blocked_by", "?")
        except (ValueError, TypeError):
            tier = "?"
    return {"latency_ms": round(ms, 1), "blocked": blocked, "tier": tier,
            "status": r.status_code}


def main():
    print("=" * 74)
    print("  🧠 RE-DETECTION через імунну пам'ять (adaptive→innate)")
    print("=" * 74)
    if not _stats():
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py (з ключем ШІ).")
        return
    learned_before = _stats().get("fast_reflex", {}).get("learned_signatures", 0)

    results = []
    print(f"\n  {'Патерн':<22}{'зустріч':<9}{'рівень':<12}{'латентність':>12}")
    print("  " + "─" * 60)
    for path, why in PATTERNS:
        enc = []
        for i in range(REPEATS):
            # той самий IP — щоб перевіряти саме ПАМ'ЯТЬ (сигнатура/кеш), не per-IP
            r = _send(path, "203.0.113.200")
            if r is None:
                continue
            enc.append(r)
            tag = "L1" if r["tier"] == "FastReflex" else ("L2-ШІ" if r["tier"] == "AIAnalyst" else r["tier"])
            mark = "  (нова→ШІ)" if i == 0 else "  (пам'ять→L1)"
            print(f"  {why:<22}#{i+1:<8}{tag:<12}{r['latency_ms']:>9.0f}мс{mark if i in (0,1) else ''}")
            time.sleep(0.2)
        results.append({"pattern": why, "path": path, "encounters": enc})
    learned_after = _stats().get("fast_reflex", {}).get("learned_signatures", 0)

    # ─── Зведення: 1-ша зустріч (новизна) vs повторні (пам'ять) ────────────────
    first = [r["encounters"][0]["latency_ms"] for r in results if r["encounters"]]
    repeat = [e["latency_ms"] for r in results for e in r["encounters"][1:]]
    avg_first = sum(first) / len(first) if first else 0
    avg_repeat = sum(repeat) / len(repeat) if repeat else 0
    speedup = (avg_first / avg_repeat) if avg_repeat else None
    l1_repeats = sum(1 for r in results for e in r["encounters"][1:] if e["tier"] == "FastReflex")
    tot_repeats = sum(len(r["encounters"][1:]) for r in results)

    print("\n" + "=" * 74)
    print(f"  Сер. латентність 1-ї зустрічі (новизна, ШІ):  {avg_first:.0f} мс")
    print(f"  Сер. латентність повторних (пам'ять):         {avg_repeat:.1f} мс")
    if speedup:
        print(f"  Прискорення повторного виявлення:             ×{speedup:.0f}")
    print(f"  Повторних, спійманих L1 (вивчена сигнатура):  {l1_repeats}/{tot_repeats}")
    print(f"  Вивчено нових L1-сигнатур за прогін:          {learned_after - learned_before}")
    print("=" * 74)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repeats": REPEATS,
        "avg_first_ms": round(avg_first, 1),
        "avg_repeat_ms": round(avg_repeat, 1),
        "speedup": round(speedup, 1) if speedup else None,
        "l1_repeats": l1_repeats, "total_repeats": tot_repeats,
        "learned_signatures_delta": learned_after - learned_before,
        "patterns": results,
    }
    out_dir = REPORTS / "redetection"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"redetection_{ts}.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  [+] Збережено: reports/redetection/redetection_{ts}.json")


if __name__ == "__main__":
    main()
