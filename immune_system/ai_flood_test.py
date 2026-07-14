"""
Тест rate-cap: захист ШІ від cache-busting флуду
Цифрова імунна система — immune_system/ai_flood_test.py

Атака на саму ЦІС: зловмисник шле УНІКАЛЬНІ патерни (кожен мимо кешу), щоб
форсувати дорогий ~3с виклик Claude на кожен запит → DoS на захист.

Очікування: після вичерпання бюджету ШІ-викликів на IP проксі переходить
у fail-closed (блокує критичні без виклику Claude) — захист не тоне у дорогих
викликах, критичні операції лишаються заблокованими.

Передумови: Helios :8001, immune_proxy :8000 (з УВІМКНЕНИМ ШІ).
Запуск:  python immune_system/ai_flood_test.py
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

FLOOD_COUNT = 20   # унікальних критичних запитів (більше за бюджет 12)


def main():
    print("=" * 76)
    print("  🧪 RATE-CAP — захист ШІ від cache-busting флуду")
    print(f"  Флуд {FLOOD_COUNT} УНІКАЛЬНИХ критичних запитів (кожен мимо кешу)")
    print("=" * 76)

    try:
        before = requests.get(f"{PROXY}/__immune__/stats", timeout=3).json()
    except requests.exceptions.ConnectionError:
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py (з ключем ШІ)")
        return

    ai_before = before["ai_analyst"]["api_calls"]
    print(f"\n  ШІ-викликів до флуду: {ai_before}")
    print(f"  Бюджет на IP: ~12 викликів / 60с\n")

    latencies = []
    blocked = 0
    s = requests.Session()
    s.headers.update({"User-Agent": "python-requests/2.31"})
    for i in range(FLOOD_COUNT):
        # cache-busting через УНІКАЛЬНИЙ query-параметр (він входить у підпис кешу,
        # на відміну від тіла) — кожен запит мимо кешу → форсує виклик Claude
        t0 = time.perf_counter()
        try:
            r = s.post(f"{PROXY}/helios/elections/{UUID}/cast?n={i}&t={int(time.time()*1000)}",
                       data=json.dumps({"nonce": f"flood-{i}"}),
                       headers={"Content-Type": "application/json"},
                       timeout=20, allow_redirects=False)
            ms = (time.perf_counter() - t0) * 1000
            latencies.append(ms)
            if r.status_code == 403:
                blocked += 1
            tag = ""
            if ms < 50:
                tag = "(дешево — rate-cap/cache)"
            elif ms > 1500:
                tag = "(дорогий виклик Claude)"
            print(f"  #{i+1:<2} HTTP {r.status_code}  {ms:>7.0f}ms  {tag}")
        except requests.exceptions.RequestException as e:
            print(f"  #{i+1:<2} ERR {type(e).__name__}")

    after = requests.get(f"{PROXY}/__immune__/stats", timeout=3).json()
    ai_after = after["ai_analyst"]["api_calls"]
    rate_capped = after["ai_analyst"].get("rate_capped", 0)
    real_calls = ai_after - ai_before

    print("\n" + "=" * 76)
    print("  📊 РЕЗУЛЬТАТ — стійкість ШІ до флуду")
    print("=" * 76)
    print(f"  Запитів надіслано:          {FLOOD_COUNT}")
    print(f"  Критичних заблоковано:      {blocked}/{FLOOD_COUNT}")
    print(f"  РЕАЛЬНИХ викликів Claude:   {real_calls}  (решта — fail-closed без ШІ)")
    print(f"  Rate-capped запитів:        {rate_capped}")
    if latencies:
        cheap = sum(1 for ms in latencies if ms < 50)
        print(f"  Дешевих відповідей (<50ms): {cheap}/{len(latencies)}")
    print()
    if real_calls <= 14 and blocked >= FLOOD_COUNT * 0.9:
        print("  ✅ Захист тримається: ШІ зробив лише ~12 дорогих викликів, далі")
        print("     критичні запити блокувались МИТТЄВО (fail-closed). Флуд не")
        print("     втопив захист у дорогих API-викликах, вкидання НЕ пройшли.")
    else:
        print(f"  ⚠️  real_calls={real_calls}, blocked={blocked} — перевірити налаштування бюджету.")
    print("=" * 76)

    save_security_result(
        key="ai_flood", label="Стійкість до DoS на ШІ",
        value=f"{blocked}/{FLOOD_COUNT} блок, викликів ШІ={real_calls}",
        detail=f"надлишок понад бюджет → fail-closed (rate_capped={rate_capped})",
        passed=(real_calls <= 14 and blocked >= FLOOD_COUNT * 0.9),
        source="ai_flood_test.py")


if __name__ == "__main__":
    main()
