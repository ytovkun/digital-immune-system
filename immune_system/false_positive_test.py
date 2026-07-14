"""
Тест false-positive: чи блокує ЦІС ЛЕГІТИМНОГО виборця
Цифрова імунна система — immune_system/false_positive_test.py

Критично для e-voting: якщо захист блокує реального виборця — це позбавлення
права голосу. Цей тест імітує добросовісну поведінку виборця і рахує, скільки
легітимних запитів помилково заблоковано (має бути 0).

Легітимний виборець (на відміну від атаки):
  - справжній браузерний User-Agent (не python-requests)
  - коректний логін зі справжніми credentials
  - нормальний темп (паузи між діями, не залп)
  - ОДНЕ голосування, не флуд
  - автентифікована сесія

Передумови: Helios :8001, immune_proxy :8000 (з УВІМКНЕНИМ ШІ).
Запуск:  python immune_system/false_positive_test.py
"""

import sys

import json
import re
import time
import requests
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_loader import load_config
from _sec_result import save_security_result

_cfg = load_config()
PROXY  = "http://localhost:8000"   # через ЦІС
UUID   = _cfg.get("helios", {}).get("election_uuid", "c88cfaeb-abc0-4440-a165-a77cab2951f2")
VOTERS = _cfg.get("helios", {}).get("voters", {})

# Справжній браузерний User-Agent — як у реального виборця
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def csrf(session, url):
    r = session.get(url, timeout=10)
    m = re.search(r'csrfmiddlewaretoken.*?value=[\'"]([^\'"]+)', r.text)
    return m.group(1) if m else ""


def legitimate_voter_journey(login: str, password: str, client_ip: str = "203.0.113.10") -> list:
    """
    Імітує добросовісну поведінку виборця через проксі.
    Повертає список (крок, статус, заблоковано?).

    client_ip — РІЗНИЙ для кожного виборця: реальні виборці приходять з РІЗНИХ
    адрес. Без цього всі тест-виборці схлопнулись би в один actor (127.0.0.1) і
    поведінковий темп-фільтр справедливо блокував би «один IP = кілька журналів
    поспіль» (штучний false-positive тесту, а не дефект захисту).
    """
    s = requests.Session()
    s.headers.update({"User-Agent": BROWSER_UA,
                      "Accept": "text/html,application/xhtml+xml",
                      "X-Forwarded-For": client_ip})
    steps = []

    def do(label, method, path, **kw):
        url = f"{PROXY}{path}"
        try:
            if method == "GET":
                r = s.get(url, timeout=10, allow_redirects=False, **kw)
            else:
                r = s.post(url, timeout=10, allow_redirects=False, **kw)
            blocked = (r.status_code == 403 and "Immune" in r.text)
            steps.append((label, r.status_code, blocked))
        except requests.exceptions.RequestException as e:
            steps.append((label, f"ERR:{type(e).__name__}", False))
        time.sleep(2.5)  # РЕАЛІСТИЧНИЙ людський темп: виборець читає сторінку й вводить
        #                  дані секундами, а не за 0.8с (0.8с — нелюдський залп)

    # 1. Виборець відкриває сторінку виборів
    do("Перегляд виборів", "GET", f"/helios/elections/{UUID}/view")
    # 2. Йде на сторінку логіну
    login_url = f"{PROXY}/helios/elections/{UUID}/password_voter_login"
    token = csrf(s, login_url)
    do("Сторінка логіну", "GET", f"/helios/elections/{UUID}/password_voter_login")
    # 3. Вводить свої справжні дані
    do("Логін (правильний пароль)", "POST", "/auth/password/login",
       data={"voter_id": login, "password": password,
             "csrfmiddlewaretoken": token, "election_uuid": UUID},
       headers={"Referer": login_url})
    # 4. Переглядає бюлетень
    do("Сторінка голосування", "GET", f"/helios/elections/{UUID}/vote")
    # 5. Голосує ОДИН раз (нормальний бюлетень)
    vote_token = csrf(s, f"{PROXY}/helios/elections/{UUID}/view")
    do("Подача голосу (одноразова)", "POST", f"/helios/elections/{UUID}/cast",
       data={"encrypted_vote": json.dumps({"answers": [{"choices": [0]}]}),
             "csrfmiddlewaretoken": vote_token},
       headers={"Referer": f"{PROXY}/helios/elections/{UUID}/vote"})
    # 6. Перевіряє що голос враховано
    do("Перевірка бюлетеня", "GET", f"/helios/elections/{UUID}/ballots/")

    return steps


def main():
    print("=" * 72)
    print("  🧪 ТЕСТ FALSE-POSITIVE — чи блокує ЦІС легітимного виборця")
    print("  Добросовісна поведінка через проксі :8000 (з ШІ)")
    print("=" * 72)

    # перевірка доступності
    try:
        requests.get(PROXY, timeout=3)
    except requests.exceptions.ConnectionError:
        print("\n  ❌ Проксі :8000 недоступний. Запусти immune_proxy.py")
        return

    # тестуємо кількох виборців (voter4/voter5 ще не голосували — найчистіший тест)
    test_voters = [("voter4", VOTERS.get("voter4", "")),
                   ("voter5", VOTERS.get("voter5", ""))]

    all_steps = []
    for i, (login, pwd) in enumerate(test_voters):
        if not pwd:
            continue
        client_ip = f"203.0.113.{20 + i}"   # РІЗНИЙ IP на кожного виборця (як у реалі)
        print(f"\n  ▶ Легітимний виборець: {login}  (IP {client_ip})")
        steps = legitimate_voter_journey(login, pwd, client_ip)
        all_steps += steps
        for label, status, blocked in steps:
            icon = "🔴 ХИБНИЙ БЛОК" if blocked else "✓"
            print(f"    {icon}  {label:<32} HTTP {status}")

    # ─── Підсумок ──────────────────────────────────────────────────────────────
    total = len(all_steps)
    false_blocks = sum(1 for _, _, b in all_steps if b)
    fp_rate = (false_blocks / total * 100) if total else 0

    print("\n" + "=" * 72)
    print("  📊 РЕЗУЛЬТАТ")
    print("=" * 72)
    print(f"  Легітимних запитів:        {total}")
    print(f"  Помилково заблоковано:     {false_blocks}")
    print(f"  False-positive rate (FPR): {fp_rate:.1f}%")
    if false_blocks == 0:
        print("\n  ✅ ЖОДНОГО хибного блоку — ЦІС не заважає реальним виборцям")
        print("     (немає позбавлення права голосу)")
    else:
        print(f"\n  ⚠️  {false_blocks} легітимних запитів заблоковано — потрібне")
        print("     калібрування ШІ (занадто агресивний поріг)")
    print("=" * 72)

    save_security_result(
        key="fpr", label="False-positive rate (FPR)",
        value=f"{fp_rate:.1f}%",
        detail=f"{total - false_blocks}/{total} легітимних запитів пропущено",
        passed=(false_blocks == 0), source="false_positive_test.py")


if __name__ == "__main__":
    main()
