"""
SIEM-порівняння, крок 1: РЕПЛЕЙ розміченого набору для захоплення трафіку.
Цифрова імунна система — siem/siem_capture.py

Надсилає ТОЙ САМИЙ labeled-набір, що й benchmark.py, до цільового сервера, аби
мережевий IDS (Suricata) побачив ідентичний атакуючий трафік. Кожен запит несе
унікальний маркер `_bid=<idx>` у URL — щоб потім однозначно зіставити алерти
Suricata з розміченими запитами (корелює siem_compare.py).

Ціль за замовчуванням — СИРИЙ Helios :8001 (як у реальному деплої, де IDS моніторить
трафік до веб-сервера). Зміна: env SIEM_TARGET=http://localhost:PORT.

Порядок (див. README / підказку siem_compare.py):
  1. sudo tcpdump -i lo0 -w reports/siem/bench.pcap 'tcp port 8001'   (термінал A)
  2. python siem/siem_capture.py                             (термінал B)
  3. Ctrl-C tcpdump → suricata -r bench.pcap ... → python siem_compare.py
"""

import os
import sys
import json
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "immune_system"))   # benchmark лежить тут
import requests
from env_loader import load_config
import benchmark as bench

_cfg = load_config()
TARGET = os.environ.get("SIEM_TARGET", "http://localhost:8001")
BROWSER_UA = bench.BROWSER_UA


def _with_bid(path: str, bid: int) -> str:
    """Додає унікальний маркер _bid=<idx> у query (для кореляції з алертами)."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}_bid={bid}"


def main():
    ds = bench.build_dataset()
    out_dir = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent)) \
        / _cfg.get("paths", {}).get("reports_dir", "reports") / "siem"
    out_dir.mkdir(parents=True, exist_ok=True)
    access_log = out_dir / "access.log"

    print("=" * 70)
    print(f"  SIEM-REPLAY — {len(ds)} запитів до {TARGET}")
    print(f"  (атак: {sum(1 for x in ds if x['label']=='attack')}, "
          f"легіт: {sum(1 for x in ds if x['label']=='legit')})")
    print("  Пише access.log (для Wazuh) + шле HTTP (для Suricata-pcap).")
    print(f"  Кожен запит має _bid=<idx> для кореляції з алертами SIEM.")
    print("=" * 70)

    # append: Wazuh тейлить НОВІ рядки (файл спорожнюється оркестратором ПЕРЕД
    # стартом моніторингу). Suricata-шлях цим не залежить.
    labels, sent = {}, 0
    with open(access_log, "a", encoding="utf-8") as alog:
        for i, item in enumerate(ds):
            labels[str(i)] = {"label": item["label"], "why": item["why"],
                              "method": item["method"], "path": item["path"]}
            path_bid = _with_bid(item["path"], i)
            url = f"{TARGET}{path_bid}"
            ua = BROWSER_UA if item["browser"] else "python-requests/2.31"
            headers = dict(item.get("headers") or {})
            headers.setdefault("User-Agent", ua)
            status = 200
            try:
                r = requests.request(item["method"], url, data=item.get("body"),
                                     headers=headers, timeout=10, allow_redirects=False)
                status = r.status_code
                sent += 1
            except requests.exceptions.RequestException:
                pass
            # Apache combined access-log рядок (те, що читає Wazuh; містить _bid у URL)
            ts = time.strftime("%d/%b/%Y:%H:%M:%S %z")
            ref = headers.get("Referer", "-")
            alog.write(f'127.0.0.1 - - [{ts}] "{item["method"]} {path_bid} HTTP/1.1" '
                       f'{status} 0 "{ref}" "{ua}"\n')
            time.sleep(0.03)

    (out_dir / "bench_labels.json").write_text(
        json.dumps(labels, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  Надіслано HTTP: {sent}/{len(ds)}")
    print(f"  [+] Access-log (для Wazuh): reports/siem/access.log ({len(ds)} рядків)")
    print(f"  [+] Мапа міток: reports/siem/bench_labels.json")
    print("  Далі: Wazuh обробляє access.log → alerts.json → siem/siem_compare.py")


if __name__ == "__main__":
    main()
