"""
Спільний хелпер: збереження результату security-тесту у JSON.
Цифрова імунна система — immune_system/_sec_result.py

Кожен security-скрипт (false_positive / held_out / prompt_injection / ai_flood)
пише СВІЙ вимір сюди → metrics_summary читає їх замість захардкоджених значень.
Так розділ 3 дисертації збирається з РЕАЛЬНИХ прогонів, а не з вписаних вручну цифр.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
_ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
SECURITY_DIR = _ROOT / _cfg.get("paths", {}).get("reports_dir", "reports") / "security"


def save_security_result(key: str, label: str, value: str, detail: str,
                         passed: bool, source: str):
    """Зберігає один вимір security-тесту у reports/security/<key>.json."""
    SECURITY_DIR.mkdir(parents=True, exist_ok=True)
    path = SECURITY_DIR / f"{key}.json"
    path.write_text(json.dumps({
        "key":          key,
        "label":        label,
        "value":        value,
        "detail":       detail,
        "passed":       bool(passed),
        "source":       source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [+] Результат збережено: reports/security/{key}.json")
