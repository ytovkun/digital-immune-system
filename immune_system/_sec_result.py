"""
Shared helper: saving a security-test result to JSON.
Digital immune system — immune_system/_sec_result.py

Each security script (false_positive / held_out / prompt_injection / ai_flood)
writes ITS measurement here → metrics_summary reads them instead of hardcoded values.
So chapter 3 of the dissertation is assembled from REAL runs, not manually entered numbers.
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
    """Save one security-test measurement to reports/security/<key>.json."""
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
