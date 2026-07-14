"""
Модуль: env_loader — спільні утиліти конфігурації
Цифрова імунна система — env_loader.py

Єдине джерело логіки завантаження:
  load_env()    — парсер .env (ключ ANTHROPIC_API_KEY тощо) в os.environ
  load_config() — пошук і читання config.json (walk-up до кореня проєкту)

Усуває дублювання _load_config у кожному модулі (DRY). Використання:
    import sys; from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from env_loader import load_config, load_env
    load_env()
    _cfg = load_config()
"""

import json
import os
from pathlib import Path


def find_root(start: Path = None) -> Path:
    """Знаходить корінь проєкту (теку з config.json), walk-up від файлу."""
    here = (start or Path(__file__)).resolve().parent
    for d in [here, *here.parents]:
        if (d / "config.json").exists():
            return d
    return here


def _deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивно зливає override у base (для перевизначень config.local.json)."""
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(start: Path = None) -> dict:
    """
    Завантажує config.json з кореня проєкту. Додає ключ '_root' з абсолютним
    шляхом до кореня — щоб модулі будували абсолютні шляхи незалежно від CWD.

    Якщо поруч є config.local.json (у .gitignore) — його значення мають
    пріоритет (deep-merge). Туди виносяться СЕКРЕТИ (паролі виборців тощо),
    щоб не комітити їх у репозиторій. Див. config.local.json.example.
    """
    root = find_root(start)
    cfg_path = root / "config.json"
    if not cfg_path.exists():
        return {"_root": str(root)}
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    # Локальні перевизначення (секрети, поза git) мають пріоритет
    local_path = root / "config.local.json"
    if local_path.exists():
        try:
            _deep_merge(cfg, json.loads(local_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass
    cfg["_root"] = str(root)
    return cfg


def load_env(start: Path = None) -> bool:
    """
    Знаходить .env (walk-up) і завантажує змінні в os.environ.
    Повертає True, якщо файл знайдено й оброблено.
    Існуючі змінні оточення мають пріоритет (не перезаписуються).
    """
    here = (start or Path(__file__)).resolve().parent
    for d in [here, *here.parents]:
        env_path = d / ".env"
        if env_path.exists():
            _parse_into_environ(env_path)
            return True
    return False


def _parse_into_environ(env_path: Path):
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        # пропускаємо порожні рядки та коментарі
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        # не перезаписуємо те, що вже є в реальному оточенні
        if key and key not in os.environ:
            os.environ[key] = value
