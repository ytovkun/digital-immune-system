"""
Module: env_loader — shared configuration utilities
Digital immune system — env_loader.py

Single source of loading logic:
  load_env()    — .env parser (ANTHROPIC_API_KEY key, etc.) into os.environ
  load_config() — find and read config.json (walk-up to the project root)

Removes duplication of _load_config in every module (DRY). Usage:
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
    """Find the project root (the dir with config.json), walking up from the file."""
    here = (start or Path(__file__)).resolve().parent
    for d in [here, *here.parents]:
        if (d / "config.json").exists():
            return d
    return here


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (for config.local.json overrides)."""
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(start: Path = None) -> dict:
    """
    Load config.json from the project root. Adds a '_root' key with the absolute
    path to the root — so modules build absolute paths regardless of CWD.

    If config.local.json exists alongside (in .gitignore) — its values take
    priority (deep-merge). SECRETS (voter passwords, etc.) are moved there so
    they are not committed to the repository. See config.local.json.example.
    """
    root = find_root(start)
    cfg_path = root / "config.json"
    if not cfg_path.exists():
        return {"_root": str(root)}
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    # Local overrides (secrets, outside git) take priority
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
    Find .env (walk-up) and load variables into os.environ.
    Returns True if the file was found and processed.
    Existing environment variables take priority (are not overwritten).
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
        # skip empty lines and comments
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        # do not overwrite what is already in the real environment
        if key and key not in os.environ:
            os.environ[key] = value
