"""
Очистка артефактів попередніх запусків.
Використання:
  python utils/cleaner.py                    — dry-run (показати що буде видалено)
  python utils/cleaner.py --yes              — видалити ВСЕ (включно зі сценаріями)
  python utils/cleaner.py --keep-scenarios   — dry-run, але сценарії лишити
  python utils/cleaner.py --keep-scenarios --yes  — видалити reports+logs, сценарії лишити

Чистить:
  reports/   — звіти атак, IRE, risk, chain (регенеруються)
  logs/      — attack_events, immune_responses, immune_blocks,
               immune_memory.db (пам'ять ЦІС), *.log
  scenarios/ — лише якщо БЕЗ прапора --keep-scenarios
"""

import sys
import shutil
import json
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config


def collect_artifacts(cfg: dict, keep_scenarios: bool) -> tuple:
    root = Path(cfg.get("_root", Path(__file__).resolve().parent))
    scenarios_dir = root / cfg["paths"]["scenarios_dir"]
    reports_dir   = root / cfg["paths"]["reports_dir"]
    logs_dir      = root / cfg["paths"]["logs_dir"]
    to_delete = []
    sub_dirs = []
    # Сценарії — лише якщо не просили зберегти
    if not keep_scenarios and scenarios_dir.exists():
        to_delete += list(scenarios_dir.rglob("*.json"))
        sub_dirs += [scenarios_dir / "system", scenarios_dir / "voter", scenarios_dir / "adaptive"]
    # Звіти й логи — завжди. reports/ тепер розкладені по підпапках
    # (attacks/ risk/ benchmark/ metrics/ defense/ ire/) → рекурсивний пошук.
    if reports_dir.exists():
        to_delete += list(reports_dir.rglob("*.json")) + list(reports_dir.rglob("*.txt"))
        sub_dirs += [d for d in reports_dir.iterdir() if d.is_dir()]   # прибрати порожні підпапки
    if logs_dir.exists():
        to_delete += [f for f in logs_dir.iterdir() if f.is_file()]   # вкл. ai_memory.db / immune_memory.db
    return to_delete, sub_dirs


def print_summary(to_delete: list, sub_dirs: list, dry_run: bool, keep_scenarios: bool):
    print("=" * 60)
    mode = "DRY RUN — додай --yes для виконання" if dry_run else "ОЧИСТКА"
    keep = "  (сценарії ЗБЕРІГАЮТЬСЯ)" if keep_scenarios else "  (включно зі сценаріями)"
    print(f"  {mode}{keep}")
    print("=" * 60)
    total_size = 0
    for f in to_delete:
        size = f.stat().st_size if f.exists() else 0
        total_size += size
        prefix = "[?]  " if dry_run else "[del]"
        print(f"  {prefix} {f}  ({size} bytes)")
    for d in sub_dirs:
        if d.exists():
            prefix = "[?dir]" if dry_run else "[rmdir]"
            print(f"  {prefix} {d}/")
    print(f"\n  Всього: {len(to_delete)} файлів, {total_size / 1024:.1f} KB")


def run_cleanup(to_delete: list, sub_dirs: list, cfg: dict):
    for f in to_delete:
        if f.exists():
            f.unlink()
    for d in sub_dirs:
        if d.exists():
            shutil.rmtree(d)
    root = Path(cfg.get("_root", Path(__file__).resolve().parent))
    for p in [cfg["paths"]["scenarios_dir"], cfg["paths"]["reports_dir"], cfg["paths"]["logs_dir"]]:
        (root / p).mkdir(exist_ok=True)
    print(f"\n  ✓ Видалено {len(to_delete)} файлів")
    print("  ✓ Готово до нового запуску")


if __name__ == "__main__":
    keep_scenarios = "--keep-scenarios" in sys.argv
    dry_run = "--yes" not in sys.argv
    cfg = load_config()
    to_delete, sub_dirs = collect_artifacts(cfg, keep_scenarios)
    print_summary(to_delete, sub_dirs, dry_run, keep_scenarios)
    if dry_run:
        flag = " --keep-scenarios" if keep_scenarios else ""
        print(f"\n  Запусти  python utils/cleaner.py{flag} --yes  щоб видалити")
        sys.exit(0)
    confirm = input("\n  Видалити? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("  Скасовано.")
        sys.exit(0)
    run_cleanup(to_delete, sub_dirs, cfg)
