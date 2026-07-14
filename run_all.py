"""
Оркестратор пайплайну ЦІС — один вхід замість ручної послідовності команд.
Цифрова імунна система — run_all.py

ПРЕСЕТИ (позиційний аргумент):
  analyze   Аналіз НАЯВНИХ даних, БЕЗ серверів і ключа:
              risk_scorer → immune_response_engine → metrics_summary
            (нічого не генерує і не виконує — працює на твоїх reports/).

  defense   Перевірка захисту через ImmuneProxy (:8000):
              benchmark → demo_before_after → metrics_summary → defense_report
            Передумова: Helios на :8001. Проксі :8000 — або підніми сама, або
            додай --with-defense (підніметься у фоні й згасне в кінці).

  offense   OFFENSIVE прогін проти СИРОГО Helios (:8001):
              [clean] → [generate] → [execute] → score → ire
            generate/execute можна пропустити (--skip-generate / --skip-execute),
            clean — лише за явним --clean (бо стирає reports/).
            Передумови: Helios :8001, ANTHROPIC_API_KEY у .env (для generate).

  campaign  ПОВНИЙ звіт «без захисту vs із захистом» однією командою:
              generate → атаки baseline(:8001) → атаки defended(через проксі :8000)
              → звіт baseline → звіт defended → ко-еволюція
            Пише reports/attacks/{baseline,defended}/ окремо; проксі :8000
            підіймається автоматично. Передумова: Helios :8001 (+ ключ для generate).
            Пропустити генерацію: --skip-generate (узяти наявні сценарії).

  test      Unit-тести (pytest) — без серверів і ключа.

  all       offense, потім defense.

ГРАНУЛЯРНІ ФЛАГИ ШАГІВ (якщо задано бодай один — пресет ігнорується, виконуються
лише вибрані кроки у канонічному порядку):
  --clean --generate --execute --score --ire --benchmark --demo --metrics --defense-report

ІНШІ ФЛАГИ:
  --with-defense   Підняти immune_proxy :8000 у фоні навколо defense-кроків і згасити в кінці
                   (якщо проксі вже працює — використає наявний, не чіпатиме).
  --skip-generate  У пресеті offense не генерувати сценарії (використати наявні)
  --skip-execute   У пресеті offense не виконувати атаки (використати наявні reports/)
  --keep-going     Не зупинятись на першій помилці

Приклади:
  python run_all.py analyze
  python run_all.py defense --with-defense
  python run_all.py offense --skip-generate
  python run_all.py --score --ire --metrics
"""

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable   # той самий інтерпретатор (venv)

PROXY_STATS_URL = "http://localhost:8000/__immune__/stats"
HELIOS_URL = "http://localhost:8001"

# Кроки: ім'я → (підпис, argv). Канонічний порядок — у ORDER.
STEPS = {
    "clean":          ("Очистка артефактів (сценарії лишаємо)",
                       [PY, "utils/cleaner.py", "--keep-scenarios", "--yes"]),
    "generate":       ("Генерація сценаріїв атак (Claude)",
                       [PY, "core/attack_generator.py", "all"]),
    "adapt":          ("Адаптація атак під блокування ЦІС (escalate/refine/bypass)",
                       [PY, "core/adaptive_generator.py", "all"]),
    "execute":        ("Виконання атак проти сирого Helios :8001",
                       [PY, "core/red_team_agent.py", "all"]),
    "score":          ("Таблиці ризиків (з наявних reports/)",
                       [PY, "core/risk_scorer.py"]),
    "ire":            ("Offline-агрегація інцидентів (IRE)",
                       [PY, "core/immune_response_engine.py"]),
    "benchmark":      ("Labeled-бенчмарк через проксі :8000 (P/R/F1 + ДІ)",
                       [PY, "immune_system/benchmark.py"]),
    "demo":           ("Демонстрація до/після (Helios :8001 vs ЦІС :8000)",
                       [PY, "immune_system/demo_before_after.py"]),
    "metrics":        ("Зведені метрики (vs SIEM)",
                       [PY, "immune_system/metrics_summary.py"]),
    "defense_report": ("Звіт ефективності захисту",
                       [PY, "immune_system/defense_report.py"]),
    "coevolution":    ("Метрика ко-еволюції (щит vs меч, поколіннями)",
                       [PY, "immune_system/coevolution_report.py"]),
    "manifest":       ("Run-маніфест (git-commit + модель + зведення метрик)",
                       [PY, "utils/run_manifest.py"]),
    # ── Кроки кампанії: дві гілки прогону — без захисту vs із захистом ──
    "execute_baseline": ("Атаки проти СИРОГО Helios :8001 (BASELINE, без захисту)",
                         [PY, "core/red_team_agent.py", "all"],
                         {"HELIOS_BASE_URL": "http://localhost:8001",
                          "REDTEAM_REPORT_SUBDIR": "baseline", "REDTEAM_DEFENDED": "0"}),
    "execute_defended": ("Атаки ЧЕРЕЗ ЦІС-проксі :8000 (DEFENDED, із захистом)",
                         [PY, "core/red_team_agent.py", "all"],
                         {"HELIOS_BASE_URL": "http://localhost:8000",
                          "REDTEAM_REPORT_SUBDIR": "defended", "REDTEAM_DEFENDED": "1"}),
    "defense_report_baseline": ("Звіт: атаки проти НЕзахищеного Helios (baseline)",
                                [PY, "immune_system/defense_report.py", "--scope", "baseline"]),
    "defense_report_defended": ("Звіт ефективності ЦІС (defended, через проксі)",
                                [PY, "immune_system/defense_report.py", "--scope", "defended"]),
    "coevolution_defended": ("Ко-еволюція (defended): щит vs меч поколіннями",
                             [PY, "immune_system/coevolution_report.py", "--scope", "defended"]),
    "attack_flow":    ("Kill chain / attack_flow.json (для візуалізації)",
                       [PY, "core/attack_flow.py", "--scope", "defended"]),
    # ── Security-тести самої ЦІС (пишуть reports/security/<key>.json) ──
    "sec_fpr":     ("Security: false-positive rate (легіт-виборець)",
                    [PY, "immune_system/false_positive_test.py"]),
    "sec_heldout": ("Security: узагальнення на нові атаки",
                    [PY, "immune_system/held_out_attack_test.py"]),
    "sec_inject":  ("Security: стійкість до prompt injection",
                    [PY, "immune_system/prompt_injection_test.py"]),
    "sec_flood":   ("Security: стійкість до DoS на ШІ",
                    [PY, "immune_system/ai_flood_test.py"]),
    "redetection": ("Re-detection через імунну пам'ять (5.1)",
                    [PY, "immune_system/redetection_test.py"]),
}
# Канонічний порядок гранулярних кроків (clean — не тут: він лише модифікатор,
# що додається спереду за --clean, щоб випадково не стерти reports/).
ORDER = ["generate", "execute", "score", "ire",
         "benchmark", "demo", "defense_report", "coevolution", "metrics"]
# Кроки, що потребують піднятого проксі :8000
DEFENSE_STEPS = {"benchmark", "demo", "defense_report", "execute_defended",
                 "sec_fpr", "sec_heldout", "sec_inject", "sec_flood", "redetection"}
SECURITY_STEPS = ["sec_fpr", "sec_heldout", "sec_inject", "sec_flood"]

PRESETS = {
    "analyze": ["score", "ire", "metrics"],
    "defense": ["benchmark", "demo", "defense_report", "metrics"],
    "offense": ["generate", "execute", "score", "ire"],
    # campaign — ПОВНИЙ прогін, що наповнює ВЕСЬ дашборд однією командою:
    # генерація → атаки baseline(:8001) → атаки defended(:8000) → ризики → IRE →
    # бенчмарк(P/R/F1/ROC) → звіт baseline → звіт defended → ко-еволюція → метрики.
    # Проксі :8000 підіймається автоматично (execute_defended/benchmark його потребують).
    "campaign": ["generate", "execute_baseline", "execute_defended",
                 "score", "ire", "benchmark",
                 "sec_fpr", "sec_heldout", "sec_inject", "sec_flood", "redetection",
                 "defense_report_baseline", "defense_report_defended",
                 "coevolution_defended", "attack_flow", "metrics", "manifest"],
    # security — лише тести стійкості самої ЦІС (потребують проксі :8000)
    "security": ["sec_fpr", "sec_heldout", "sec_inject", "sec_flood",
                 "redetection", "metrics"],
    # coevolve — ко-еволюційний цикл: мутуємо атаки під блокування ЦІС (за DEFENDED-
    # результатами → escalate/refine/bypass) → виконуємо через проксі → метрика поколінь.
    # Передумова: вже є defended-звіти (з попереднього campaign). Потребує проксі :8000.
    "coevolve": ["adapt", "execute_defended", "defense_report_defended",
                 "coevolution_defended", "attack_flow"],
}


# ─── Допоміжне ────────────────────────────────────────────────────────────────

def _run(label: str, argv: list, env_extra: dict = None) -> int:
    print("\n" + "=" * 78)
    print(f"  ▶ {label}")
    if env_extra:
        print(f"    env: {' '.join(f'{k}={v}' for k, v in env_extra.items())}")
    print(f"    $ {' '.join(argv)}")
    print("=" * 78, flush=True)
    env = {**os.environ, **env_extra} if env_extra else None
    return subprocess.call(argv, cwd=str(ROOT), env=env)


def _url_up(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=1)
        return True
    except urllib.error.HTTPError:
        return True   # сервер відповів (хай навіть 4xx) → працює
    except Exception:
        return False


def start_proxy():
    """Піднімає immune_proxy :8000 у фоні. Повертає (proc | None, owned: bool).
    Якщо проксі вже працює — owned=False (не чіпаємо чужий процес)."""
    if _url_up(PROXY_STATS_URL):
        print("  ℹ️  Проксі вже працює на :8000 — використовую наявний.")
        return None, False
    print("  ▶ Стартую immune_proxy на :8000 (фон)...", flush=True)
    proc = subprocess.Popen([PY, "immune_system/immune_proxy.py"], cwd=str(ROOT))
    for _ in range(60):   # ~30с
        if _url_up(PROXY_STATS_URL):
            print("  ✓ Проксі готовий (:8000).", flush=True)
            return proc, True
        if proc.poll() is not None:
            raise RuntimeError("проксі впав під час старту (див. вивід вище)")
        time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("проксі не піднявся за 30с")


def stop_proxy(proc):
    if proc is None:
        return
    print("\n  ⏹  Гашу проксі :8000...", flush=True)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_steps(steps: list, keep_going: bool, with_defense: bool) -> int:
    """Виконує впорядкований список кроків. За потреби сам підіймає/гасить проксі."""
    need_proxy = with_defense and any(s in DEFENSE_STEPS for s in steps)
    proc, owned = None, False

    # попередження, якщо Helios :8001 не відповідає, а він знадобиться
    if any(s in DEFENSE_STEPS or s.startswith("execute") for s in steps) and not _url_up(HELIOS_URL):
        print("  ⚠️  Helios :8001 не відповідає — підніми його перед запуском "
              "(cd ~/helios-server && python manage.py runserver 8001).", file=sys.stderr)

    failed = []
    try:
        if need_proxy:
            proc, owned = start_proxy()
        for name in steps:
            spec = STEPS[name]
            label, argv = spec[0], spec[1]
            env_extra = spec[2] if len(spec) > 2 else None
            rc = _run(label, argv, env_extra)
            if rc != 0:
                failed.append((label, rc))
                print(f"\n  ⚠️  Крок завершився з кодом {rc}: {label}", file=sys.stderr)
                if not keep_going:
                    print("  Зупиняюсь (додай --keep-going, щоб продовжити).",
                          file=sys.stderr)
                    return rc
    finally:
        if owned:
            stop_proxy(proc)

    if failed:
        print(f"\n  Готово з помилками ({len(failed)}): "
              + "; ".join(l for l, _ in failed), file=sys.stderr)
        return 1
    print("\n  ✅ Готово.")
    return 0


def build_steps(args) -> list:
    """Будує впорядкований список кроків з пресету або гранулярних флагів."""
    # 1) гранулярні флаги мають пріоритет (clean — лише префікс-модифікатор)
    flagged = [s for s in ORDER if getattr(args, s)]
    if flagged:
        return (["clean"] + flagged) if args.clean else flagged
    # 2) інакше — пресет
    preset = args.preset
    if preset == "all":
        steps = list(PRESETS["offense"])
        steps += [s for s in PRESETS["defense"] if s not in steps]
    else:
        steps = list(PRESETS.get(preset, []))
    # модифікатори offense/all/campaign (clean ігнорується для analyze/defense)
    if preset in ("offense", "all", "campaign"):
        if args.skip_generate and "generate" in steps:
            steps.remove("generate")
        if args.skip_execute:
            for s in ("execute", "execute_baseline", "execute_defended"):
                if s in steps:
                    steps.remove(s)
        if args.clean:
            steps = ["clean"] + steps
    return steps


def main():
    p = argparse.ArgumentParser(
        prog="run_all.py", description="Оркестратор пайплайну ЦІС",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("preset", nargs="?", default="",
                   choices=["", "analyze", "defense", "offense", "campaign",
                            "security", "coevolve", "test", "all"],
                   help="пресет запуску")
    p.add_argument("--with-defense", action="store_true",
                   help="підняти immune_proxy :8000 у фоні навколо defense-кроків "
                        "(для campaign вмикається автоматично)")
    p.add_argument("--skip-generate", action="store_true")
    p.add_argument("--skip-execute", action="store_true")
    p.add_argument("--keep-going", action="store_true")
    # гранулярні кроки
    p.add_argument("--clean", action="store_true")
    p.add_argument("--generate", action="store_true")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--score", action="store_true")
    p.add_argument("--ire", action="store_true")
    p.add_argument("--benchmark", action="store_true")
    p.add_argument("--demo", action="store_true")
    p.add_argument("--metrics", action="store_true")
    p.add_argument("--defense-report", dest="defense_report", action="store_true")
    p.add_argument("--coevolution", action="store_true")
    args = p.parse_args()

    # test — окремо (просто pytest)
    if args.preset == "test":
        sys.exit(_run("Unit-тести (без серверів)", [PY, "-m", "pytest", "tests/"]))

    # campaign/security/coevolve самі керують проксі (кроки б'ють по :8000)
    if args.preset in ("campaign", "security", "coevolve"):
        args.with_defense = True

    steps = build_steps(args)
    if not steps:
        p.print_help()
        sys.exit(0)
    sys.exit(run_steps(steps, args.keep_going, args.with_defense))


if __name__ == "__main__":
    main()
