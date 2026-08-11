"""
DIS pipeline orchestrator — one entry point instead of a manual sequence of commands.
Digital immune system — run_all.py

PRESETS (positional argument):
  analyze   Analysis of EXISTING data, WITHOUT servers or a key:
              risk_scorer → immune_response_engine → metrics_summary
            (generates and executes nothing — works on your reports/).

  defense   Defense check via ImmuneProxy (:8000):
              benchmark → demo_before_after → metrics_summary → defense_report
            Precondition: Helios on :8001. Proxy :8000 — either start it yourself, or
            add --with-defense (started in the background and stopped at the end).

  offense   OFFENSIVE run against RAW Helios (:8001):
              [clean] → [generate] → [execute] → score → ire
            generate/execute can be skipped (--skip-generate / --skip-execute),
            clean — only with an explicit --clean (as it wipes reports/).
            Preconditions: Helios :8001, ANTHROPIC_API_KEY in .env (for generate).

  campaign  FULL "without defense vs with defense" report in one command:
              generate → baseline attacks(:8001) → defended attacks(via proxy :8000)
              → baseline report → defended report → co-evolution
            Writes reports/attacks/{baseline,defended}/ separately; proxy :8000
            is started automatically. Precondition: Helios :8001 (+ key for generate).
            Skip generation: --skip-generate (take existing scenarios).

  test      Unit tests (pytest) — no servers or key.

  all       offense, then defense.

GRANULAR STEP FLAGS (if at least one is set — the preset is ignored, only the
selected steps run in canonical order):
  --clean --generate --execute --score --ire --benchmark --demo --metrics --defense-report

OTHER FLAGS:
  --with-defense   Start immune_proxy :8000 in the background around defense steps and stop it at the end
                   (if the proxy is already running — uses the existing one, does not touch it).
  --skip-generate  In the offense preset do not generate scenarios (use existing ones)
  --skip-execute   In the offense preset do not execute attacks (use existing reports/)
  --keep-going     Do not stop on the first error

Examples:
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
PY = sys.executable   # the same interpreter (venv)

PROXY_STATS_URL = "http://localhost:8000/__immune__/stats"
HELIOS_URL = "http://localhost:8001"

# Steps: name → (label, argv). Canonical order — in ORDER.
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
    # ── Campaign steps: two run branches — without defense vs with defense ──
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
    # ── Security tests of the DIS itself (write reports/security/<key>.json) ──
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
# Canonical order of granular steps (clean is not here: it is only a modifier
# prepended by --clean, so reports/ are not accidentally wiped).
ORDER = ["generate", "execute", "score", "ire",
         "benchmark", "demo", "defense_report", "coevolution", "metrics"]
# Steps that require the :8000 proxy running
DEFENSE_STEPS = {"benchmark", "demo", "defense_report", "execute_defended",
                 "sec_fpr", "sec_heldout", "sec_inject", "sec_flood", "redetection"}
SECURITY_STEPS = ["sec_fpr", "sec_heldout", "sec_inject", "sec_flood"]

PRESETS = {
    "analyze": ["score", "ire", "metrics"],
    "defense": ["benchmark", "demo", "defense_report", "metrics"],
    "offense": ["generate", "execute", "score", "ire"],
    # campaign — a FULL run that fills the ENTIRE dashboard with one command:
    # generate → baseline attacks(:8001) → defended attacks(:8000) → risks → IRE →
    # benchmark(P/R/F1/ROC) → baseline report → defended report → co-evolution → metrics.
    # The :8000 proxy is started automatically (execute_defended/benchmark need it).
    "campaign": ["generate", "execute_baseline", "execute_defended",
                 "score", "ire", "benchmark",
                 "sec_fpr", "sec_heldout", "sec_inject", "sec_flood", "redetection",
                 "defense_report_baseline", "defense_report_defended",
                 "coevolution_defended", "attack_flow", "metrics", "manifest"],
    # security — only resilience tests of the DIS itself (need the :8000 proxy)
    "security": ["sec_fpr", "sec_heldout", "sec_inject", "sec_flood",
                 "redetection", "metrics"],
    # coevolve — the co-evolution cycle: mutate attacks under DIS blocking (from DEFENDED
    # results → escalate/refine/bypass) → run through the proxy → the generations metric.
    # Precondition: defended reports already exist (from a prior campaign). Needs the :8000 proxy.
    "coevolve": ["adapt", "execute_defended", "defense_report_defended",
                 "coevolution_defended", "attack_flow"],
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

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
        return True   # the server responded (even a 4xx) → it works
    except Exception:
        return False


def start_proxy():
    """Start immune_proxy :8000 in the background. Returns (proc | None, owned: bool).
    If the proxy is already running — owned=False (do not touch someone else's process)."""
    if _url_up(PROXY_STATS_URL):
        print("  ℹ️  Проксі вже працює на :8000 — використовую наявний.")
        return None, False
    print("  ▶ Стартую immune_proxy на :8000 (фон)...", flush=True)
    proc = subprocess.Popen([PY, "immune_system/immune_proxy.py"], cwd=str(ROOT))
    for _ in range(60):   # ~30s
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
    """Run the ordered list of steps. Starts/stops the proxy itself if needed."""
    need_proxy = with_defense and any(s in DEFENSE_STEPS for s in steps)
    proc, owned = None, False

    # warn if Helios :8001 is not responding but will be needed
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
    """Build the ordered list of steps from a preset or granular flags."""
    # 1) granular flags take priority (clean — only a prefix modifier)
    flagged = [s for s in ORDER if getattr(args, s)]
    if flagged:
        return (["clean"] + flagged) if args.clean else flagged
    # 2) otherwise — a preset
    preset = args.preset
    if preset == "all":
        steps = list(PRESETS["offense"])
        steps += [s for s in PRESETS["defense"] if s not in steps]
    else:
        steps = list(PRESETS.get(preset, []))
    # offense/all/campaign modifiers (clean is ignored for analyze/defense)
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
    # granular steps
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

    # test — separate (just pytest)
    if args.preset == "test":
        sys.exit(_run("Unit-тести (без серверів)", [PY, "-m", "pytest", "tests/"]))

    # campaign/security/coevolve manage the proxy themselves (steps hit :8000)
    if args.preset in ("campaign", "security", "coevolve"):
        args.with_defense = True

    steps = build_steps(args)
    if not steps:
        p.print_help()
        sys.exit(0)
    sys.exit(run_steps(steps, args.keep_going, args.with_defense))


if __name__ == "__main__":
    main()
