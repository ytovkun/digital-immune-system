"""
Module: DefenseReport — DIS defense effectiveness report
Digital immune system — immune_system/defense_report.py

Measures the CORRECT metric: did a DANGEROUS operation reach Helios,
not "did the attacker finish their script" (the red_team_agent verdict).

Logic:
  - critical operations = POST to /cast, /cast_confirm, /upload-decryption,
    /encrypt_tally (these cause the harm: ballot stuffing, key swap)
  - for each attack: how many critical operations were BLOCKED (403) by the
    proxy, how many reached Helios, how many are absent (attack off-server)

Sources:
  reports/ATK*_report.json   — attack steps and their HTTP statuses
  logs/immune_blocks.jsonl   — proxy decisions (who, what, at which tier)

Run:  python immune_system/defense_report.py
Out:  table + reports/defense_effectiveness_{ts}.json
"""

import sys

import argparse
import json
import glob
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS_DIR = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")
LOGS_DIR    = ROOT / _cfg.get("paths", {}).get("logs_dir", "logs")
BLOCKS_LOG  = LOGS_DIR / "immune_blocks.jsonl"

# Critical operations — these cause the real harm. Kept in sync with
# ai_analyst.CRITICAL_ENDPOINTS / attack_flow.CRITICAL_OPS (incl. /freeze).
CRITICAL_OPS = ("/cast", "/cast_confirm", "/upload-decryption", "/encrypt_tally", "/freeze")


def _dis_blocked(r: dict) -> bool:
    """Whether a 403 was returned by the immune PROXY (not a Helios/Django 403,
    e.g. a CSRF rejection). Only a DIS-origin 403 counts as a defense block —
    otherwise the metric would credit the DIS for Helios's own rejections."""
    if r.get("status_code") != 403:
        return False
    body = r.get("response_preview") or ""
    return "Immune" in body or "Digital Immune System" in body


# Markers of a Helios HTML framework page (login / view / error / confirm shell).
# A critical operation that actually COMMITTED never returns such a page — a real
# /cast success is a 302 redirect to the ballot board, and access control for a
# private election returns the "Log In to View Election" shell. So a 2xx carrying
# this shell is NOT proof of execution.
_HELIOS_SHELL_MARKERS = ("<!doctype html", "no-js", "foundation",
                         "log in to view election")


def _executed_at_backend(r: dict) -> bool:
    """Positive evidence a critical op actually EXECUTED at Helios.

    HTTP status alone cannot prove it, and this was the core reporting bug:
      * a private-election access-control page returns 200 with the Helios shell
        ("Log In to View Election") — nothing executed;
      * a staged / rejected /cast returns a 302 redirect — nothing committed.
    So a critical op counts as executed ONLY when the response is a 2xx that is
    NOT the Helios HTML shell (e.g. a real JSON data dump = disclosure). A 302 or
    any HTML shell never counts. Real ballot commits are confirmed out-of-band via
    vote_hash comparison (helios_ballot_count --hashes), not via status here."""
    if r.get("status_code") not in (200, 201):
        return False
    body = (r.get("response_preview") or "").lower()
    if any(m in body for m in _HELIOS_SHELL_MARKERS):
        return False
    return True

# Attacks that by nature are NOT blocked at the server proxy
# (they happen between people, in the victim's browser, or at the network level)
OFF_SERVER_CLASSES = {
    "voter_timing_deanonymization":  "мережевий рівень (ISP-перехоплення)",
    "voter_coercion_receipt":        "примус між людьми (поза сервером)",
    "voter_device_js_injection":     "браузер жертви (до сервера)",
}


def load_blocks() -> list:
    blocks = []
    if BLOCKS_LOG.exists():
        for line in BLOCKS_LOG.read_text(encoding="utf-8").splitlines():
            try:
                blocks.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return blocks


def analyze_report(report: dict) -> dict:
    """Classify each critical operation by outcome (source-aware, honest):
      crit_blocked — prevented by the DIS: a proxy 403, OR None (chain broken by an
                     earlier DIS block so the crit step never ran);
      crit_reached — LEAKED: a SUCCESSFUL backend response (2xx/3xx), i.e. the
                     dangerous op actually executed and returned;
      crit_other   — neither: a non-DIS 403 (Helios/CSRF rejection), 404 (endpoint
                     absent) or 5xx (server error) — the op did NOT execute, but it
                     was NOT a DIS block either. Counting these as "leaked" (old bug)
                     overstated leaks; crediting the DIS for them overstated blocks.
    NOTE: a 2xx does not by itself prove a real ballot was cast — confirm baseline
    effect against the Helios DB (ballot count before/after)."""
    crit_blocked = crit_reached = crit_other = 0
    crit_steps = []
    # A None status (request errored / never ran) counts as a DIS block ONLY if the
    # chain was actually broken by an earlier proxy 403 — otherwise it is just a
    # failed request and must not be credited to the defense.
    has_dis_block = any(_dis_blocked(e.get("result", {}))
                        for e in report.get("execution_log", []))
    for entry in report.get("execution_log", []):
        r = entry["result"]
        ep = r.get("endpoint", "") or ""
        if r.get("is_simulated"):
            continue
        if any(op in ep for op in CRITICAL_OPS):
            status = r.get("status_code")
            op_name = ep.rstrip("/").split("/")[-1]
            if _dis_blocked(r):
                crit_blocked += 1
                crit_steps.append(f"{op_name}:DIS-БЛОК")
            elif status is None and has_dis_block:
                crit_blocked += 1
                crit_steps.append(f"{op_name}:обірвано(після DIS-блоку)")
            elif _executed_at_backend(r):
                crit_reached += 1
                crit_steps.append(f"{op_name}:{status}⚠виконано")
            else:
                # login-page 200, 302 redirect, 4xx/5xx, non-DIS 403, or a failed
                # request with no preceding DIS block → NOT demonstrably executed.
                crit_other += 1
                lbl = status if status is not None else "err"
                crit_steps.append(f"{op_name}:{lbl}(не виконано)")
    return {
        "attack_class":  report.get("attack_class"),
        "vector":        report.get("vector", "system"),
        "agent_verdict": report.get("verdict", "?"),
        "crit_blocked":  crit_blocked,
        "crit_reached":  crit_reached,
        "crit_other":    crit_other,
        "crit_total":    crit_blocked + crit_reached + crit_other,
        "crit_steps":    crit_steps,
    }


def classify_defense(a: dict) -> str:
    """
    Final defense status for an attack:
      NEUTRALIZED — DIS blocked the critical op(s), none leaked
      PARTIAL_BLOCK — some blocked, some leaked
      LEAKED      — a critical op reached Helios and executed (2xx/3xx), no DIS block
      OFF_SERVER / NO_CRITICAL — no critical HTTP that either leaked or was DIS-blocked
    """
    if a["crit_total"] == 0:
        return "OFF_SERVER" if a["attack_class"] in OFF_SERVER_CLASSES else "NO_CRITICAL"
    if a["crit_reached"] == 0:
        # no proven leak; a DIS block present → neutralized, else nothing decisive
        return "NEUTRALIZED" if a["crit_blocked"] > 0 else "NO_CRITICAL"
    if a["crit_blocked"] > 0:
        return "PARTIAL_BLOCK"
    return "LEAKED"


SCOPED_SUBDIRS = ("baseline", "defended")   # campaign sets (viewed with --scope)


def _collect_reports(scope: str) -> list:
    """Reports by scope: scope='baseline'|'defended' → only reports/attacks/<scope>/;
    empty scope → all, BUT WITHOUT campaign sets (so baseline+defended are not mixed).
    EXCLUDE adaptive reports (*_adaptive_report.json): this report measures
    EFFECTIVENESS on the BASE attack set (so bypass attacks with 0 crit ops do not
    "overwrite" base ones during per-class dedup). Evolution (gen-1) is measured by
    coevolution_report."""
    if scope:
        base = REPORTS_DIR / "attacks" / scope
        files = glob.glob(str(base / "**" / "ATK*_report.json"), recursive=True)
    else:
        files = glob.glob(str(REPORTS_DIR / "**" / "ATK*_report.json"), recursive=True)
        files = [f for f in files
                 if not any(f"{os.sep}attacks{os.sep}{s}{os.sep}" in f for s in SCOPED_SUBDIRS)]
    files = [f for f in files if not f.endswith("_adaptive_report.json")]
    return sorted(files, key=os.path.getmtime)


def _scoped_sets_exist() -> list:
    return [s for s in SCOPED_SUBDIRS if (REPORTS_DIR / "attacks" / s).is_dir()]


def main():
    ap = argparse.ArgumentParser(description="Звіт ефективності захисту ЦІС")
    ap.add_argument("--scope", default=os.environ.get("DEFENSE_SCOPE", ""),
                    help="baseline | defended (підпапка reports/attacks/); порожньо = усі")
    args = ap.parse_args()
    scope = args.scope.strip()

    reports = _collect_reports(scope)
    if not scope and _scoped_sets_exist():
        print(f"  ℹ️  Виявлено campaign-набори ({', '.join(_scoped_sets_exist())}) — вони "
              f"НЕ включені у цей «загальний» звіт. Дивись їх окремо: "
              f"--scope baseline / --scope defended.")
    if not reports:
        where = f"reports/attacks/{scope}/" if scope else "reports/ (поза campaign-наборами)"
        print(f"[-] Немає звітів атак у {where}. Спочатку прожени red_team_agent "
              f"(для defended — через проксі :8000).")
        return
    scope_label = {"baseline": "БЕЗ ЗАХИСТУ (сирий Helios :8001)",
                   "defended": "ІЗ ЗАХИСТОМ (через ЦІС-проксі :8000)"}.get(scope, "усі звіти")

    blocks = load_blocks()
    analyses = [analyze_report(json.load(open(f, encoding="utf-8"))) for f in reports]

    # Deduplication: the latest report per class
    by_class = {}
    for a in analyses:
        by_class[a["attack_class"]] = a
    analyses = list(by_class.values())

    STATUS_ICON = {
        "NEUTRALIZED":   "🛡  НЕЙТРАЛІЗОВАНО",
        "PARTIAL_BLOCK": "⚠️  ЧАСТКОВО",
        "LEAKED":        "🔴 ПРОПУЩЕНО",
        "OFF_SERVER":    "🌐 ПОЗА СЕРВЕРОМ",
        "NO_CRITICAL":   "—  немає критичних",
    }

    print("=" * 84)
    print("  🛡  ЕФЕКТИВНІСТЬ ЗАХИСТУ ЦІС — чи дійшла небезпечна операція до Helios")
    print(f"  Режим: {scope_label}  ({len(analyses)} атак)")
    print("=" * 84)
    print(f"  {'Атака':<40} {'Критич.оп':<11} {'Захист':<18} Agent")
    print(f"  {'─'*80}")

    counts = Counter()
    for grp, label in [("system", "🖥  SYSTEM"), ("voter", "👤 VOTER")]:
        grp_items = [a for a in analyses if a["vector"] == grp]
        if not grp_items:
            continue
        print(f"\n  ── {label} ──")
        for a in sorted(grp_items, key=lambda x: x["attack_class"]):
            status = classify_defense(a)
            counts[status] += 1
            crit = f"{a['crit_blocked']}/{a['crit_total']} блок" if a["crit_total"] else "немає"
            icon = STATUS_ICON.get(status, status)
            print(f"  {a['attack_class']:<40} {crit:<11} {icon:<18} {a['agent_verdict']}")

    print(f"\n  {'─'*80}")

    # ─── Summary ────────────────────────────────────────────────────────────────
    neutralized = counts["NEUTRALIZED"]
    partial     = counts["PARTIAL_BLOCK"]
    off_server  = counts["OFF_SERVER"]        # network/browser/human — NOT NO_CRITICAL
    no_critical = counts["NO_CRITICAL"]       # crit op present but nothing executed/blocked
    total       = len(analyses)
    crit_blocked_total = sum(a["crit_blocked"] for a in analyses)
    crit_reached_total = sum(a["crit_reached"] for a in analyses)
    crit_other_total   = sum(a.get("crit_other", 0) for a in analyses)
    # A real leak = ANY attack with a demonstrably executed critical op — this
    # includes PARTIAL_BLOCK (some blocked, some executed), which the old "leaked =
    # counts['LEAKED']" silently dropped, letting the manifest print leaked=0.
    leaked_attacks = sum(1 for a in analyses if a["crit_reached"] > 0)

    print("  📊 ПІДСУМОК ЗАХИСТУ")
    print(f"     🛡  Нейтралізовано (критична операція заблокована DIS): {neutralized}/{total}")
    if partial:
        print(f"     🟡 Частково (частину заблоковано, частину виконано): {partial}/{total}")
    print(f"     🔴 Виконано у Helios (2xx з реальними даними; ПІДТВЕРДЖУЙ vote_hash): "
          f"{leaked_attacks}/{total}")
    print(f"     🌐 Поза зоною серверного захисту (мережа/браузер/люди): {off_server}/{total}")
    if no_critical:
        print(f"     ◻️  Без крит-ефекту (крит-оп була, але НЕ виконалась і не DIS-блок): "
              f"{no_critical}/{total}")
    if crit_other_total:
        print(f"        (крит-кроків 'не виконано' — сторінка логіну/302/4xx/5xx: {crit_other_total})")
    # Explicit list of "off-server" ONLY — network/browser/human-level attacks the
    # proxy does not intercept by definition (a boundary of applicability, not a hole).
    # tally_manipulation etc. are NO_CRITICAL, NOT off-server, and are listed apart.
    off_classes = sorted({a["attack_class"] for a in analyses
                          if classify_defense(a) == "OFF_SERVER"})
    nocrit_classes = sorted({a["attack_class"] for a in analyses
                             if classify_defense(a) == "NO_CRITICAL"})
    if off_classes:
        print("     ↳ поза сервером (за визначенням, не «дірки»): " + ", ".join(off_classes))
    if nocrit_classes:
        print("     ↳ без підтвердженого крит-ефекту (Helios сам відхилив): "
              + ", ".join(nocrit_classes))
    print(f"\n     Небезпечних операцій заблоковано: {crit_blocked_total}/"
          f"{crit_blocked_total + crit_reached_total} "
          f"({crit_blocked_total/(crit_blocked_total+crit_reached_total)*100:.0f}%)"
          if (crit_blocked_total + crit_reached_total) else "")

    # ─── Proxy statistics ───────────────────────────────────────────────────────
    if blocks:
        by_tier = Counter(b.get("tier", "?") for b in blocks)
        by_attack = Counter(b.get("attack_class", "?") for b in blocks)
        print(f"\n  ⚡ РІШЕННЯ ПРОКСІ ({len(blocks)} блоків):")
        for tier, c in by_tier.most_common():
            label = "ШІ-аналітик (L2)" if tier == "AIAnalyst" else "FastReflex (L1)"
            print(f"     {label}: {c}")
        print(f"     За класами: {dict(by_attack)}")

    print("=" * 84)
    print("\n  💡 Чому вердикт red_team_agent інший: він міряє «чи закінчив атакувальник")
    print("     скрипт» (рахуючи безпечну розвідку+логін), а ЦІС блокує лише НЕБЕЗПЕЧНУ")
    print("     операцію. Розвідка проходить — вкидання голосу НІ.")

    # ─── Saving ─────────────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope or "all",
        "mode": scope_label,
        "total_attacks": total,
        "summary": {
            "neutralized": neutralized,
            "partial":     partial,
            "off_server":  off_server,
            "no_critical": no_critical,
            "leaked":      leaked_attacks,   # attacks with ANY executed crit op (incl PARTIAL)
            "critical_ops_blocked":  crit_blocked_total,
            "critical_ops_reached":  crit_reached_total,
            "critical_ops_other":    crit_other_total,
        },
        "proxy_blocks": len(blocks),
        "proxy_by_tier": dict(Counter(b.get("tier", "?") for b in blocks)),
        "attacks": [
            {**a, "defense_status": classify_defense(a)} for a in analyses
        ],
    }
    defense_dir = REPORTS_DIR / "defense"
    defense_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{scope}_" if scope else ""   # baseline/defended do not overwrite each other
    out_path = defense_dir / f"defense_effectiveness_{tag}{ts}.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n  [+] Звіт збережено: {out_path}")

    # ─── Dissertation table (.txt) ──────────────────────────────────────────────
    STATUS_TXT = {
        "NEUTRALIZED": "НЕЙТРАЛІЗОВАНО", "PARTIAL_BLOCK": "ЧАСТКОВО",
        "LEAKED": "ПРОПУЩЕНО", "OFF_SERVER": "ПОЗА СЕРВЕРОМ", "NO_CRITICAL": "немає критич.",
    }
    tbl = [
        "ТАБЛИЦЯ — Ефективність захисту ЦІС (defense-in-depth)",
        f"            Режим: {scope_label}",
        "            (чи ВИКОНАЛАСЬ небезпечна операція у Helios, а не «чи завершив скрипт»;",
        "             реальний ефект підтверджується порівнянням vote_hash, не HTTP-статусом)",
        "",
        f"{'№':<3} {'Атака':<38} {'Вектор':<8} {'Крит.оп(блок/усього)':<22} {'Статус захисту':<16} Agent",
        "─" * 100,
    ]
    for i, a in enumerate(sorted(analyses, key=lambda x: (x["vector"], x["attack_class"])), 1):
        st = STATUS_TXT.get(classify_defense(a), classify_defense(a))
        crit = f"{a['crit_blocked']}/{a['crit_total']}" if a["crit_total"] else "немає"
        tbl.append(f"{i:<3} {a['attack_class']:<38} {a['vector']:<8} {crit:<22} {st:<16} {a['agent_verdict']}")
    tbl.append("─" * 100)
    denom = crit_blocked_total + crit_reached_total
    pct = f"{crit_blocked_total/denom*100:.0f}%" if denom else "—"
    tbl += [
        f"Нейтралізовано: {neutralized}/{total} | Частково: {partial}/{total} | "
        f"Поза сервером: {off_server}/{total} | Без крит-ефекту: {no_critical}/{total} | "
        f"Виконано (vote_hash!): {leaked_attacks}/{total}",
        f"Небезпечних операцій заблоковано DIS: {crit_blocked_total}/{denom} ({pct})",
        "",
        "Примітки: критичні операції = POST /cast, /cast_confirm, /upload-decryption,",
        "  /encrypt_tally, /freeze. «Поза сервером» — атаки мережевого/браузерного/",
        "  людського рівня (не перехоплюються проксі за визначенням). «Без крит-ефекту» —",
        "  крит-оп була, але Helios сам її відхилив (сторінка логіну/302/5xx), не DIS.",
        "  «Виконано» підтверджується ПОРІВНЯННЯМ vote_hash до/після, а не HTTP-статусом.",
    ]
    (defense_dir / f"defense_table_{tag}{ts}.txt").write_text("\n".join(tbl), encoding="utf-8")
    print(f"  [+] Таблиця для дисертації: reports/defense/defense_table_{tag}{ts}.txt")


if __name__ == "__main__":
    main()
