"""
Attack Flow / Kill Chain builder.
Digital immune system — core/attack_flow.py

Builds attack_flow.json from red_team defended reports: for EACH attack — the
sequence of kill-chain steps (Reconnaissance → Weaponization → Delivery →
Exploitation → Action) with a defense verdict on each step (blocked / passed /
simulated). This is the source for the kill-chain visualization in the dashboard
(sections 3.1, 4.5, 5.4).

Run:  python core/attack_flow.py [--scope defended|baseline]
Out:  reports/killchain/attack_flow.json
"""

import re
import sys
import json
import glob
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_config

_cfg = load_config()
ROOT = Path(_cfg.get("_root", Path(__file__).resolve().parent.parent))
REPORTS = ROOT / _cfg.get("paths", {}).get("reports_dir", "reports")

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
# ALL-CAPS placeholders that were not substituted in the scenario (TRUSTEE_UUID, VOTER_UUID…)
_PLACEHOLDER = re.compile(r"[A-Z][A-Z_]{3,}")
# critical (dangerous) operations — those "reaching Helios" is a real leak
CRITICAL_OPS = ("/cast", "/cast_confirm", "/upload-decryption", "/encrypt_tally", "/freeze")


def _mask(ep: str) -> str:
    if not ep:
        return "LOCAL"
    if "/" not in ep:          # LOCAL / NETWORK (simulation) — leave as is
        return ep[:48]
    ep = _UUID.sub("{id}", ep)
    ep = _PLACEHOLDER.sub("{id}", ep)   # unsubstituted placeholders → {id}
    return ep[:48]


def _verdict(r: dict) -> str:
    """blocked (403) | leaked (critical op reached) | allowed (safe step reached) |
    simulated | not_executed. We distinguish leaked/allowed so recon/login (normal)
    do not look like a leak — red is only for a DANGEROUS operation that reached Helios."""
    if r.get("is_simulated"):
        return "simulated"
    s = r.get("status_code")
    if s is None:
        return "not_executed"
    if s == 403:
        return "blocked"
    ep = r.get("endpoint", "") or ""
    is_crit = any(op in ep for op in CRITICAL_OPS)
    return "leaked" if is_crit else "allowed"   # critical op reached = leak; else normal


def build_flow(report: dict) -> dict:
    steps = []
    for i, e in enumerate(report.get("execution_log", []), 1):
        r = e["result"]
        v = _verdict(r)
        steps.append({
            "n": i,
            "phase": e.get("phase", "?"),
            "method": r.get("method", "?"),
            "endpoint": _mask(r.get("endpoint") or "LOCAL"),
            "status": r.get("status_code"),
            "verdict": v,
            "note": (r.get("attacker_note") or "")[:80],
        })
    summary = {k: sum(1 for s in steps if s["verdict"] == k)
               for k in ("blocked", "leaked", "allowed", "simulated", "not_executed")}
    return {
        "attack_id": report.get("attack_id"),
        "attack_class": report.get("attack_class"),
        "vector": report.get("vector", "system"),
        "name": report.get("name", ""),
        "mitre": report.get("mitre_technique_id", ""),
        "mitre_name": report.get("mitre_technique_name", ""),
        "adaptation_mode": report.get("adaptation_mode"),
        "steps": steps,
        "summary": summary,
    }


def main():
    ap = argparse.ArgumentParser(description="Attack Flow / Kill Chain builder")
    ap.add_argument("--scope", default="defended", choices=["defended", "baseline"])
    args = ap.parse_args()

    files = sorted(glob.glob(str(REPORTS / "attacks" / args.scope / "ATK*_report.json")))
    if not files:
        print(f"[-] Немає звітів у reports/attacks/{args.scope}/. Прожени campaign.")
        return
    # dedup by attack_class (latest) + adaptation_mode, to avoid duplicates
    flows = {}
    for f in files:
        try:
            rep = json.load(open(f, encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        key = (rep.get("attack_class"), bool(rep.get("adaptation_mode")))
        flows[key] = build_flow(rep)
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": args.scope,
        "attacks": sorted(flows.values(), key=lambda a: (a["vector"], a["attack_class"])),
    }
    out_dir = REPORTS / "killchain"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "attack_flow.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    tot = sum(a["summary"]["blocked"] for a in out["attacks"])
    leak = sum(a["summary"]["leaked"] for a in out["attacks"])
    print(f"  [+] reports/killchain/attack_flow.json — {len(out['attacks'])} атак")
    print(f"      кроків заблоковано: {tot} · крит-операцій дійшло (leaked): {leak}")


if __name__ == "__main__":
    main()
