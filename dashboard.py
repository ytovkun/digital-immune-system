"""
Visual dashboard of the digital immune system (Streamlit).
Digital immune system — dashboard.py

Reads reports from reports/ (attacks/ risk/ benchmark/ metrics/ defense/ ire/)
and draws tables, charts, the ROC curve and the confusion matrix — visually for the defense.

Run:  streamlit run dashboard.py
(requires: pip install -r requirements.txt)
"""

import glob
import json
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"

st.set_page_config(page_title="Цифрова імунна система — дашборд",
                   page_icon="🛡", layout="wide")

RISK_COLORS = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#f1c40f",
               "LOW": "#2ca02c", "Critical": "#d62728", "High": "#ff7f0e",
               "Medium": "#f1c40f", "Low": "#2ca02c"}

# Ordering of levels/urgency for "worst-first" table sorting.
# IMPORTANT: without this, sorting rows by text would give ALPHABETICAL order
# (Critical, High, Low, Medium — meaningless); here — by real criticality.
LEVEL_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
               "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
URGENCY_ORDER = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _rank(mapping: dict, val) -> int:
    """Rank of a value for sorting (unknown → to the end)."""
    return mapping.get(str(val), 99)


# ─── Loading reports ──────────────────────────────────────────────────────────

def _latest(subdir: str, pattern: str):
    files = sorted(glob.glob(str(REPORTS / subdir / pattern)))
    if not files:
        return None, None
    p = files[-1]
    try:
        return json.load(open(p, encoding="utf-8")), Path(p).name
    except Exception:
        return None, Path(p).name


# ─── Header ───────────────────────────────────────────────────────────────────

st.title("🛡 Цифрова імунна система — результати")
st.caption("GenAI-моделювання кіберзагроз + inline-захист Helios e-voting · "
           "дані з `reports/` (останні прогони)")

bench, bench_f   = _latest("benchmark", "benchmark_*.json")
risk, risk_f     = _latest("risk", "risk_assessment_*.json")
ire, ire_f       = _latest("ire", "ire_report_*.json")
metrics, met_f   = _latest("metrics", "metrics_summary_*.json")
# Defense: separately "without defense" (baseline) and "with defense" (defended) — for comparison.
# Fallback to the generic pattern (legacy runs without scope).
defense_def, defd_f  = _latest("defense", "defense_effectiveness_defended_*.json")
defense_base, defb_f = _latest("defense", "defense_effectiveness_baseline_*.json")
defense, def_f = (defense_def, defd_f) if defense_def else _latest(
    "defense", "defense_effectiveness_*.json")
# Co-evolution (shield vs sword across generations)
coevo, coevo_f = _latest("coevolution", "coevolution_defended_*.json")
if not coevo:
    coevo, coevo_f = _latest("coevolution", "coevolution_*.json")
# SIEM (Suricata/Wazuh) vs DIS — a measured comparison on one dataset
siem, siem_f = _latest("siem", "siem_comparison_*.json")
# Kill chain / attack flow (sections 3.1, 4.5, 5.4)
killchain, kc_f = _latest("killchain", "attack_flow.json")
# Re-detection through immune memory (section 5.1)
redetect, rd_f = _latest("redetection", "redetection_*.json")


# ─── KPI row ──────────────────────────────────────────────────────────────────

st.markdown("**🛡 Із захистом (ЦІС) — класифікаційні метрики:**")
c1, c2, c3, c4, c5 = st.columns(5)
if bench:
    m = bench.get("metrics", {})
    c1.metric("Precision", f"{m.get('precision', 0):.2f}")
    c2.metric("Recall", f"{m.get('recall', 0):.2f}")
    c3.metric("F1", f"{m.get('f1', 0):.2f}")
    # headline — the realistic combined ROC (main+borderline), not the "ideal" 1.0
    c4.metric("ROC-AUC (реаліст.)", f"{bench.get('roc_auc_combined') or bench.get('roc_auc') or 0:.3f}",
              help="Комбінований ROC (основна+гранична вибірка) — чесніший за точковий 1.0")
    c5.metric("FPR", f"{m.get('fpr', 0):.2f}")
else:
    st.info("Немає бенчмарку — прожени `python immune_system/benchmark.py` (з проксі).")

# ── "Without defense" (raw Helios) — key indicators for contrast on screen 1 ──
if defense_base:
    sb = defense_base.get("summary", {})
    _bb = sb.get("critical_ops_blocked", 0)
    _br = sb.get("critical_ops_reached", 0)
    _tot = _bb + _br
    st.markdown("**🔴 Без захисту (сирий Helios) — ті самі атаки прямо в :8001:**")
    n1, n2, n3, n4 = st.columns(5)[:4]
    n1.metric("Детекція атак", "0%",
              help="Сирий Helios не має детектора загроз — не блокує нічого")
    n2.metric("🔴 Крит-операцій дійшло", f"{_br}/{_tot}" if _tot else "—",
              help="Небезпечні операції (cast/tally/…), що досягли Helios без захисту")
    n3.metric("Заблоковано", f"{_bb}/{_tot}" if _tot else "0")
    n4.metric("Витоків (leaked)", _br)
    st.caption("Контраст: без захисту небезпечні операції проходять; із ЦІС — "
               "0 витоків, усі крит-операції блоковано (деталі: вкладка «🔬 Ефективність захисту»).")

st.divider()

tabs = st.tabs(["⚠️ Ризики", "📈 Бенчмарк + ROC", "🧬 Класифікація (IRE)",
                "🔬 Ефективність захисту", "🧬 Ко-еволюція", "🎯 Kill Chain",
                "🛡 Attack Surface", "⏱ Метрики vs SIEM", "✅ Легітимна поведінка",
                "📡 Live"])


# ─── TAB 1: Risks ─────────────────────────────────────────────────────────────

with tabs[0]:
    st.subheader("Кількісна оцінка ризиків атак")
    if not risk:
        st.info("Немає risk_assessment — прожени `python core/risk_scorer.py`.")
    else:
        scores = risk.get("scores", [])
        # column order: identifier → level/score → type/vector → factors
        df = pd.DataFrame([{
            "Клас атаки": s["attack_class"],
            "Рівень": s.get("risk_level", ""),
            "Score": s.get("composite_score", 0),
            "Тип": "адаптивна" if s.get("is_adaptive") else "базова",
            "Вектор": s.get("vector", ""),
            "STRIDE": s.get("stride_category", ""),
            "CIA": s.get("components", {}).get("cia", 0),
            "LINDDUN": s.get("components", {}).get("linddun", 0),
            "Exec": s.get("components", {}).get("exec_f", 0),
        } for s in scores])

        _n_base = sum(1 for s in scores if not s.get("is_adaptive"))
        _n_adap = sum(1 for s in scores if s.get("is_adaptive"))
        a, b = st.columns(2)
        a.metric("Середній ризик", f"{risk.get('summary', {}).get('avg_score', 0):.2f}/10")
        b.metric("Атак оцінено", risk.get("total", len(scores)),
                 help="Кількість АТАК (сценаріїв): базові + адаптивні (кожна версія окремо). "
                      "Не плутати з крит-операціями у вкладці «Ефективність захисту».")
        st.caption(f"Атак оцінено: {risk.get('total', len(scores))} = "
                   f"{_n_base} базових + {_n_adap} адаптивних (gen-0 + gen-1).")

        with st.expander("📐 Методологія оцінки ризику (OWASP Risk Rating) — фактори та формула"):
            st.markdown(
                "**Формула** (`core/risk_scorer.py`):\n\n"
                "`Risk = (CIA×0.35 + LINDDUN×0.25 + MITRE×0.15 + Execution×0.25) × Severity × 10`\n\n"
                "Це канонічний **OWASP Risk Rating**: `Risk = Likelihood × Impact`, де\n"
                "- **Impact** = технічний вплив **CIA** (Confidentiality/Integrity/Availability) "
                "+ приватнісний **LINDDUN** (деанонімізація виборця);\n"
                "- **Likelihood** = **Execution** (спостережувана успішність атаки у прогонах) "
                "× **MITRE** (зрілість техніки ATT&CK);\n"
                "- **Severity** — категорійний множник під критичність e-voting.\n\n"
                "**Чому OWASP Risk Rating, а не CVSS:** CVSS оцінює серйозність *окремої "
                "вразливості* (статичний бал), а нам треба ризик *реалізованого сценарію атаки* "
                "з урахуванням **успішності** у прогонах та **приватності** виборця (LINDDUN) — "
                "це саме сфера OWASP Risk Rating. CVSS застосовний на рівні `VULN-xx`. "
                "Деталі — `docs/RISK_AND_COVERAGE.md`.")

        # chart: score by class, base vs adaptive
        chart = alt.Chart(df).mark_bar().encode(
            x=alt.X("Score:Q", title="Композитний ризик-скор (0–10)"),
            y=alt.Y("Клас атаки:N", sort="-x", title=None),
            color=alt.Color("Тип:N", scale=alt.Scale(
                domain=["базова", "адаптивна"], range=["#4c78a8", "#e45756"])),
            yOffset="Тип:N",
            tooltip=["Клас атаки", "Тип", "Score", "Рівень", "STRIDE"],
        ).properties(height=max(300, 26 * df["Клас атаки"].nunique()))
        st.altair_chart(chart, use_container_width=True)

        # worst-first: by composite risk ↓, tie-break — by criticality level
        _df = df.assign(_lvl=df["Рівень"].map(lambda v: _rank(LEVEL_ORDER, v)))
        _df = _df.sort_values(["Score", "_lvl"], ascending=[False, True]).drop(columns="_lvl")
        st.dataframe(_df, use_container_width=True, hide_index=True)
        st.caption("↓ Відсортовано за спаданням композитного ризику (найкритичніші зверху).")
        st.caption(f"Джерело: reports/risk/{risk_f}")


# ─── TAB 2: Benchmark + ROC ───────────────────────────────────────────────────

with tabs[1]:
    st.subheader("Класифікаційні метрики захисту")
    if not bench:
        st.info("Немає бенчмарку.")
    else:
        cm = bench.get("confusion_matrix", {})
        m = bench.get("metrics", {})
        ci = bench.get("confidence_intervals_95_wilson", {})

        left, right = st.columns(2)

        with left:
            st.markdown("**Матриця плутанини**")
            cm_df = pd.DataFrame(
                [[cm.get("TP", 0), cm.get("FN", 0)],
                 [cm.get("FP", 0), cm.get("TN", 0)]],
                index=["факт ATTACK", "факт LEGIT"],
                columns=["передбач. ATTACK", "передбач. LEGIT"])
            st.table(cm_df)

            def _ci(name):
                lo, hi = (ci.get(name) or [None, None])
                return f"  (95% ДІ [{lo:.3f}, {hi:.3f}])" if lo is not None else ""
            st.markdown(
                f"- **Precision:** {m.get('precision',0):.3f}{_ci('precision')}\n"
                f"- **Recall:** {m.get('recall',0):.3f}{_ci('recall')}\n"
                f"- **F1:** {m.get('f1',0):.3f}\n"
                f"- **Accuracy:** {m.get('accuracy',0):.3f}{_ci('accuracy')}\n"
                f"- **FPR:** {m.get('fpr',0):.3f}  ·  **FNR:** {m.get('fnr',0):.3f}")

        with right:
            st.markdown(f"**ROC-крива** (AUC = {bench.get('roc_auc') or 0:.3f})")
            pts = bench.get("roc_points", [])
            if pts:
                roc_df = pd.DataFrame(pts).rename(
                    columns={"fpr": "FPR", "tpr": "TPR"}).sort_values("FPR")
                base = alt.Chart(roc_df).mark_line(point=True, color="#e45756").encode(
                    x=alt.X("FPR:Q", scale=alt.Scale(domain=[0, 1])),
                    y=alt.Y("TPR:Q", scale=alt.Scale(domain=[0, 1])),
                    tooltip=["FPR", "TPR", "threshold"])
                diag = alt.Chart(pd.DataFrame({"FPR": [0, 1], "TPR": [0, 1]})).mark_line(
                    strokeDash=[5, 5], color="gray").encode(x="FPR", y="TPR")
                st.altair_chart((diag + base).properties(height=340),
                                use_container_width=True)
            else:
                st.info("Немає ROC-точок (онови бенчмарк).")
        # n breakdown (Recall/FPR denominators) — from report fields or the confusion matrix
        _na = bench.get("n_attack", cm.get("TP", 0) + cm.get("FN", 0))
        _nl = bench.get("n_legit", cm.get("FP", 0) + cm.get("TN", 0))
        st.caption(f"Зразків: {bench.get('samples')} "
                   f"(**атак n={_na}** — знаменник Recall · **легіт n={_nl}** — знаменник FPR)"
                   f"  ·  Джерело: reports/benchmark/{bench_f}")

        st.warning(
            f"⚠️ **Обмеження вибірки.** n={bench.get('samples')} — обмежений; точкові "
            f"метрики (напр. 1.0) НЕ слід читати як генеральну оцінку «завжди 1.0». "
            f"Істинне значення — в **95% ДІ Вілсона** (див. вище), а реалістичний "
            f"показник дискримінації — **комбінований ROC = "
            f"{bench.get('roc_auc_combined') or 0:.3f}** (осн.+гранична), а не «ідеальний» 1.0. "
            f"Напрям розвитку — розширення вибірки.")

        # n breakdown by attack class / legit type (if the report has it — after a re-run)
        abc = bench.get("attack_by_class") or {}
        lbc = bench.get("legit_by_category") or {}
        if abc or lbc:
            xa, xl = st.columns(2)
            if abc:
                with xa:
                    st.markdown("**Тести за класами атак**")
                    st.dataframe(pd.DataFrame([{
                        "Клас атаки": k, "n": v.get("n"),
                        "🟩 блок": v.get("blocked"), "🔴 пропущено": v.get("missed"),
                    } for k, v in abc.items()]), use_container_width=True, hide_index=True)
            if lbc:
                with xl:
                    st.markdown("**Тести за типами легіт-поведінки**")
                    st.dataframe(pd.DataFrame([{
                        "Тип поведінки": k, "n": v.get("n"),
                        "✅ пройшло": v.get("allowed"), "⚠️ хибний блок": v.get("false_block"),
                    } for k, v in lbc.items()]), use_container_width=True, hide_index=True)

        # ── Borderline stress set + realistic (combined) ROC ──
        border = bench.get("borderline")
        cpts = bench.get("roc_points_combined", [])
        if border and cpts:
            st.divider()
            _n_bl = len(border.get("cases", []))
            st.markdown(f"**🌫 Гранична стрес-вибірка** (n={_n_bl}) — неоднозначні кейси "
                        "(легіт з підозрілими ознаками + тонкі атаки без явного payload)")
            bl, br2 = st.columns([1, 1])
            with bl:
                bm = border.get("metrics", {})
                bcm = border.get("confusion_matrix", {})
                st.markdown(
                    f"- **Precision:** {bm.get('precision',0):.3f}\n"
                    f"- **Recall:** {bm.get('recall',0):.3f}\n"
                    f"- **F1:** {bm.get('f1',0):.3f}\n"
                    f"- **AUC (гранична):** {border.get('roc_auc') or 0:.3f}\n"
                    f"- TP={bcm.get('TP',0)} FN={bcm.get('FN',0)} "
                    f"FP={bcm.get('FP',0)} TN={bcm.get('TN',0)}")
                st.caption("Мета — строгіший ЧЕСНИЙ тест дискримінації, не заниження AUC.")
                cases = border.get("cases", [])
                if cases:
                    st.dataframe(pd.DataFrame([{
                        "Мітка": c.get("label"), "Кейс": c.get("why"),
                        "рез": c.get("result"), "score": c.get("score"),
                    } for c in cases]), use_container_width=True, hide_index=True)
            with br2:
                st.markdown(f"**Комбінований ROC** (осн.+гранична, AUC = "
                            f"{bench.get('roc_auc_combined') or 0:.3f})")
                cdf = pd.DataFrame(cpts).rename(
                    columns={"fpr": "FPR", "tpr": "TPR"}).sort_values("FPR")
                cbase = alt.Chart(cdf).mark_line(point=True, color="#f58518").encode(
                    x=alt.X("FPR:Q", scale=alt.Scale(domain=[0, 1])),
                    y=alt.Y("TPR:Q", scale=alt.Scale(domain=[0, 1])),
                    tooltip=["FPR", "TPR", "threshold"])
                cdiag = alt.Chart(pd.DataFrame({"FPR": [0, 1], "TPR": [0, 1]})).mark_line(
                    strokeDash=[5, 5], color="gray").encode(x="FPR", y="TPR")
                st.altair_chart((cdiag + cbase).properties(height=300),
                                use_container_width=True)


# ─── TAB 3: IRE classification ────────────────────────────────────────────────

with tabs[2]:
    st.subheader("Класифікація загроз і реагування (Detect→Classify→Respond)")
    if not ire:
        st.info("Немає IRE-звіту — прожени `python core/immune_response_engine.py`.")
    else:
        inc = ire.get("incidents", [])
        # column order: identifier → risk/urgency → actions → taxonomy → source/patch
        df = pd.DataFrame([{
            "Клас атаки": i.get("attack_class"),
            "Ризик": i.get("risk_level"),
            "Терміновість": i.get("urgency"),
            "Дії": ", ".join(i.get("response_actions", [])),
            "STRIDE": i.get("stride_category"),
            "MITRE": i.get("mitre_technique_id"),
            "LINDDUN": i.get("linddun_category"),
            "Джерело": "inline" if i.get("source") == "inline_proxy" else "offline",
            "Патч": (i.get("recommended_patch", "") or "")[:90],
        } for i in inc])

        a, b, c = st.columns(3)
        a.metric("Інцидентів", ire.get("total_incidents", len(inc)))
        b.metric("Сер. час реакції", f"{ire.get('summary', {}).get('avg_response_ms', 0)} ms")
        b_risk = ire.get("summary", {}).get("by_risk", {})
        c.metric("Critical", b_risk.get("Critical", 0))

        if b_risk:
            rdf = pd.DataFrame({"Рівень": list(b_risk), "К-сть": list(b_risk.values())})
            # scale domain = ONLY the levels present in the data (otherwise Altair draws
            # all RISK_COLORS keys into the legend — both UPPER and Capitalized — duplicating ghost levels)
            _dom = list(b_risk)
            _rng = [RISK_COLORS.get(k, "#888888") for k in _dom]
            chart = alt.Chart(rdf).mark_arc(innerRadius=50).encode(
                theta="К-сть:Q",
                color=alt.Color("Рівень:N", scale=alt.Scale(domain=_dom, range=_rng)),
                tooltip=["Рівень", "К-сть"])
            st.altair_chart(chart.properties(height=260), use_container_width=True)

        # worst-first: by risk level (Critical→Low), tie-break — by urgency
        _df = df.assign(
            _lvl=df["Ризик"].map(lambda v: _rank(LEVEL_ORDER, v)),
            _urg=df["Терміновість"].map(lambda v: _rank(URGENCY_ORDER, v)))
        _df = _df.sort_values(["_lvl", "_urg"]).drop(columns=["_lvl", "_urg"])
        st.dataframe(_df, use_container_width=True, hide_index=True)
        st.caption("↓ Відсортовано за критичністю (Critical→Low), далі за терміновістю "
                   f"(IMMEDIATE→LOW).  ·  Джерело: reports/ire/{ire_f}")


# ─── TAB 4: Defense effectiveness ─────────────────────────────────────────────

with tabs[3]:
    st.subheader("Чи дійшла небезпечна операція до Helios")

    # Comparison "without defense" (baseline) vs "with defense" (defended) — the essence of campaign.
    if defense_base and defense_def:
        sb = defense_base.get("summary", {})
        sd = defense_def.get("summary", {})
        bb, br = sb.get("critical_ops_blocked", 0), sb.get("critical_ops_reached", 0)
        db, dr = sd.get("critical_ops_blocked", 0), sd.get("critical_ops_reached", 0)
        st.markdown("**Небезпечні операції: без захисту → із захистом**")
        x, y = st.columns(2)
        x.metric("🔴 БЕЗ захисту (сирий Helios)",
                 f"{bb}/{bb+br} крит-оп.",
                 f"{(bb/(bb+br)*100 if bb+br else 0):.0f}% заблоковано")
        y.metric("🛡 ІЗ захистом (через ЦІС)",
                 f"{db}/{db+dr} крит-оп.",
                 f"{(db/(db+dr)*100 if db+dr else 0):.0f}% заблоковано")
        st.caption(f"{bb+br} — це критичні ОПЕРАЦІЇ (POST /cast, /encrypt_tally, "
                   f"/upload-decryption) у базовому наборі, НЕ кількість атак. "
                   f"Одна атака може містити кілька крит-операцій (напр. cast + cast_confirm).")
        cmp_df = pd.DataFrame([
            {"Режим": "без захисту", "Заблоковано": bb, "Пропущено": br},
            {"Режим": "із захистом", "Заблоковано": db, "Пропущено": dr},
        ]).melt("Режим", var_name="Результат", value_name="Операцій")
        st.altair_chart(
            alt.Chart(cmp_df).mark_bar().encode(
                # no dot in the field name: Altair treats "." as a nested field → empty
                x=alt.X("Операцій:Q", title="Крит. операцій"),
                y=alt.Y("Режим:N", sort=["без захисту", "із захистом"]),
                color=alt.Color("Результат:N", scale=alt.Scale(
                    domain=["Заблоковано", "Пропущено"], range=["#2ca02c", "#d62728"])),
                tooltip=["Режим", "Результат", "Операцій"]
            ).properties(height=140, title="Критичні операції: щит проти меча"),
            use_container_width=True)
        st.divider()

    if not defense:
        st.info("Немає defense_effectiveness — прожени `python run_all.py campaign`.")
    else:
        s = defense.get("summary", {})
        t = defense.get("total_attacks", 0)
        a, b, c, d = st.columns(4)
        a.metric("Усього атак", t)
        b.metric("🛡 Нейтралізовано", s.get("neutralized", 0))
        c.metric("🌐 Поза сервером", s.get("off_server", 0))
        d.metric("🔴 Пропущено", s.get("leaked", 0))

        cb, cr = s.get("critical_ops_blocked", 0), s.get("critical_ops_reached", 0)
        if cb + cr:
            st.progress(cb / (cb + cr),
                        text=f"Небезпечних операцій заблоковано: {cb}/{cb+cr} "
                             f"({cb/(cb+cr)*100:.0f}%)")

        tier = defense.get("proxy_by_tier", {})
        if tier:
            tdf = pd.DataFrame({"Рівень": list(tier), "Блоків": list(tier.values())})
            st.altair_chart(
                alt.Chart(tdf).mark_bar().encode(
                    x="Блоків:Q", y=alt.Y("Рівень:N", sort="-x"),
                    color=alt.value("#4c78a8"), tooltip=["Рівень", "Блоків"]
                ).properties(height=160, title="Рішення проксі за рівнями"),
                use_container_width=True)

        atk = defense.get("attacks", [])
        if atk:
            # worst-first: first with a LEAK (crit op reached), then by number of crit ops ↓
            def _atk_key(a):
                reached = (a.get("crit_total", 0) or 0) - (a.get("crit_blocked", 0) or 0)
                return (-reached, -(a.get("crit_total", 0) or 0), str(a.get("attack_class")))
            atk_sorted = sorted(atk, key=_atk_key)
            # column order: identifier → status → crit ops → AI verdict → vector
            st.dataframe(pd.DataFrame([{
                "Клас атаки": a.get("attack_class"),
                "Статус": a.get("defense_status"),
                "Крит. (блок/усього)": f"{a.get('crit_blocked',0)}/{a.get('crit_total',0)}",
                "Agent": a.get("agent_verdict"),
                "Вектор": a.get("vector"),
            } for a in atk_sorted]), use_container_width=True, hide_index=True)
            st.caption("↓ Відсортовано worst-first: спершу атаки з витоком крит-операції, "
                       "далі за к-стю критичних операцій.  ·  "
                       f"Джерело: reports/defense/{def_f}")
        else:
            st.caption(f"Джерело: reports/defense/{def_f}")


# ─── TAB 5: Co-evolution (shield vs sword across generations) ──────────────────

with tabs[4]:
    st.subheader("Ко-еволюція захисту й атак — динаміка поколінь")
    st.caption("gen-0 — вихідні атаки; gen-1 — мутовані GenAI під тиском блокувань "
               "(escalate/refine/bypass). Стійка нейтралізація крізь покоління = "
               "захист генералізує, а не запам'ятовує відомі IoC.")
    if not coevo:
        st.info("Немає звіту ко-еволюції — прожени `python run_all.py campaign` "
                "(або `immune_system/coevolution_report.py --scope defended`).")
    elif not coevo.get("ran_through_proxy"):
        st.warning("У звіті немає 403-блоків: атаки прогнані повз проксі. "
                   "Потрібен прогін ЧЕРЕЗ ЦІС (`campaign`).")
    else:
        g0, g1 = coevo.get("gen0", {}), coevo.get("gen1", {})
        rows = []
        for label, g in [("gen-0 (baseline)", g0), ("gen-1 (adaptive)", g1)]:
            if g.get("attacks"):
                cb, ct = g.get("critical_ops_blocked", 0), g.get("critical_ops_total", 0)
                rows.append({
                    "Покоління": label,
                    "Атак": g.get("attacks", 0),
                    "Пропущено (leaked)": g.get("leaked", 0),
                    "Утримано (held), %": g.get("held_pct"),
                    "Крит. оп. блок": f"{cb}/{ct}" if ct else "немає (bypass уникає)",
                    "held_pct": g.get("held_pct"),
                })
        if rows:
            gdf = pd.DataFrame(rows)
            a, b = st.columns(2)
            a.metric("gen-0 утримано (0 витоків)", f"{g0.get('held_pct') or 0:.0f}%")
            b.metric("gen-1 утримано (0 витоків)", f"{g1.get('held_pct') or 0:.0f}%",
                     help="Утримано = жодна небезпечна операція не дійшла до Helios. "
                          "Тримається на рівні gen-0 → захист генералізує на мутації.")
            chart_df = gdf[["Покоління", "held_pct"]].dropna()
            if not chart_df.empty:
                st.altair_chart(
                    alt.Chart(chart_df).mark_bar().encode(
                        x=alt.X("held_pct:Q", scale=alt.Scale(domain=[0, 100]),
                                title="Утримано (0 небезпечних операцій дійшло), %"),
                        y=alt.Y("Покоління:N", sort=["gen-0 (baseline)", "gen-1 (adaptive)"],
                                title=None),
                        color=alt.value("#4c78a8"),
                        tooltip=["Покоління", "held_pct"]
                    ).properties(height=160, title="Утримання захисту крізь покоління"),
                    use_container_width=True)
            st.dataframe(gdf.drop(columns=["held_pct"]),
                         use_container_width=True, hide_index=True)
            if (g1.get("critical_ops_total") or 0) == 0 and g1.get("attacks"):
                st.info("🔑 gen-1 (bypass/refine) атаки ВЗАГАЛІ уникають критичних "
                        "операцій — під тиском блокувань вони відступили від прямої "
                        "шкоди. 0 небезпечних операцій дійшло до Helios (100% утримано).")

        modes = coevo.get("by_adaptation_mode", {})
        if modes:
            st.markdown("**Режими адаптації (під тиском блокувань)**")
            mdf = pd.DataFrame([{
                "Режим": m,
                "Атак": v.get("attacks", 0),
                "Крит. блок": f"{v.get('critical_ops_blocked',0)}/{v.get('critical_ops_total',0)}",
                "Блок, %": v.get("block_rate_pct"),
            } for m, v in modes.items()])
            st.dataframe(mdf, use_container_width=True, hide_index=True)
        st.caption(f"Джерело: reports/coevolution/{coevo_f}")


# ─── TAB 6: Kill Chain (sections 3.1, 4.5, 5.4) ───────────────────────────────

with tabs[5]:
    st.subheader("Kill Chain — послідовність кроків атаки та вердикт захисту")
    st.caption("Кожна атака — ланцюг Cyber Kill Chain (recon→…→action). Колір кроку = "
               "вердикт ЦІС: 🟩 заблоковано · 🟦 безпечний крок дійшов (recon/логін — норма) · "
               "🟥 КРИТИЧНА операція дійшла (витік!) · ⬜ симуляція. У defended-графах "
               "червоного НЕМАЄ — жодна небезпечна операція не дійшла до Helios.")
    if not killchain:
        st.info("Немає attack_flow.json — прожени "
                "`python core/attack_flow.py --scope defended`.")
    else:
        atks = killchain.get("attacks", [])
        def _lbl(i):
            a = atks[i]
            m = f" · {a['adaptation_mode']}" if a.get("adaptation_mode") else ""
            return f"{a['attack_class']} [{a['vector']}]{m}"
        idx = st.selectbox("Атака", range(len(atks)), format_func=_lbl)
        a = atks[idx]
        st.markdown(f"**{a['attack_class']}** · MITRE `{a['mitre']}` {a['mitre_name']}")
        s = a["summary"]
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("🟩 Заблоковано", s.get("blocked", 0))
        k2.metric("🟥 Витік (крит.оп)", s.get("leaked", 0))
        k3.metric("🟦 Безпечно дійшло", s.get("allowed", 0))
        k4.metric("⬜ Симуляція", s.get("simulated", 0) + s.get("not_executed", 0))

        COL = {"blocked": "#c6efce", "leaked": "#ffc7ce", "allowed": "#cfe2f3",
               "simulated": "#e2e2e2", "not_executed": "#f2f2f2", "passed": "#cfe2f3"}
        def _esc(t):
            return str(t).replace('"', "'").replace("\n", " ")
        dot = ['digraph { rankdir=TB; bgcolor="transparent";',
               'node [shape=box style="filled,rounded" fontname="Helvetica" fontsize=10];']
        for stp in a["steps"]:
            lbl = f"{stp['n']}. {stp['phase']}\\n{stp['method']} {_esc(stp['endpoint'])}\\n{stp['status']}"
            dot.append(f'n{stp["n"]} [label="{lbl}" fillcolor="{COL.get(stp["verdict"], "#eee")}"];')
        for i in range(len(a["steps"]) - 1):
            dot.append(f'n{a["steps"][i]["n"]} -> n{a["steps"][i+1]["n"]};')
        dot.append("}")
        st.graphviz_chart("\n".join(dot), use_container_width=True)
        st.caption(f"Джерело: reports/killchain/{kc_f} (scope={killchain.get('scope')})")


# ─── TAB 7: Attack Surface (section 4.3) ──────────────────────────────────────

with tabs[6]:
    st.subheader("Attack Surface — endpoint'и Helios під атакою та покриття захисту")
    st.caption("Поверхня атаки, зведена з реальних прогонів: які endpoint атаковано, "
               "скільки кроків заблоковано vs пройшло, скільки класів атак їх торкнулось.")
    if not killchain:
        st.info("Немає даних — прожени `python core/attack_flow.py`.")
    else:
        from collections import defaultdict
        agg = defaultdict(lambda: {"blocked": 0, "leaked": 0, "allowed": 0,
                                   "sim": 0, "classes": set()})
        for atk in killchain["attacks"]:
            for stp in atk["steps"]:
                ep = stp["endpoint"]
                v = stp["verdict"]
                if v in ("blocked", "leaked", "allowed"):
                    agg[ep][v] += 1
                else:
                    agg[ep]["sim"] += 1
                agg[ep]["classes"].add(atk["attack_class"])
        rows = []
        for ep, d in agg.items():
            reached = d["leaked"] + d["allowed"]
            tot = d["blocked"] + reached
            # column order: identifier → verdicts (block/leak/reached) → coverage → volume
            rows.append({"Endpoint": ep,
                         "🟩 Блок": d["blocked"], "🟥 Витік (крит)": d["leaked"],
                         "🟦 Безпеч. дійшло": d["allowed"],
                         "Покриття, %": round(d["blocked"] / tot * 100) if tot else None,
                         "Кроків": tot + d["sim"],
                         "Класів атак": len(d["classes"])})
        # worst-first: first endpoints with LEAKS of crit ops, then by number of attack steps
        df = pd.DataFrame(rows).sort_values(
            ["🟥 Витік (крит)", "Кроків"], ascending=[False, False])
        x, y, z = st.columns(3)
        x.metric("Endpoint під атакою", len(agg))
        y.metric("Класів атак усього",
                 len({atk["attack_class"] for atk in killchain["attacks"]}))
        z.metric("🟥 Витоків крит-операцій", sum(d["leaked"] for d in agg.values()),
                 help="Небезпечних операцій, що дійшли до Helios (у defended = 0)")
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption("↓ Відсортовано worst-first: спершу endpoint із витоками крит-операцій, "
                   "далі за к-стю атак-кроків.")
        # chart: top endpoints — blocked vs reached (crit-leak + safe)
        top = df.head(12).melt(id_vars=["Endpoint"],
                               value_vars=["🟩 Блок", "🟥 Витік (крит)", "🟦 Безпеч. дійшло"],
                               var_name="Результат", value_name="Кроків_")
        st.altair_chart(
            alt.Chart(top).mark_bar().encode(
                x=alt.X("Кроків_:Q", title="Атак-кроків"),
                y=alt.Y("Endpoint:N", sort="-x", title=None),
                color=alt.Color("Результат:N", scale=alt.Scale(
                    domain=["🟩 Блок", "🟥 Витік (крит)", "🟦 Безпеч. дійшло"],
                    range=["#2ca02c", "#d62728", "#4c78a8"])),
                tooltip=["Endpoint", "Результат", "Кроків_"]
            ).properties(height=340, title="Поверхня атаки по endpoint"),
            use_container_width=True)
        st.caption(f"Джерело: reports/killchain/{kc_f}")


# ─── TAB 8: Metrics vs SIEM ───────────────────────────────────────────────────

with tabs[7]:
    st.subheader("Час реагування та порівняння з класичним SIEM")
    if not metrics:
        st.info("Немає metrics_summary — прожени `python immune_system/metrics_summary.py`.")
    else:
        dt = metrics.get("detection_time", {})
        if dt:
            dtf = pd.DataFrame([{"Рівень": k, "avg_ms": v.get("avg_ms", 0),
                                 "Блоків": v.get("count", 0)} for k, v in dt.items()])
            st.altair_chart(
                alt.Chart(dtf).mark_bar().encode(
                    # no dot in the field name (Altair treats "." as a nested field)
                    x=alt.X("avg_ms:Q", scale=alt.Scale(type="symlog"),
                            title="Сер. час, ms (log)"),
                    y=alt.Y("Рівень:N", sort="-x"),
                    color=alt.value("#54a24b"),
                    tooltip=["Рівень", "avg_ms", "Блоків"]
                ).properties(height=180, title="Час реагування за рівнями"),
                use_container_width=True)

        sec = metrics.get("security_tests", {})
        if sec:
            st.markdown("**Безпека та стійкість самої ЦІС** (з реальних прогонів)")
            def _mark(p):
                return "✅" if p is True else ("—" if p is None else "⚠️")
            st.dataframe(pd.DataFrame([{
                "Метрика": name,
                "": _mark(m.get("passed")),
                "Значення": str(m.get("value")),
                "Деталі": m.get("detail", ""),
                "Джерело": m.get("source", ""),
            } for name, m in sec.items()]), use_container_width=True, hide_index=True)

        # Re-detection through immune memory (section 5.1)
        if redetect:
            st.divider()
            st.markdown("**🧠 Re-detection через імунну пам'ять** (adaptive→innate immunity)")
            r1, r2, r3 = st.columns(3)
            r1.metric("1-ша зустріч (ШІ, новизна)", f"{redetect.get('avg_first_ms', 0):.0f} мс")
            r2.metric("Повторна (пам'ять, L1)", f"{redetect.get('avg_repeat_ms', 0):.1f} мс",
                      help="Вивчена сигнатура / кеш-антитіло ловить повторні миттєво")
            sp = redetect.get("speedup")
            r3.metric("Прискорення", f"×{sp:.0f}" if sp else "—",
                      f"L1-повторів: {redetect.get('l1_repeats',0)}/{redetect.get('total_repeats',0)}")
            _rd_pat = len(redetect.get("results", redetect.get("patterns", [])))
            st.caption("Новий підозрілий патерн аналізує ШІ (~секунди) і синтезує сигнатуру; "
                       "повторна поява ловиться рефлексом L1 за ~0мс — ефект імунної пам'яті. "
                       f"n = {_rd_pat} патерни × {redetect.get('repeats', 3)} зустрічі "
                       f"({redetect.get('total_repeats',0)} повторних вимірів). "
                       f"Джерело: reports/redetection/{rd_f}")

        # Measured head-to-head: a real SIEM vs DIS on the SAME dataset (if available)
        if siem:
            tool = siem.get("siem", {}).get("tool") or "SIEM"
            st.markdown(f"**🆚 Виміряне порівняння: {tool} vs ЦІС** (один розмічений набір)")
            sm = siem.get("siem", {}).get("metrics", {})
            dm = siem.get("dis", {}).get("metrics", {})
            scm = siem.get("siem", {}).get("confusion_matrix", {})
            siem_col = f"SIEM ({tool})"
            rows = []
            # headline — Recall/F1 (this is where the SIEM's weakness shows); Precision below with an explanation
            for k, lab in [("recall", "Recall / Detection ⭐"), ("f1", "F1 ⭐"),
                           ("precision", "Precision **"), ("fpr", "FPR")]:
                rows.append({"Метрика": lab, siem_col: sm.get(k),
                             "ЦІС (це дослідж.)": dm.get(k)})
            _apt_siem = siem.get("siem", {}).get("apt_detected", "0/3")
            rows.append({"Метрика": "APT (поведінка)",
                         siem_col: f"{_apt_siem} (за побудовою)",
                         "ЦІС (це дослідж.)": siem.get("dis", {}).get("apt")})
            cL, cR = st.columns([1, 1])
            with cL:
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            with cR:
                # chart: Precision/Recall/F1 — SIEM vs DIS
                bar = pd.DataFrame([
                    {"Метрика": lab, "Система": tool, "Значення": sm.get(k) or 0}
                    for k, lab in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1")]
                ] + [
                    {"Метрика": lab, "Система": "ЦІС", "Значення": dm.get(k) or 0}
                    for k, lab in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1")]
                ])
                st.altair_chart(
                    alt.Chart(bar).mark_bar().encode(
                        x=alt.X("Значення:Q", scale=alt.Scale(domain=[0, 1])),
                        y=alt.Y("Метрика:N", title=None),
                        yOffset="Система:N",
                        color=alt.Color("Система:N", scale=alt.Scale(
                            domain=[tool, "ЦІС"], range=["#8c8c8c", "#2ca02c"])),
                        tooltip=["Метрика", "Система", "Значення"]
                    ).properties(height=200, title=f"{tool} vs ЦІС"),
                    use_container_width=True)
            _prec_note = siem.get("siem", {}).get("precision_note")
            if _prec_note:
                st.caption(f"** {_prec_note}")
            _apt_note = siem.get("siem", {}).get("apt_detected_note")
            if _apt_note:
                st.caption(f"ℹ APT: {_apt_note}")
            missed = siem.get("siem_missed_attacks", [])
            st.caption(f"{tool}: TP={scm.get('TP')} FN={scm.get('FN')} "
                       f"FP={scm.get('FP')} TN={scm.get('TN')} · пропустив {len(missed)} атак.")
            if missed:
                with st.expander(f"🔴 Атаки, які {tool} пропустив ({len(missed)}) — перевага ШІ-ядра ЦІС"):
                    for w in missed:
                        st.markdown(f"- {w}")
            st.caption(f"Джерело: reports/siem/{siem_f}")
            st.divider()

        comp = metrics.get("comparison_vs_siem", [])
        if comp:
            st.markdown("**ЦІС vs класичний SIEM (якісне, з літератури)**")
            st.dataframe(pd.DataFrame([{
                "Характеристика": c.get("characteristic"),
                "Класичний SIEM": c.get("siem"),
                "ЦІС (це дослідження)": c.get("dis"),
            } for c in comp]), use_container_width=True, hide_index=True)
        if metrics.get("siem_sources"):
            with st.expander("Джерела показників SIEM (література)"):
                for src in metrics["siem_sources"]:
                    st.markdown(f"- {src}")
        st.caption(f"Джерело: reports/metrics/{met_f}")


# ─── TAB 9: Legitimate behavior (a separate set — how the system recognizes "normal") ─

with tabs[8]:
    st.subheader("Легітимна поведінка виборця — як ЦІС розпізнає «норму»")
    st.caption("Окремий сет НОРМАЛЬНИХ запитів (без жодних injection-ознак): чи "
               "правильно система їх ПРОПУСКАЄ (ALLOW). Нульовий хибний блок = "
               "виборця не позбавлено голосу. Джерело — легіт-частина benchmark-набору.")
    if not bench:
        st.info("Немає бенчмарку — прожени `python immune_system/benchmark.py` (з проксі).")
    else:
        cm2 = bench.get("confusion_matrix", {})
        _nl2 = bench.get("n_legit", cm2.get("FP", 0) + cm2.get("TN", 0))
        _fp2 = cm2.get("FP", 0)
        p1, p2, p3 = st.columns(3)
        p1.metric("Легіт-запитів (норма)", _nl2)
        p2.metric("✅ Пройшло (ALLOW)", _nl2 - _fp2)
        p3.metric("⚠️ Хибно заблоковано (FP)", _fp2,
                  help="0 = жоден легітимний виборець не заблокований (FPR=0)")
        lbc2 = bench.get("legit_by_category") or {}
        if lbc2:
            st.markdown("**Типи нормальної поведінки (кожен має ПРОХОДИТИ):**")
            st.dataframe(pd.DataFrame([{
                "Тип поведінки": k, "n": v.get("n"),
                "✅ пройшло": v.get("allowed"), "⚠️ хибний блок": v.get("false_block"),
                "Коректно": "так" if v.get("false_block", 0) == 0 else "НІ",
            } for k, v in lbc2.items()]), use_container_width=True, hide_index=True)
            st.caption("Демонструє ДИСКРИМІНАЦІЮ: система відрізняє нормальний перегляд/"
                       "логін/голос від атак — не по чорному списку, а по поведінці.")
        else:
            st.info("Розбивка за типами поведінки з'явиться після наступного прогону "
                    "`benchmark.py` (звіт отримає поле `legit_by_category`). "
                    f"Наразі відомо: {_nl2} легіт-запитів, хибних блоків — {_fp2}.")
        # borderline "grey" legit behavior (apostrophe O'Brien, etc.) — the subtlest normality test
        _bl = bench.get("borderline", {})
        _bcases = [c for c in _bl.get("cases", []) if c.get("label") == "legit"]
        if _bcases:
            st.markdown("**🌫 Гранична легіт-поведінка** (виглядає підозріло, але це норма):")
            st.dataframe(pd.DataFrame([{
                "Кейс": c.get("why"), "рез": c.get("result"), "score": c.get("score"),
            } for c in _bcases]), use_container_width=True, hide_index=True)
        st.caption(f"Джерело: reports/benchmark/{bench_f}")


# ─── TAB 10: Live proxy ───────────────────────────────────────────────────────

with tabs[9]:
    st.subheader("Живі метрики проксі (:8000)")
    st.caption("Потрібен запущений `immune_proxy.py`. Онови сторінку для свіжих даних.")
    try:
        import requests
        r = requests.get("http://localhost:8000/__immune__/stats", timeout=2).json()
        a, b, c, d = st.columns(4)
        a.metric("Всього запитів", r.get("total_requests", 0))
        b.metric("Заблоковано L1", r.get("blocked_fast", 0))
        c.metric("Заблоковано L2 (ШІ)", r.get("blocked_ai", 0))
        d.metric("Сер. латентність", f"{r.get('avg_latency_ms', 0)} ms")

        ai = r.get("ai_analyst", {})
        fr = r.get("fast_reflex", {})
        e, f, g = st.columns(3)
        e.metric("Cache hit rate", f"{ai.get('cache_hit_rate', 0)}%")
        f.metric("🧬 Вивчені L1-сигнатури", fr.get("learned_signatures", 0))
        g.metric("Антитіл у пам'яті", ai.get("persistent_antibodies", 0))

        bac = r.get("by_attack_class", {})
        if bac:
            bdf = pd.DataFrame({"Клас": list(bac), "Блоків": list(bac.values())})
            st.altair_chart(
                alt.Chart(bdf).mark_bar().encode(
                    x="Блоків:Q", y=alt.Y("Клас:N", sort="-x"),
                    color=alt.value("#b279a2"), tooltip=["Клас", "Блоків"]
                ).properties(height=max(160, 24 * len(bac)),
                             title="Блокування за класами атак"),
                use_container_width=True)
    except Exception:
        st.warning("Проксі :8000 недоступний. Запусти `python immune_system/immune_proxy.py`.")
