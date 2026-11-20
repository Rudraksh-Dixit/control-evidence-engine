from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cee.config import DEFAULT_RUNS_DIR, load_config  # noqa: E402
from cee.engine import list_runs, run_assessment  # noqa: E402
from cee.models import THEME_LABELS  # noqa: E402

RUNS_DIR = Path(os.environ.get("CEE_RUNS_DIR", str(DEFAULT_RUNS_DIR)))
CONFIG = load_config(os.environ.get("CEE_CONFIG") or None)

STATUS_COLORS = {
    "compliant": "#37d39b",
    "partial": "#fdb022",
    "non_compliant": "#f97066",
    "attested": "#53b1fd",
    "error": "#b692f6",
    "manual": "#5c7080",
    "not_applicable": "#39485a",
}
STATUS_LABELS = {
    "compliant": "Compliant",
    "partial": "Partial",
    "non_compliant": "Non-compliant",
    "manual": "Manual pending",
    "attested": "Attested",
    "not_applicable": "Not applicable",
    "error": "Error",
}
SEVERITY_COLORS = {
    "critical": "#f97066",
    "high": "#fdb022",
    "medium": "#fdb022",
    "low": "#8ba3b9",
    "info": "#53b1fd",
}
THEME_SHORT = {
    "organizational": "A.5 Organizational",
    "people": "A.6 People",
    "physical": "A.7 Physical",
    "technological": "A.8 Technological",
}

st.set_page_config(
    page_title="Control Evidence Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
  .stApp { background: radial-gradient(1200px 600px at 20% -10%, #0e2234 0%, #07101c 55%, #050b12 100%); }
  [data-testid="stSidebar"] { background: #081421; border-right: 1px solid #15283a; }
  [data-testid="stSidebar"] .stButton button { width: 100%; }
  .block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
  .cee-brand { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
  .cee-mark {
    display: inline-flex; align-items: center; justify-content: center; width: 38px; height: 38px;
    border-radius: 10px; background: #37d39b; color: #052a1d; font-weight: 800; font-size: 13px;
  }
  .cee-brand h1 { font-size: 18px; margin: 0; color: #eef6fc; letter-spacing: .2px; }
  .cee-brand p { margin: 0; color: #7f97ad; font-size: 11px; }
  .hero-grid { display: grid; grid-template-columns: 240px 1fr; gap: 16px; margin: 8px 0 18px; }
  .cee-card { background: #0c1a28; border: 1px solid #1a2d42; border-radius: 14px; padding: 18px; }
  .score-card { display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .gauge {
    --ring: #37d39b; width: 150px; height: 150px; border-radius: 50%;
    background: conic-gradient(var(--ring) calc(var(--pct) * 1%), #16283a 0);
    display: flex; align-items: center; justify-content: center;
  }
  .gauge.strong { --ring: #37d39b; } .gauge.moderate { --ring: #fdb022; }
  .gauge.weak { --ring: #f97066; } .gauge.na { --ring: #5c7080; }
  .gauge-inner {
    width: 118px; height: 118px; border-radius: 50%; background: #0c1a28;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .gauge-inner b { font-size: 30px; color: #f4f9fd; line-height: 1; }
  .gauge-inner span { font-size: 9px; color: #7f97ad; letter-spacing: 1px; text-transform: uppercase; margin-top: 5px; }
  .band { margin-top: 10px; color: #8ba3b9; font-size: 11px; text-transform: uppercase; letter-spacing: 1.4px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .kpi { background: #0c1a28; border: 1px solid #1a2d42; border-radius: 12px; padding: 14px 16px; }
  .kpi b { display: block; font-size: 27px; line-height: 1.1; color: #eef6fc; }
  .kpi span { display: block; color: #7f97ad; font-size: 11px; margin-top: 4px; text-transform: uppercase; letter-spacing: .7px; }
  .kpi.green b { color: #37d39b; } .kpi.amber b { color: #fdb022; } .kpi.red b { color: #f97066; }
  .kpi.blue b { color: #53b1fd; } .kpi.gray b { color: #9fb2c4; } .kpi.purple b { color: #b692f6; }
  .section-title { font-size: 15px; color: #e6f0f8; margin: 20px 0 10px; font-weight: 600; }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 10px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; }
  .meta-line { color: #7f97ad; font-size: 12px; }
  .control-title { font-size: 20px; color: #f4f9fd; margin: 2px 0 2px; }
  .control-sub { color: #8ba3b9; font-size: 12px; margin-bottom: 12px; }
  .stTabs [data-baseweb="tab-list"] { gap: 4px; }
  .stTabs [data-baseweb="tab"] { background: #0c1a28; border-radius: 8px 8px 0 0; padding: 8px 16px; }
  .stTabs [aria-selected="true"] { background: #13283c; }
  div[data-testid="stMetricValue"] { color: #eef6fc; }
  code { color: #8ee8c4; }
  .footer-note { color: #5c7080; font-size: 11px; margin-top: 26px; border-top: 1px solid #15283a; padding-top: 14px; }
</style>
""",
    unsafe_allow_html=True,
)


def run_demo() -> None:
    with st.spinner("Collecting evidence from the synthetic demo environment..."):
        run_assessment(mode="demo", config=CONFIG, runs_dir=RUNS_DIR)
    st.rerun()


def status_pill(status: str) -> str:
    color = STATUS_COLORS.get(status, "#9fb2c4")
    label = STATUS_LABELS.get(status, status)
    return (
        f'<span class="pill" style="background:{color}22;color:{color};'
        f'border:1px solid {color}55">{label}</span>'
    )


def render_sidebar(runs: list[dict]) -> dict | None:
    with st.sidebar:
        st.markdown(
            '<div class="cee-brand"><span class="cee-mark">CEE</span>'
            "<div><h1>Control Evidence</h1><p>ISO/IEC 27001:2022</p></div></div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            '<p class="meta-line">Continuous compliance evidence from GitHub, AWS, Wazuh, '
            "Trivy and Windows hosts.</p>",
            unsafe_allow_html=True,
        )
        if st.button("Run demo assessment", type="primary"):
            run_demo()

        selected = None
        if runs:
            labels = {
                run["run_id"]: (
                    f"{run['started_at'][:16].replace('T', ' ')} · {run['mode']} · "
                    f"{run['score']:.1f}%" if run["score"] is not None else run["run_id"]
                )
                for run in runs
            }
            run_id = st.selectbox("Assessment run", [run["run_id"] for run in runs], format_func=labels.get)
            selected = next(run for run in runs if run["run_id"] == run_id)

            run_dir = Path(selected["path"])
            st.markdown("---")
            st.caption("Download the audit pack")
            html_path = run_dir / "report.html"
            md_path = run_dir / "report.md"
            bundle_path = run_dir / "audit-bundle.zip"
            if html_path.exists():
                st.download_button(
                    "HTML report",
                    html_path.read_bytes(),
                    file_name=f"cee-{selected['run_id']}.html",
                    mime="text/html",
                )
            if md_path.exists():
                st.download_button(
                    "Markdown report",
                    md_path.read_bytes(),
                    file_name=f"cee-{selected['run_id']}.md",
                    mime="text/markdown",
                )
            if bundle_path.exists():
                st.download_button(
                    "Audit bundle (zip)",
                    bundle_path.read_bytes(),
                    file_name=f"cee-{selected['run_id']}-bundle.zip",
                    mime="application/zip",
                )

        st.markdown("---")
        st.caption(
            "Demo mode uses a synthetic company with planted findings. Live mode reads only the "
            "systems configured in cee.yaml."
        )
        st.caption(f"Runs directory: `{RUNS_DIR}`")
    return selected


def render_header(run: dict) -> None:
    mode_class = "green" if run["mode"] == "demo" else "blue"
    st.markdown(
        f"""
        <div style="display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:6px;">
          <div>
            <div style="color:#37d39b;font-size:11px;letter-spacing:1.6px;text-transform:uppercase;font-weight:700;">
              Continuous control assurance
            </div>
            <div style="color:#f4f9fd;font-size:30px;font-weight:700;letter-spacing:-.5px;margin-top:2px;">
              {CONFIG.get("report", {}).get("organization", "Organization")}
            </div>
            <div class="meta-line">{run["framework_name"]} · run <code>{run["run_id"]}</code> ·
              started {run["started_at"]}</div>
          </div>
          <div style="text-align:right;">
            <span class="pill" style="background:{'#37d39b22' if mode_class == 'green' else '#53b1fd22'};
              color:{'#37d39b' if mode_class == 'green' else '#53b1fd'};
              border:1px solid {'#37d39b55' if mode_class == 'green' else '#53b1fd55'};">
              {run["mode"]} mode
            </span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_score(summary: dict) -> None:
    score = summary.get("score")
    if score is None:
        klass, display = "na", "n/a"
    elif score >= 85:
        klass, display = "strong", f"{score:.1f}%"
    elif score >= 65:
        klass, display = "moderate", f"{score:.1f}%"
    else:
        klass, display = "weak", f"{score:.1f}%"
    controls = summary["control_status"]
    checks = summary["checks"]
    st.markdown(
        f"""
        <div class="hero-grid">
          <div class="cee-card score-card">
            <div class="gauge {klass}" style="--pct:{score or 0}">
              <div class="gauge-inner"><b>{display}</b><span>assurance</span></div>
            </div>
            <div class="band">{summary["assurance_band"]}</div>
          </div>
          <div class="kpi-grid">
            <div class="kpi green"><b>{controls["compliant"]}</b><span>Compliant</span></div>
            <div class="kpi amber"><b>{controls["partial"]}</b><span>Partial</span></div>
            <div class="kpi red"><b>{controls["non_compliant"]}</b><span>Non-compliant</span></div>
            <div class="kpi gray"><b>{summary["manual_pending"]}</b><span>Manual pending</span></div>
            <div class="kpi blue"><b>{summary["attested_controls"]}</b><span>Attested</span></div>
            <div class="kpi purple"><b>{summary["findings_total"]}</b><span>Open findings</span></div>
          </div>
        </div>
        <div class="meta-line" style="margin-top:-4px;">
          {summary["controls_assessed"]} of {summary["controls_total"]} controls assessed ·
          {summary["automation_coverage_percent"]}% automated coverage ·
          {summary["evidence_count"]} evidence artifacts ·
          {checks["pass"]} checks passed / {checks["fail"]} failed / {checks["error"]} errored
        </div>
        """,
        unsafe_allow_html=True,
    )


def theme_chart(summary: dict) -> None:
    rows = []
    for theme in summary["themes"]:
        for status in ("compliant", "partial", "non_compliant", "attested", "error", "manual"):
            count = theme["counts"].get(status, 0)
            if count:
                rows.append(
                    {
                        "theme": THEME_SHORT[theme["theme"]],
                        "status": STATUS_LABELS[status],
                        "count": count,
                    }
                )
    if not rows:
        return
    domain = [label for label in STATUS_LABELS.values() if label in {row["status"] for row in rows}]
    colors = [STATUS_COLORS[key] for key in STATUS_LABELS if STATUS_LABELS[key] in domain]
    frame = pd.DataFrame(rows)
    chart = (
        alt.Chart(frame)
        .mark_bar(cornerRadius=3)
        .encode(
            y=alt.Y(
                "theme:N",
                sort=list(THEME_SHORT.values()),
                title=None,
                axis=alt.Axis(labelOverlap=False, labelLimit=180),
            ),
            x=alt.X("count:Q", stack="normalize", title="share of controls"),
            color=alt.Color(
                "status:N",
                scale=alt.Scale(domain=domain, range=colors),
                legend=alt.Legend(title=None, orient="bottom"),
            ),
            tooltip=["theme:N", "status:N", "count:Q"],
        )
        .properties(height=240)
    )
    st.altair_chart(chart, width="stretch")


def controls_tab(run: dict) -> None:
    checks_by_id = {check["check_id"]: check for check in run["checks"]}
    controls = run["controls"]
    status_options = ["compliant", "partial", "non_compliant", "manual", "attested", "error", "not_applicable"]
    selected_statuses = st.multiselect(
        "Filter by status",
        status_options,
        format_func=lambda value: STATUS_LABELS[value],
        default=[],
        placeholder="All statuses",
    )
    filtered = [control for control in controls if not selected_statuses or control["status"] in selected_statuses]
    rows = []
    for control in filtered:
        rows.append(
            {
                "ID": control["control_id"],
                "Control": control["title"],
                "Theme": THEME_LABELS[control["theme"]],
                "Status": STATUS_LABELS[control["status"]],
                "Score": round(control["score"] * 100) if control["score"] is not None else None,
                "Evidence": control["evidence_count"],
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=min(420, 38 * max(1, len(rows)) + 40))

    if not filtered:
        return
    st.markdown('<div class="section-title">Inspect a control</div>', unsafe_allow_html=True)
    control_id = st.selectbox(
        "Control",
        [control["control_id"] for control in filtered],
        format_func=lambda value: f"{value} · {next(c['title'] for c in filtered if c['control_id'] == value)}",
        label_visibility="collapsed",
    )
    control = next(item for item in filtered if item["control_id"] == control_id)
    st.markdown(
        f'<div class="control-title">{control["control_id"]} · {control["title"]}</div>'
        f'<div class="control-sub">{THEME_LABELS[control["theme"]]} · '
        f'{status_pill(control["status"])} · score '
        f'{"-" if control["score"] is None else str(round(control["score"] * 100)) + "%"} · '
        f'{control["evidence_count"]} evidence artifacts</div>',
        unsafe_allow_html=True,
    )
    left, right = st.columns(2)
    with left:
        st.markdown("**Control objective**")
        st.write(control["objective"])
    with right:
        st.markdown("**Evidence expectation**")
        st.write(control["evidence_expectation"])
    if control.get("note"):
        st.info(control["note"])

    for check_id in control["check_ids"]:
        check = checks_by_id.get(check_id)
        if not check:
            continue
        label = f"{check['status'].upper().replace('_', ' ')} · {check['title']} · {check_id}"
        with st.expander(label, expanded=check["status"] in ("fail", "error")):
            st.write(check["summary"])
            if check.get("detail"):
                st.caption(check["detail"])
            if check.get("remediation"):
                st.markdown(f"**Remediation:** {check['remediation']}")
            if check["evidence"]:
                st.markdown("**Evidence**")
                for item in check["evidence"]:
                    st.markdown(
                        f"- {item['title']} — `{item['artifact']}` "
                        f"(sha256 `{item['sha256'][:16]}…`, {item['size_bytes']} bytes)"
                    )
            if check.get("error"):
                st.error(check["error"])

    if control["manual_evidence"]:
        st.markdown("**Manual evidence**")
        for item in control["manual_evidence"]:
            st.markdown(
                f"- `{item['file']}` — {item['note']} "
                f"({item['attested_by']}, {item['attested_at']}) "
                + ("" if item["valid"] else "**HASH MISMATCH**")
            )


def findings_tab(run: dict) -> None:
    findings = run["findings"]
    if not findings:
        st.success("No open findings in this run.")
        return
    rows = [
        {
            "ID": item["id"],
            "Severity": item["severity"].upper(),
            "Control": ", ".join(item["controls"]),
            "Finding": item["summary"],
            "Status": item["status"],
            "Remediation": item["remediation"],
        }
        for item in findings
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=480)


def evidence_tab(run: dict, run_dir: Path) -> None:
    rows = []
    for check in run["checks"]:
        for item in check["evidence"]:
            rows.append(
                {
                    "Check": check["check_id"],
                    "Evidence": item["title"],
                    "Kind": item["kind"],
                    "Source": item["source"],
                    "Bytes": item["size_bytes"],
                    "Artifact": item["artifact"],
                    "SHA-256": item["sha256"],
                }
            )
    if not rows:
        st.info("No evidence artifacts in this run.")
        return
    st.dataframe(pd.DataFrame(rows).drop(columns=["SHA-256"]), hide_index=True, width="stretch")
    labels = {row["Artifact"]: f"{row['Check']} · {row['Evidence']}" for row in rows}
    artifact = st.selectbox("Inspect an artifact", options=list(labels), format_func=labels.get)
    row = next(item for item in rows if item["Artifact"] == artifact)
    st.caption(f"Source: {row['Source']} · SHA-256: `{row['SHA-256']}`")
    path = run_dir / artifact
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        st.json(payload.get("content"))
        st.download_button(
            "Download artifact JSON",
            path.read_bytes(),
            file_name=Path(artifact).name,
            mime="application/json",
        )
    else:
        st.error("Artifact file is missing from the run directory.")


def history_tab(runs: list[dict]) -> None:
    if not runs:
        return
    frame = pd.DataFrame(
        [
            {
                "started": run["started_at"],
                "score": run["score"],
                "findings": run["findings"],
                "mode": run["mode"],
                "run": run["run_id"],
            }
            for run in runs
        ]
    )
    frame["started"] = pd.to_datetime(frame["started"], errors="coerce")
    frame = frame.dropna(subset=["started"]).sort_values("started")
    if frame["score"].notna().any():
        chart = (
            alt.Chart(frame)
            .mark_line(point=True, color="#37d39b")
            .encode(
                x=alt.X("started:T", title=None),
                y=alt.Y("score:Q", title="assurance score", scale=alt.Scale(domain=[0, 100])),
                tooltip=["run:N", "started:T", "score:Q", "findings:Q"],
            )
            .properties(height=280)
        )
        st.altair_chart(chart, width="stretch")
    st.dataframe(
        frame[["run", "mode", "started", "score", "findings"]].sort_values("started", ascending=False),
        hide_index=True,
        width="stretch",
    )


runs = list_runs(RUNS_DIR)
selected = render_sidebar(runs)

if selected is None:
    st.markdown(
        """
        <div class="cee-card" style="padding:34px;margin-top:30px;">
          <div style="color:#37d39b;font-size:11px;letter-spacing:1.6px;text-transform:uppercase;font-weight:700;">
            Compliance as code
          </div>
          <div style="color:#f4f9fd;font-size:36px;font-weight:700;letter-spacing:-.8px;margin-top:6px;">
            Audit evidence, collected continuously.
          </div>
          <p style="color:#8ba3b9;max-width:720px;margin-top:10px;">
            Control Evidence Engine maps evidence from GitHub, AWS, Wazuh, Trivy and Windows hosts
            to ISO/IEC 27001:2022 controls, hashes every artifact, and produces an auditor-ready
            report with gaps and remediation actions.
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.info("No assessment runs yet. Run the synthetic demo to explore the dashboard.")
    if st.button("Run demo assessment", type="primary", key="empty-demo"):
        run_demo()
    st.stop()

run_dir = Path(selected["path"])
run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
summary = run["summary"]

render_header(run)
render_score(summary)

overview, controls, findings, evidence, history = st.tabs(
    ["Overview", "Controls", "Findings", "Evidence", "Run history"]
)

with overview:
    st.markdown('<div class="section-title">Coverage by theme</div>', unsafe_allow_html=True)
    theme_chart(summary)
    st.markdown('<div class="section-title">Top findings</div>', unsafe_allow_html=True)
    if run["findings"]:
        top = run["findings"][:6]
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "ID": item["id"],
                        "Severity": item["severity"].upper(),
                        "Control": ", ".join(item["controls"]),
                        "Finding": item["title"],
                    }
                    for item in top
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    else:
        st.success("No open findings.")
    with st.expander("How the score works"):
        st.markdown(
            "The assurance score is the mean of assessed controls: compliant = 100%, partial = 50%, "
            "non-compliant = 0%, verified manual attestation = 100%. Controls without automated checks "
            "stay out of the score until manual evidence is attached. Each evidence artifact is hashed "
            "with SHA-256; `python -m cee verify` recomputes every hash."
        )
        st.markdown(
            "**Manual evidence:** `python -m cee attest --control A.5.1 --file policy.pdf "
            '--note "Approved by the risk committee"`'
        )

with controls:
    controls_tab(run)
with findings:
    findings_tab(run)
with evidence:
    evidence_tab(run, run_dir)
with history:
    history_tab(runs)

st.markdown(
    '<div class="footer-note">Control Evidence Engine · demo data is synthetic · '
    "technical evidence only, not a certification or legal opinion.</div>",
    unsafe_allow_html=True,
)
