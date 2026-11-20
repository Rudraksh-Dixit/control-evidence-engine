from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cee.models import ControlStatus, Severity

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

STATUS_LABELS = {
    ControlStatus.COMPLIANT.value: "Compliant",
    ControlStatus.PARTIAL.value: "Partial",
    ControlStatus.NON_COMPLIANT.value: "Non-compliant",
    ControlStatus.MANUAL.value: "Manual evidence required",
    ControlStatus.ATTESTED.value: "Attested",
    ControlStatus.NOT_APPLICABLE.value: "Not applicable",
    ControlStatus.ERROR.value: "Error",
}

SEVERITY_LABELS = {severity.value: severity.value.upper() for severity in Severity}


def build_context(run: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    summary = run.get("summary", {})
    checks_by_id = {check["check_id"]: check for check in run.get("checks", [])}
    controls = []
    for control in run.get("controls", []):
        item = dict(control)
        item["check_results"] = [
            checks_by_id[check_id]
            for check_id in control.get("check_ids", [])
            if check_id in checks_by_id
        ]
        controls.append(item)

    evidence = []
    for check in run.get("checks", []):
        for item in check.get("evidence", []):
            evidence.append(
                {
                    "check_id": check["check_id"],
                    "check_title": check["title"],
                    "title": item.get("title", ""),
                    "kind": item.get("kind", ""),
                    "source": item.get("source", ""),
                    "summary": item.get("summary", ""),
                    "artifact": item.get("artifact", ""),
                    "sha256": item.get("sha256", ""),
                    "size_bytes": item.get("size_bytes", 0),
                }
            )

    themes = []
    for theme in summary.get("themes", []):
        item = dict(theme)
        total = item.get("total") or 1
        item["segments"] = [
            {"status": status, "count": count, "pct": round(count / total * 100, 2)}
            for status, count in item.get("counts", {}).items()
            if count
        ]
        themes.append(item)

    score = summary.get("score")
    if score is None:
        score_class = "na"
    elif score >= 85:
        score_class = "strong"
    elif score >= 65:
        score_class = "moderate"
    else:
        score_class = "weak"

    report_meta = config.get("report", {})
    return {
        "run": run,
        "summary": summary,
        "controls": controls,
        "findings": run.get("findings", []),
        "themes": themes,
        "evidence": evidence,
        "status_labels": STATUS_LABELS,
        "severity_labels": SEVERITY_LABELS,
        "score_class": score_class,
        "report": {
            "organization": report_meta.get("organization", ""),
            "prepared_by": report_meta.get("prepared_by", ""),
            "reviewer": report_meta.get("reviewer", ""),
        },
    }


def _environment(autoescape: bool) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]) if autoescape else False,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def write_reports(run_dir: Path, run: dict[str, Any], config: dict[str, Any]) -> dict[str, Path]:
    context = build_context(run, config)
    html = _environment(True).get_template("report.html.j2").render(**context)
    markdown = _environment(False).get_template("report.md.j2").render(**context)
    html_path = run_dir / "report.html"
    md_path = run_dir / "report.md"
    html_path.write_text(html, encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    return {"html": html_path, "md": md_path}


def load_run_for_report(path: Path | str) -> dict[str, Any]:
    return json.loads((Path(path) / "run.json").read_text(encoding="utf-8"))
