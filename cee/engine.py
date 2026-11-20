from __future__ import annotations

import json
import platform
import secrets
import socket
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any

import cee.checks  # noqa: F401  (registers bundled checks)
from cee import __version__
from cee.attest import load_registry
from cee.catalog import DEFAULT_FRAMEWORK, load_framework
from cee.checks.base import CheckContext, CheckError
from cee.checks.registry import build_checks
from cee.config import DEFAULT_RUNS_DIR, load_config
from cee.demo import materialize
from cee.evidence import bundle_run, copy_manual_evidence, persist_check_evidence
from cee.models import (
    THEME_LABELS,
    THEME_ORDER,
    AssessmentRun,
    CheckResult,
    CheckStatus,
    Control,
    ControlAssessment,
    ControlStatus,
    EvidenceItem,
    Severity,
    utcnow,
)
from cee.report import write_reports

ASSESSED_STATUSES = {
    ControlStatus.COMPLIANT,
    ControlStatus.PARTIAL,
    ControlStatus.NON_COMPLIANT,
    ControlStatus.ATTESTED,
}


def _manual_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for entry in entries:
        summary.append(
            {
                "file": Path(str(entry.get("file", ""))).name,
                "note": entry.get("note", ""),
                "attested_by": entry.get("attested_by", ""),
                "attested_at": entry.get("attested_at", ""),
                "sha256": entry.get("sha256", ""),
                "valid": bool(entry.get("valid")),
                "artifact": entry.get("artifact", ""),
                "size_bytes": entry.get("size_bytes", 0),
            }
        )
    return summary


def _assess_control(
    control: Control,
    by_id: dict[str, CheckResult],
    manual_entries: list[dict[str, Any]],
) -> ControlAssessment:
    mapped = [by_id[check_id] for check_id in control.check_ids if check_id in by_id]
    valid_manual = [entry for entry in manual_entries if entry.get("valid")]
    invalid_manual = [entry for entry in manual_entries if not entry.get("valid")]
    manual = _manual_summary(manual_entries)
    note = ""
    status: ControlStatus
    score: float | None

    if mapped:
        applicable = [result for result in mapped if result.status != CheckStatus.NOT_APPLICABLE]
        if not applicable:
            status = ControlStatus.NOT_APPLICABLE
            score = None
            note = "Mapped checks are not applicable to this host."
        else:
            scores = [result.score for result in applicable if result.score is not None]
            score = mean(scores) if scores else None
            if all(result.status == CheckStatus.ERROR for result in applicable):
                status = ControlStatus.ERROR
            elif all(result.status == CheckStatus.PASS for result in applicable):
                status = ControlStatus.COMPLIANT
            elif score == 0:
                status = ControlStatus.NON_COMPLIANT
            else:
                status = ControlStatus.PARTIAL
        if valid_manual:
            note = (note + " " if note else "") + f"{len(valid_manual)} manual evidence file(s) attached."
        if invalid_manual:
            note = (note + " " if note else "") + (
                f"{len(invalid_manual)} manual evidence file(s) failed hash verification."
            )
    elif control.check_ids:
        status = ControlStatus.ERROR
        score = None
        note = "Configured checks did not produce a result."
    elif manual_entries:
        if valid_manual:
            status = ControlStatus.ATTESTED
            score = 1.0
            note = f"{len(valid_manual)} manual evidence file(s) attached and verified."
        else:
            status = ControlStatus.ERROR
            score = None
            note = "Manual evidence is registered but missing or the hash does not match."
    else:
        status = ControlStatus.MANUAL
        score = None
        note = "No automated check mapped. Attach evidence with `python -m cee attest`."

    evidence_count = sum(len(result.evidence) for result in mapped) + len(valid_manual)
    return ControlAssessment(
        control_id=control.id,
        title=control.title,
        theme=control.theme,
        status=status,
        score=round(score, 4) if score is not None else None,
        check_ids=list(control.check_ids),
        objective=control.objective,
        evidence_expectation=control.evidence_expectation,
        note=note,
        evidence_count=evidence_count,
        manual_evidence=manual,
    )


def _findings(results: list[CheckResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in results:
        if result.status not in (CheckStatus.FAIL, CheckStatus.PARTIAL, CheckStatus.ERROR):
            continue
        rows.append(
            {
                "check_id": result.check_id,
                "title": result.title,
                "severity": result.severity.value,
                "status": result.status.value,
                "summary": result.summary,
                "detail": result.detail,
                "remediation": result.remediation,
                "controls": result.control_ids,
            }
        )
    rows.sort(key=lambda row: (Severity(row["severity"]).rank, row["check_id"]))
    for index, row in enumerate(rows, start=1):
        row["id"] = f"F-{index:03d}"
    return rows


def _assurance_band(score: float | None) -> str:
    if score is None:
        return "not assessed"
    if score >= 85:
        return "strong"
    if score >= 65:
        return "moderate"
    if score >= 40:
        return "needs improvement"
    return "critical"


def _summarize(
    framework_controls: list[Control],
    assessments: list[ControlAssessment],
    results: list[CheckResult],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    status_counts = Counter(assessment.status.value for assessment in assessments)
    assessed = [assessment for assessment in assessments if assessment.status in ASSESSED_STATUSES]
    scores = [assessment.score for assessment in assessed if assessment.score is not None]
    score = round(mean(scores) * 100, 1) if scores else None

    check_counts = Counter(result.status.value for result in results)
    severity_counts = {
        severity.value: sum(1 for finding in findings if finding["severity"] == severity.value)
        for severity in Severity
    }

    themes = []
    for theme in THEME_ORDER:
        subset = [assessment for assessment in assessments if assessment.theme == theme]
        themed_assessed = [assessment for assessment in subset if assessment.status in ASSESSED_STATUSES]
        themed_scores = [
            assessment.score for assessment in themed_assessed if assessment.score is not None
        ]
        counts = Counter(assessment.status.value for assessment in subset)
        themes.append(
            {
                "theme": theme,
                "label": THEME_LABELS[theme],
                "total": len(subset),
                "assessed": len(themed_assessed),
                "score": round(mean(themed_scores) * 100, 1) if themed_scores else None,
                "counts": {status.value: counts[status.value] for status in ControlStatus},
            }
        )

    automated = sum(1 for control in framework_controls if control.automated)
    total = len(framework_controls)
    return {
        "score": score,
        "assurance_band": _assurance_band(score),
        "controls_total": total,
        "controls_assessed": len(assessed),
        "automated_controls": automated,
        "manual_controls": total - automated,
        "automation_coverage_percent": round(automated / total * 100, 1) if total else 0.0,
        "control_status": {status.value: status_counts[status.value] for status in ControlStatus},
        "manual_pending": status_counts[ControlStatus.MANUAL.value],
        "attested_controls": status_counts[ControlStatus.ATTESTED.value],
        "findings_total": len(findings),
        "findings_by_severity": severity_counts,
        "checks": {
            "total": len(results),
            "pass": check_counts[CheckStatus.PASS.value],
            "partial": check_counts[CheckStatus.PARTIAL.value],
            "fail": check_counts[CheckStatus.FAIL.value],
            "error": check_counts[CheckStatus.ERROR.value],
            "not_applicable": check_counts[CheckStatus.NOT_APPLICABLE.value],
        },
        "evidence_count": sum(len(result.evidence) for result in results)
        + sum(len(assessment.manual_evidence) for assessment in assessments),
        "themes": themes,
    }


def _error_result(check: Any, exc: Exception, duration_ms: int) -> CheckResult:
    return CheckResult(
        check_id=check.id,
        title=check.title,
        status=CheckStatus.ERROR,
        severity=check.severity,
        summary=f"Check could not run: {exc}",
        remediation="Review the configuration and credentials for this check, then re-run the assessment.",
        error=str(exc),
        evidence=[
            EvidenceItem(
                title="Check execution error",
                kind="error",
                source=check.id,
                summary=str(exc),
                content={"check_id": check.id, "error": str(exc), "type": type(exc).__name__},
            )
        ],
        duration_ms=duration_ms,
    )


def run_assessment(
    mode: str = "demo",
    config: dict[str, Any] | None = None,
    framework_id: str = DEFAULT_FRAMEWORK,
    runs_dir: Path | str | None = None,
    now: datetime | None = None,
    check_ids: list[str] | None = None,
) -> AssessmentRun:
    if mode not in ("demo", "live"):
        raise ValueError("mode must be 'demo' or 'live'")

    config = config if config is not None else load_config()
    started_at = now or utcnow()
    framework = load_framework(framework_id)

    catalog_check_ids: list[str] = []
    for control in framework.controls:
        for check_id in control.check_ids:
            if check_id not in catalog_check_ids:
                catalog_check_ids.append(check_id)
    if check_ids is not None:
        unknown = sorted(set(check_ids) - set(catalog_check_ids))
        if unknown:
            raise ValueError(f"Checks not mapped in {framework.id}: {', '.join(unknown)}")
        catalog_check_ids = [check_id for check_id in catalog_check_ids if check_id in set(check_ids)]

    checks = build_checks(catalog_check_ids)
    reverse: dict[str, list[str]] = {}
    for control in framework.controls:
        for check_id in control.check_ids:
            reverse.setdefault(check_id, []).append(control.id)

    run_id = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{mode}-{secrets.token_hex(2)}"
    base_dir = Path(runs_dir) if runs_dir else DEFAULT_RUNS_DIR
    run_dir = base_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    demo_dir = run_dir / "demo"
    if mode == "demo":
        materialize(demo_dir, started_at)

    context = CheckContext(
        mode=mode,
        demo_dir=demo_dir,
        config=config,
        runs_dir=base_dir,
        now=started_at,
    )

    results: list[CheckResult] = []
    for check in checks:
        check_started = time.perf_counter()
        try:
            result = check.run(context)
        except CheckError as exc:
            result = _error_result(check, exc, int((time.perf_counter() - check_started) * 1000))
        except Exception as exc:  # noqa: BLE001 - a broken check must not abort the assessment
            result = _error_result(check, exc, int((time.perf_counter() - check_started) * 1000))
        result.duration_ms = int((time.perf_counter() - check_started) * 1000)
        result.control_ids = reverse.get(check.id, [])
        results.append(result)

    persist_check_evidence(run_dir, results)

    if mode == "demo":
        registry_path = demo_dir / "manual" / "attestations.json"
    else:
        registry_path = Path(str(config.get("manual", {}).get("registry", "")))
    manual = load_registry(registry_path) if str(registry_path) and registry_path.exists() else {}
    copy_manual_evidence(run_dir, manual)

    by_id = {result.check_id: result for result in results}
    assessments = [
        _assess_control(control, by_id, manual.get(control.id, []))
        for control in framework.controls
    ]
    findings = _findings(results)
    summary = _summarize(framework.controls, assessments, results, findings)
    finished_at = utcnow()

    artifacts = {
        "run": "run.json",
        "report_html": "report.html",
        "report_md": "report.md",
        "bundle": "audit-bundle.zip",
    }
    run = AssessmentRun(
        run_id=run_id,
        framework_id=framework.id,
        framework_name=framework.name,
        framework_version=framework.version,
        mode=mode,
        started_at=started_at,
        finished_at=finished_at,
        controls=assessments,
        checks=results,
        findings=findings,
        summary=summary,
        host={
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "tool_version": __version__,
        },
        artifacts=artifacts,
    )

    run_payload = run.to_dict()
    (run_dir / "run.json").write_text(
        json.dumps(run_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    write_reports(run_dir, run_payload, config)
    bundle_run(run_dir)
    return run


def list_runs(runs_dir: Path | str | None = None) -> list[dict[str, Any]]:
    base = Path(runs_dir) if runs_dir else DEFAULT_RUNS_DIR
    if not base.exists():
        return []
    runs = []
    for path in base.iterdir():
        run_file = path / "run.json"
        if not path.is_dir() or not run_file.exists():
            continue
        try:
            payload = json.loads(run_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        runs.append(
            {
                "run_id": payload.get("run_id", path.name),
                "path": str(path),
                "started_at": payload.get("started_at", ""),
                "mode": payload.get("mode", ""),
                "score": (payload.get("summary") or {}).get("score"),
                "findings": (payload.get("summary") or {}).get("findings_total", 0),
                "controls": len(payload.get("controls", [])),
            }
        )
    runs.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    return runs


def latest_run_dir(runs_dir: Path | str | None = None) -> Path | None:
    runs = list_runs(runs_dir)
    return Path(runs[0]["path"]) if runs else None


def load_run(run_dir: Path | str) -> dict[str, Any]:
    path = Path(run_dir) / "run.json"
    return json.loads(path.read_text(encoding="utf-8"))
