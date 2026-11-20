from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.checks.util import newest_file, parse_timestamp
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity


def _report_path(ctx: CheckContext) -> Path:
    if not ctx.live:
        return ctx.demo_dir / "trivy_report.json"
    configured = str(ctx.setting("trivy.report_path", "") or "").strip()
    if not configured:
        raise CheckError("trivy.report_path must be set in cee.yaml for live mode")
    path = Path(configured).expanduser()
    if path.is_dir():
        match = newest_file(path, ("*.json",))
        if match is None:
            raise CheckError(f"No Trivy JSON reports found in {path}")
        return match
    if not path.exists():
        raise CheckError(f"Trivy report not found: {path}")
    return path


@register
class VulnerabilitySla(Check):
    id = "trivy_vulnerability_sla"
    title = "Critical and high vulnerability remediation SLA"
    description = "Ingests a Trivy JSON report and checks findings against remediation SLAs."
    severity = Severity.CRITICAL

    def run(self, ctx: CheckContext) -> CheckResult:
        path = _report_path(ctx)
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CheckError(f"Could not parse Trivy report {path}: {exc}") from exc

        critical_sla = int(ctx.setting("trivy.critical_sla_days", 7) or 7)
        high_sla = int(ctx.setting("trivy.high_sla_days", 30) or 30)

        findings: list[dict[str, Any]] = []
        for result in report.get("Results", []) or []:
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = str(vuln.get("Severity", "")).upper()
                if severity not in ("CRITICAL", "HIGH"):
                    continue
                published = parse_timestamp(vuln.get("PublishedDate"))
                age_days = None
                if published is not None:
                    age_days = max(0, (ctx.now - published).days)
                findings.append(
                    {
                        "cve": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion") or None,
                        "severity": severity,
                        "title": vuln.get("Title"),
                        "published": vuln.get("PublishedDate"),
                        "age_days": age_days,
                        "target": result.get("Target"),
                    }
                )

        def overdue(item: dict[str, Any]) -> bool:
            age = item.get("age_days")
            if age is None:
                return False
            limit = critical_sla if item["severity"] == "CRITICAL" else high_sla
            return age > limit

        overdue_findings = [item for item in findings if overdue(item)]
        open_critical = [item for item in findings if item["severity"] == "CRITICAL"]
        open_high = [item for item in findings if item["severity"] == "HIGH"]
        overdue_critical = [item for item in overdue_findings if item["severity"] == "CRITICAL"]
        overdue_high = [item for item in overdue_findings if item["severity"] == "HIGH"]

        evidence = [
            EvidenceItem(
                title="Vulnerability SLA summary",
                kind="analysis",
                source=str(path),
                summary=f"{len(open_critical)} critical / {len(open_high)} high findings; "
                f"{len(overdue_findings)} overdue.",
                content={
                    "report": str(path),
                    "artifact": report.get("ArtifactName"),
                    "critical_sla_days": critical_sla,
                    "high_sla_days": high_sla,
                    "critical_open": len(open_critical),
                    "high_open": len(open_high),
                    "overdue_critical": len(overdue_critical),
                    "overdue_high": len(overdue_high),
                    "overdue_findings": overdue_findings[:25],
                },
            ),
            EvidenceItem(
                title="Raw Trivy scan report",
                kind="scan_report",
                source=str(path),
                summary=f"Trivy report for {report.get('ArtifactName', 'unknown artifact')}.",
                content=report,
            ),
        ]

        if not findings:
            return self.result(
                CheckStatus.PASS,
                "No critical or high vulnerabilities were found in the latest Trivy report.",
                evidence=evidence,
            )
        if overdue_critical:
            return self.result(
                CheckStatus.FAIL,
                f"{len(overdue_critical)} critical vulnerability(ies) exceed the {critical_sla}-day SLA.",
                detail="Overdue: "
                + ", ".join(
                    f"{item['cve']} ({item['package']}, {item['age_days']}d)" for item in overdue_critical[:10]
                ),
                remediation="Patch or mitigate overdue critical vulnerabilities immediately. If no fix "
                "exists, document a compensating control and exception with an expiry date.",
                evidence=evidence,
            )
        if overdue_high:
            return self.result(
                CheckStatus.FAIL,
                f"{len(overdue_high)} high vulnerability(ies) exceed the {high_sla}-day SLA.",
                detail="Overdue: "
                + ", ".join(
                    f"{item['cve']} ({item['package']}, {item['age_days']}d)" for item in overdue_high[:10]
                ),
                remediation="Remediate overdue high vulnerabilities or document compensating controls "
                "and time-bound risk acceptance.",
                evidence=evidence,
                severity=Severity.HIGH,
            )
        if open_critical:
            return self.result(
                CheckStatus.PARTIAL,
                f"{len(open_critical)} critical vulnerability(ies) are open but still within the "
                f"{critical_sla}-day SLA.",
                detail="Maintain the remediation timeline and escalate if the SLA approaches.",
                remediation="Track the finding to closure and confirm a fixed version is available.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            f"{len(open_high)} high vulnerability(ies) are open but within the {high_sla}-day SLA.",
            detail="No SLA breaches were detected in the latest scan.",
            evidence=evidence,
        )
