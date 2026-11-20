from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.checks.util import parse_timestamp, tail_lines
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity


def _alert_path(ctx: CheckContext) -> Path:
    if not ctx.live:
        return ctx.demo_dir / "wazuh_alerts.jsonl"
    configured = str(ctx.setting("wazuh.alerts_path", "") or "").strip()
    if not configured:
        raise CheckError("wazuh.alerts_path must be set in cee.yaml for live mode")
    path = Path(configured).expanduser()
    if path.is_dir():
        candidates = sorted(
            (p for p in path.glob("*.json*") if p.is_file()), key=lambda p: p.stat().st_mtime
        )
        if not candidates:
            raise CheckError(f"No Wazuh alert files found in {path}")
        return candidates[-1]
    if not path.exists():
        raise CheckError(f"Wazuh alert file not found: {path}")
    return path


@register
class WazuhAlertPipeline(Check):
    id = "wazuh_alert_pipeline"
    title = "Wazuh alert pipeline health"
    description = "Confirms the SIEM is receiving recent alerts and producing high-severity detections."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        path = _alert_path(ctx)
        window_hours = int(ctx.setting("wazuh.freshness_hours", 24) or 24)
        alerts: list[dict[str, Any]] = []
        invalid = 0
        for line in tail_lines(path):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue
            if isinstance(payload, dict):
                alerts.append(payload)

        parsed = []
        for alert in alerts:
            timestamp = parse_timestamp(alert.get("timestamp") or alert.get("@timestamp"))
            if timestamp is not None:
                parsed.append((timestamp, alert))

        evidence = [
            EvidenceItem(
                title="Wazuh alert statistics",
                kind="log_sample",
                source=str(path),
                summary=f"{len(parsed)} timestamped alerts in the inspected log tail.",
                content={
                    "source": str(path),
                    "file_size_bytes": path.stat().st_size,
                    "alerts_parsed": len(parsed),
                    "invalid_lines": invalid,
                    "window_hours": window_hours,
                },
            )
        ]

        if not parsed:
            return self.result(
                CheckStatus.FAIL,
                "No timestamped alerts were found in the Wazuh alert log.",
                detail="The SIEM may not be ingesting logs, or the configured path is incorrect.",
                remediation="Verify the Wazuh manager is running, agents are connected, and "
                "wazuh.alerts_path points at alerts/alerts.json.",
                evidence=evidence,
                severity=Severity.CRITICAL,
            )

        latest = max(ts for ts, _ in parsed)
        age_hours = max(0.0, (ctx.now - latest).total_seconds() / 3600)
        recent = [(ts, alert) for ts, alert in parsed if ctx.now - ts <= timedelta(hours=window_hours)]
        high = [
            alert
            for _, alert in recent
            if int((alert.get("rule") or {}).get("level", 0) or 0) >= 10
        ]

        sample = []
        for ts, alert in sorted(recent, key=lambda item: item[0], reverse=True)[:8]:
            rule = alert.get("rule") or {}
            sample.append(
                {
                    "timestamp": ts.isoformat().replace("+00:00", "Z"),
                    "level": rule.get("level"),
                    "rule_id": rule.get("id"),
                    "description": rule.get("description"),
                    "agent": (alert.get("agent") or {}).get("name"),
                }
            )

        evidence.append(
            EvidenceItem(
                title="Recent high-severity alert sample",
                kind="log_sample",
                source=str(path),
                summary=f"{len(high)} high-severity alert(s) within {window_hours}h.",
                content={
                    "latest_alert_age_hours": round(age_hours, 2),
                    "alerts_in_window": len(recent),
                    "high_severity_in_window": len(high),
                    "sample": sample,
                },
            )
        )

        if age_hours > window_hours:
            return self.result(
                CheckStatus.FAIL,
                f"The newest Wazuh alert is {age_hours:.1f} hours old (threshold {window_hours}h).",
                detail="Alerting appears stale, so monitoring cannot be evidenced for the current period.",
                remediation="Check Wazuh manager health, agent connectivity and log ingestion. Confirm "
                "the alert file is not rotated or truncated.",
                evidence=evidence,
                severity=Severity.HIGH,
            )
        if not high:
            return self.result(
                CheckStatus.PARTIAL,
                f"Alerts are fresh ({age_hours:.1f}h old) but no level >=10 alerts were seen in "
                f"{window_hours}h.",
                detail="Monitoring is active; detection severity or rule coverage may need tuning.",
                remediation="Review detection rules and alert levels, and validate the pipeline with a "
                "known test event.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            f"Wazuh is ingesting alerts; newest is {age_hours:.1f}h old with {len(high)} high-severity "
            f"alert(s) in {window_hours}h.",
            evidence=evidence,
        )
