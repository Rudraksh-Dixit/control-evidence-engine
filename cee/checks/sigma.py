from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity

DEFAULT_TECHNIQUES = [
    "T1059",  # Command and Scripting Interpreter
    "T1078",  # Valid Accounts
    "T1110",  # Brute Force
    "T1190",  # Exploit Public-Facing Application
    "T1053",  # Scheduled Task/Job
    "T1547",  # Boot or Logon Autostart Execution
    "T1071",  # Application Layer Protocol (C2)
    "T1105",  # Ingress Tool Transfer
    "T1486",  # Data Encrypted for Impact
    "T1562",  # Impair Defenses
    "T1021",  # Remote Services
    "T1041",  # Exfiltration Over C2 Channel
]

TECHNIQUE_RE = re.compile(r"attack\.t(\d{4})(?:\.\d{3})?", re.IGNORECASE)


def _rules_dir(ctx: CheckContext) -> Path:
    if not ctx.live:
        return ctx.demo_dir / "sigma_rules"
    configured = str(ctx.setting("sigma.rules_dir", "") or "").strip()
    if not configured:
        raise CheckError("sigma.rules_dir must be set in cee.yaml for live mode")
    path = Path(configured).expanduser()
    if not path.exists() or not path.is_dir():
        raise CheckError(f"Sigma rules directory not found: {path}")
    return path


def _extract_techniques(document: dict[str, Any]) -> set[str]:
    tags = document.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    techniques: set[str] = set()
    for tag in tags:
        match = TECHNIQUE_RE.search(str(tag))
        if match:
            techniques.add(f"T{match.group(1).upper()}")
    for key in ("technique", "techniques", "attack"):
        value = document.get(key)
        if isinstance(value, str):
            match = TECHNIQUE_RE.search(value)
            if match:
                techniques.add(f"T{match.group(1).upper()}")
    return techniques


@register
class SigmaCoverage(Check):
    id = "sigma_detection_coverage"
    title = "Detection coverage against priority ATT&CK techniques"
    description = "Maps Sigma rules to priority MITRE ATT&CK techniques and measures coverage."
    severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> CheckResult:
        rules_dir = _rules_dir(ctx)
        configured = ctx.setting("sigma.required_techniques", None)
        required = [str(t).upper() for t in configured] if configured else DEFAULT_TECHNIQUES

        files = sorted(list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml")))
        covered: dict[str, list[str]] = {}
        inventory: list[dict[str, Any]] = []
        parse_errors: list[str] = []

        for path in files:
            try:
                with path.open("r", encoding="utf-8") as fh:
                    document = yaml.safe_load(fh)
            except (OSError, yaml.YAMLError) as exc:
                parse_errors.append(f"{path.name}: {exc}")
                continue
            if not isinstance(document, dict):
                parse_errors.append(f"{path.name}: not a YAML mapping")
                continue
            techniques = sorted(_extract_techniques(document))
            inventory.append(
                {
                    "rule": path.stem,
                    "title": document.get("title"),
                    "level": document.get("level"),
                    "techniques": techniques,
                }
            )
            for technique in techniques:
                if technique in required:
                    covered.setdefault(technique, []).append(path.stem)

        coverage = len(covered) / len(required) if required else 0.0
        missing = [technique for technique in required if technique not in covered]
        evidence = [
            EvidenceItem(
                title="Sigma rule inventory",
                kind="config_snapshot",
                source=str(rules_dir),
                summary=f"{len(files)} rule file(s), {len(inventory)} parsed.",
                content={
                    "rules_dir": str(rules_dir),
                    "rule_files": len(files),
                    "rules_parsed": len(inventory),
                    "parse_errors": parse_errors,
                    "inventory": inventory,
                },
            ),
            EvidenceItem(
                title="ATT&CK technique coverage matrix",
                kind="analysis",
                source=str(rules_dir),
                summary=f"{len(covered)}/{len(required)} priority techniques covered "
                f"({coverage * 100:.0f}%).",
                content={
                    "required_techniques": required,
                    "covered_techniques": covered,
                    "missing_techniques": missing,
                    "coverage_percent": round(coverage * 100, 1),
                },
            ),
        ]

        if not required:
            return self.result(
                CheckStatus.ERROR,
                "No priority ATT&CK techniques are configured.",
                remediation="Set sigma.required_techniques in cee.yaml.",
                evidence=evidence,
            )
        if coverage >= 0.8:
            return self.result(
                CheckStatus.PASS,
                f"{len(covered)}/{len(required)} priority ATT&CK techniques have Sigma coverage "
                f"({coverage * 100:.0f}%).",
                detail=("Missing: " + ", ".join(missing)) if missing else "",
                evidence=evidence,
            )
        if coverage >= 0.5:
            return self.result(
                CheckStatus.PARTIAL,
                f"Detection coverage is {coverage * 100:.0f}% ({len(covered)}/{len(required)} priority "
                f"techniques).",
                detail="Missing techniques: " + ", ".join(missing),
                remediation="Add Sigma rules for the missing techniques and validate them through the "
                "Sigma validation pipeline.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.FAIL,
            f"Detection coverage is only {coverage * 100:.0f}% ({len(covered)}/{len(required)} priority "
            f"techniques).",
            detail="Missing techniques: " + ", ".join(missing),
            remediation="Build and validate Sigma detections for the missing techniques before relying on "
            "the SIEM for monitoring evidence.",
            evidence=evidence,
            severity=Severity.HIGH,
        )
