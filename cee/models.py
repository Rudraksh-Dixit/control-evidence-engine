from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return to_iso(value)
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def to_jsonable(value: Any) -> Any:
    """Round-trip through JSON so dataclasses/enums/datetimes become plain data."""
    return json.loads(json.dumps(value, default=_json_default))


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    MANUAL = "manual"
    ATTESTED = "attested"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


CHECK_SCORE = {
    CheckStatus.PASS: 1.0,
    CheckStatus.PARTIAL: 0.5,
    CheckStatus.FAIL: 0.0,
    CheckStatus.ERROR: 0.0,
}

THEME_ORDER = ["organizational", "people", "physical", "technological"]
THEME_LABELS = {
    "organizational": "Organizational (A.5)",
    "people": "People (A.6)",
    "physical": "Physical (A.7)",
    "technological": "Technological (A.8)",
}


@dataclass
class EvidenceItem:
    title: str
    kind: str
    source: str
    summary: str = ""
    content: Any = None
    collected_at: datetime = field(default_factory=utcnow)
    artifact: str | None = None
    sha256: str | None = None
    size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "kind": self.kind,
            "source": self.source,
            "summary": self.summary,
            "collected_at": to_iso(self.collected_at),
            "artifact": self.artifact,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: CheckStatus
    severity: Severity
    summary: str
    detail: str = ""
    remediation: str = ""
    control_ids: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
    collected_at: datetime = field(default_factory=utcnow)

    @property
    def score(self) -> float | None:
        if self.status == CheckStatus.NOT_APPLICABLE:
            return None
        return CHECK_SCORE[self.status]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "detail": self.detail,
            "remediation": self.remediation,
            "control_ids": self.control_ids,
            "evidence": [item.to_dict() for item in self.evidence],
            "error": self.error,
            "duration_ms": self.duration_ms,
            "collected_at": to_iso(self.collected_at),
        }


@dataclass
class Control:
    id: str
    title: str
    theme: str
    objective: str
    evidence_expectation: str
    check_ids: list[str] = field(default_factory=list)
    automated: bool = False
    references: list[str] = field(default_factory=list)
    applicability: str = "All organizations"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "theme": self.theme,
            "objective": self.objective,
            "evidence_expectation": self.evidence_expectation,
            "check_ids": self.check_ids,
            "automated": self.automated,
            "references": self.references,
            "applicability": self.applicability,
        }


@dataclass
class Framework:
    id: str
    name: str
    version: str
    description: str
    source: str
    controls: list[Control] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "source": self.source,
            "control_count": len(self.controls),
        }


@dataclass
class ControlAssessment:
    control_id: str
    title: str
    theme: str
    status: ControlStatus
    score: float | None
    check_ids: list[str] = field(default_factory=list)
    objective: str = ""
    evidence_expectation: str = ""
    note: str = ""
    evidence_count: int = 0
    manual_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "theme": self.theme,
            "status": self.status.value,
            "score": self.score,
            "check_ids": self.check_ids,
            "objective": self.objective,
            "evidence_expectation": self.evidence_expectation,
            "note": self.note,
            "evidence_count": self.evidence_count,
            "manual_evidence": self.manual_evidence,
        }


@dataclass
class AssessmentRun:
    run_id: str
    framework_id: str
    framework_name: str
    framework_version: str
    mode: str
    started_at: datetime
    finished_at: datetime
    controls: list[ControlAssessment]
    checks: list[CheckResult]
    findings: list[dict[str, Any]]
    summary: dict[str, Any]
    host: dict[str, Any]
    artifacts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "mode": self.mode,
            "started_at": to_iso(self.started_at),
            "finished_at": to_iso(self.finished_at),
            "controls": [c.to_dict() for c in self.controls],
            "checks": [c.to_dict() for c in self.checks],
            "findings": self.findings,
            "summary": self.summary,
            "host": self.host,
            "artifacts": self.artifacts,
        }
