from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cee.models import CheckResult, CheckStatus, Severity, utcnow


class CheckError(RuntimeError):
    """Raised when a check cannot collect evidence (missing config, API error, ...)."""


@dataclass
class CheckContext:
    mode: str
    demo_dir: Path
    config: dict[str, Any]
    runs_dir: Path
    now: datetime = field(default_factory=utcnow)
    cache: dict[str, Any] = field(default_factory=dict)

    @property
    def live(self) -> bool:
        return self.mode == "live"

    def fixture(self, name: str) -> Any:
        path = self.demo_dir / name
        if not path.exists():
            raise CheckError(f"Demo fixture missing: {name}")
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def fixture_text(self, name: str) -> str:
        path = self.demo_dir / name
        if not path.exists():
            raise CheckError(f"Demo fixture missing: {name}")
        return path.read_text(encoding="utf-8")

    def setting(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.config
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


class Check:
    id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    live_only: bool = False

    def run(self, ctx: CheckContext) -> CheckResult:  # pragma: no cover - interface
        raise NotImplementedError

    def result(
        self,
        status: CheckStatus,
        summary: str,
        *,
        detail: str = "",
        remediation: str = "",
        evidence: list | None = None,
        error: str | None = None,
        severity: Severity | None = None,
        duration_ms: int = 0,
    ) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            title=self.title,
            status=status,
            severity=severity or self.severity,
            summary=summary,
            detail=detail,
            remediation=remediation,
            evidence=evidence or [],
            error=error,
            duration_ms=duration_ms,
        )
