from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity

BACKUP_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".bak", ".sql", ".dump", ".7z")


def _backup_files(ctx: CheckContext) -> list[Path]:
    if not ctx.live:
        directory = ctx.demo_dir / "backups"
        return sorted(p for p in directory.iterdir() if p.is_file())
    configured = str(ctx.setting("backup.path", "") or "").strip()
    if not configured:
        raise CheckError("backup.path must be set in cee.yaml for live mode")
    path = Path(configured).expanduser()
    if path.is_file():
        return [path]
    if not path.exists() or not path.is_dir():
        raise CheckError(f"Backup path not found: {path}")
    return sorted(
        p
        for p in path.rglob("*")
        if p.is_file() and p.name.lower().endswith(BACKUP_SUFFIXES)
    )


@register
class BackupFreshness(Check):
    id = "backup_freshness"
    title = "Backup freshness and retention"
    description = "Checks the most recent backup age and the retention window available on disk."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        files = _backup_files(ctx)
        max_age_hours = float(ctx.setting("backup.max_age_hours", 24) or 24)
        min_retention_days = float(ctx.setting("backup.min_retention_days", 7) or 7)

        snapshots = []
        for path in files:
            stat = path.stat()
            modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            age_hours = max(0.0, (ctx.now - modified).total_seconds() / 3600)
            snapshots.append(
                {
                    "name": path.name,
                    "size_bytes": stat.st_size,
                    "modified": modified.isoformat().replace("+00:00", "Z"),
                    "age_hours": round(age_hours, 2),
                }
            )
        snapshots.sort(key=lambda item: item["age_hours"])

        evidence = [
            EvidenceItem(
                title="Backup inventory",
                kind="filesystem",
                source=str(files[0].parent) if files else "unconfigured",
                summary=f"{len(snapshots)} backup artifact(s) discovered.",
                content={
                    "snapshot_count": len(snapshots),
                    "max_age_hours": max_age_hours,
                    "min_retention_days": min_retention_days,
                    "snapshots": snapshots[:30],
                },
            )
        ]

        if not snapshots:
            return self.result(
                CheckStatus.FAIL,
                "No backup artifacts were found.",
                detail="There is no evidence of recoverable backups in the configured location.",
                remediation="Configure automated backups, store them off-host, and retain at least 7 daily "
                "recovery points. Record restore tests as separate evidence.",
                evidence=evidence,
                severity=Severity.CRITICAL,
            )

        newest = snapshots[0]
        oldest = snapshots[-1]
        span_days = (oldest["age_hours"] - newest["age_hours"]) / 24
        if newest["age_hours"] > max_age_hours:
            return self.result(
                CheckStatus.FAIL,
                f"The newest backup is {newest['age_hours']:.1f} hours old (threshold {max_age_hours:.0f}h).",
                detail=f"Most recent artifact: {newest['name']}.",
                remediation="Restore the backup schedule, verify the job is not failing silently, and alert "
                "on backup age.",
                evidence=evidence,
            )
        if span_days < min_retention_days:
            return self.result(
                CheckStatus.PARTIAL,
                f"Backups are fresh but only {span_days:.1f} days of retention were observed "
                f"(target {min_retention_days:.0f} days).",
                remediation="Extend the retention policy and lifecycle rules to meet the recovery "
                "objectives.",
                evidence=evidence,
                severity=Severity.MEDIUM,
            )
        return self.result(
            CheckStatus.PASS,
            f"Newest backup is {newest['age_hours']:.1f}h old with {span_days:.1f} days of retention.",
            evidence=evidence,
        )
