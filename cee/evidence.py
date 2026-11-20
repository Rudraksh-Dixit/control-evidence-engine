from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

from cee.checks.util import slugify
from cee.models import CheckResult


def canonical_bytes(content: Any) -> bytes:
    return json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def content_hash(content: Any) -> str:
    return hashlib.sha256(canonical_bytes(content)).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def persist_check_evidence(run_dir: Path, results: list[CheckResult]) -> None:
    """Write every evidence item to disk and stamp its artifact path and SHA-256."""
    for result in results:
        for index, item in enumerate(result.evidence, start=1):
            artifact_rel = (
                Path("evidence") / result.check_id / f"{index:02d}-{slugify(item.title)}.json"
            )
            artifact_path = run_dir / artifact_rel
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            digest = content_hash(item.content)
            size = len(canonical_bytes(item.content))
            payload = {
                "check_id": result.check_id,
                "title": item.title,
                "kind": item.kind,
                "source": item.source,
                "summary": item.summary,
                "collected_at": item.collected_at.isoformat().replace("+00:00", "Z"),
                "sha256": digest,
                "size_bytes": size,
                "content": item.content,
            }
            artifact_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            item.artifact = artifact_rel.as_posix()
            item.sha256 = digest
            item.size_bytes = size
            item.content = None


def copy_manual_evidence(run_dir: Path, manual_by_control: dict[str, list[dict[str, Any]]]) -> None:
    """Copy attested files into the run bundle so the evidence pack is self-contained."""
    for control_id, entries in manual_by_control.items():
        for entry in entries:
            if not entry.get("valid"):
                continue
            source = Path(entry["path"])
            destination = run_dir / "evidence" / "manual" / control_id / source.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.resolve() != destination.resolve():
                destination.write_bytes(source.read_bytes())
            entry["artifact"] = destination.relative_to(run_dir).as_posix()
            entry["size_bytes"] = destination.stat().st_size


def verify_run(run_dir: Path) -> list[dict[str, Any]]:
    """Recompute SHA-256 for every evidence artifact and report mismatches."""
    run_path = run_dir / "run.json"
    if not run_path.exists():
        raise FileNotFoundError(f"No run.json in {run_dir}")
    run = json.loads(run_path.read_text(encoding="utf-8"))
    records: list[dict[str, Any]] = []
    for check in run.get("checks", []):
        for item in check.get("evidence", []):
            artifact = item.get("artifact")
            expected = item.get("sha256")
            record = {
                "kind": "check",
                "check_id": check.get("check_id"),
                "title": item.get("title"),
                "artifact": artifact,
                "expected": expected,
                "actual": None,
                "ok": False,
            }
            if not artifact:
                records.append(record)
                continue
            path = run_dir / artifact
            if not path.exists():
                record["error"] = "artifact missing"
                records.append(record)
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
            actual = content_hash(payload.get("content"))
            record["actual"] = actual
            record["ok"] = actual == expected
            records.append(record)

    for control in run.get("controls", []):
        for item in control.get("manual_evidence", []):
            artifact = item.get("artifact")
            expected = item.get("sha256")
            record = {
                "kind": "manual",
                "check_id": control.get("control_id"),
                "title": item.get("file"),
                "artifact": artifact,
                "expected": expected,
                "actual": None,
                "ok": False,
            }
            if not artifact:
                records.append(record)
                continue
            path = run_dir / artifact
            if not path.exists():
                record["error"] = "artifact missing"
                records.append(record)
                continue
            actual = file_hash(path)
            record["actual"] = actual
            record["ok"] = actual == expected
            records.append(record)
    return records


def bundle_run(run_dir: Path) -> Path:
    """Zip the run into a portable audit bundle (excluding any previous bundle)."""
    bundle_path = run_dir / "audit-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(run_dir.rglob("*")):
            if not path.is_file() or path == bundle_path:
                continue
            archive.write(path, path.relative_to(run_dir).as_posix())
    return bundle_path
