from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cee.models import to_iso, utcnow


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_control_id(control_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", control_id)


def load_registry(registry_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Load attestations and verify each attached file against its recorded hash."""
    registry_path = Path(registry_path)
    if not registry_path.exists():
        return {}
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    base = registry_path.parent
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in payload.get("attestations", []):
        row = dict(entry)
        raw_file = Path(str(entry.get("file", "")))
        path = raw_file if raw_file.is_absolute() else (base / raw_file)
        row["path"] = str(path)
        row["valid"] = False
        if path.exists() and path.is_file():
            actual = _sha256(path)
            row["valid"] = actual == str(entry.get("sha256", ""))
            row["actual_sha256"] = actual
            row["size_bytes"] = path.stat().st_size
        grouped.setdefault(str(entry.get("control_id", "")), []).append(row)
    return grouped


def add_attestation(
    registry_path: Path,
    control_id: str,
    source_file: Path,
    note: str,
    attested_by: str,
    framework_id: str = "iso27001-2022",
) -> dict[str, Any]:
    registry_path = Path(registry_path)
    source_file = Path(source_file)
    if not source_file.exists() or not source_file.is_file():
        raise FileNotFoundError(f"Evidence file not found: {source_file}")

    base = registry_path.parent
    destination = base / _safe_control_id(control_id) / source_file.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists() or destination.read_bytes() != source_file.read_bytes():
        if destination.exists():
            stem, suffix = destination.stem, destination.suffix
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            destination = destination.with_name(f"{stem}-{stamp}{suffix}")
        destination.write_bytes(source_file.read_bytes())

    entry = {
        "control_id": control_id,
        "file": destination.relative_to(base).as_posix(),
        "sha256": _sha256(destination),
        "note": note,
        "attested_by": attested_by,
        "attested_at": to_iso(utcnow()),
    }

    payload: dict[str, Any] = {"framework": framework_id, "attestations": []}
    if registry_path.exists():
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        payload.setdefault("attestations", [])
    payload["framework"] = framework_id
    payload["attestations"].append(entry)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return entry


def default_attester() -> str:
    for variable in ("CEE_ATTESTED_BY", "GIT_AUTHOR_NAME", "USERNAME", "USER"):
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return "Unknown"
