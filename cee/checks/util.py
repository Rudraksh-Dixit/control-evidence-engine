from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort parse of ISO-8601 / epoch timestamps into aware UTC datetimes."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            # Also accept "2026-11-20 14:03:01" and trailing fractional seconds.
            cleaned = text.replace(" ", "T", 1)
            try:
                dt = datetime.fromisoformat(cleaned)
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "evidence"


def tail_lines(path: Path, max_bytes: int = 2_000_000) -> list[str]:
    """Read the tail of a file without loading the whole thing into memory."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            data = fh.read()
            lines = data.decode("utf-8", errors="replace").splitlines()
            # First line is likely a partial record.
            return lines[1:] if lines else []
        return fh.read().decode("utf-8", errors="replace").splitlines()


def newest_file(directory: Path, patterns: tuple[str, ...]) -> Path | None:
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(p for p in directory.glob(pattern) if p.is_file())
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def directory_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total
