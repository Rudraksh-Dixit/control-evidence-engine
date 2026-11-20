from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from cee.checks.base import CheckContext
from cee.demo import materialize

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def demo_dir(tmp_path: Path) -> Path:
    root = tmp_path / "demo"
    materialize(root, NOW)
    return root


@pytest.fixture()
def context(demo_dir: Path, tmp_path: Path) -> CheckContext:
    return CheckContext(
        mode="demo",
        demo_dir=demo_dir,
        config={},
        runs_dir=tmp_path / "runs",
        now=NOW,
    )
