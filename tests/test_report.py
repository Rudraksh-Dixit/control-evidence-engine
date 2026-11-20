from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from cee.config import load_config
from cee.engine import run_assessment


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory):
    runs_dir = tmp_path_factory.mktemp("reports")
    run = run_assessment(
        mode="demo",
        config=load_config(),
        runs_dir=runs_dir,
        now=datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc),
    )
    return runs_dir / run.run_id


def test_html_report_renders(generated: Path) -> None:
    html = (generated / "report.html").read_text(encoding="utf-8")
    assert "Control Evidence Report" in html
    assert "ISO/IEC 27001:2022" in html
    assert "A.8.15" in html
    assert "A.5.17" in html
    assert "assurance score" in html
    assert "{{" not in html
    assert "{%" not in html


def test_markdown_report_renders(generated: Path) -> None:
    markdown = (generated / "report.md").read_text(encoding="utf-8")
    assert "# Control Evidence Report" in markdown
    assert "## Findings" in markdown
    assert "## Evidence manifest" in markdown
    assert "A.8.16" in markdown
    assert "{{" not in markdown
    assert "{%" not in markdown
