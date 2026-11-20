from __future__ import annotations

import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cee.engine import list_runs, load_run, run_assessment
from cee.evidence import verify_run

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def assessment(tmp_path_factory: pytest.TempPathFactory):
    runs_dir = tmp_path_factory.mktemp("runs")
    run = run_assessment(mode="demo", runs_dir=runs_dir, now=NOW)
    return run, runs_dir, runs_dir / run.run_id


def test_demo_assessment_produces_complete_run(assessment) -> None:
    run, _, run_dir = assessment
    assert run.summary["score"] is not None
    assert run.summary["controls_total"] == 36
    assert run.summary["automated_controls"] == 10
    assert run.summary["attested_controls"] == 1
    assert run.summary["manual_pending"] == 25
    assert run.summary["checks"]["error"] == 0
    assert run.summary["evidence_count"] == 19

    for name in ("run.json", "report.html", "report.md", "audit-bundle.zip"):
        assert (run_dir / name).exists(), name
    payload = load_run(run_dir)
    assert payload["run_id"] == run.run_id
    assert len(payload["controls"]) == 36
    assert len(payload["checks"]) == 13
    assert len(payload["findings"]) == 7


def test_control_statuses_reflect_evidence(assessment) -> None:
    run, _, _ = assessment
    by_id = {control.control_id: control for control in run.controls}
    assert by_id["A.8.8"].status.value == "non_compliant"
    assert by_id["A.8.12"].status.value == "non_compliant"
    assert by_id["A.8.15"].status.value == "partial"
    assert by_id["A.8.16"].status.value == "partial"
    assert by_id["A.8.13"].status.value == "compliant"
    assert by_id["A.5.1"].status.value == "attested"
    assert by_id["A.5.2"].status.value == "manual"
    assert by_id["A.5.1"].manual_evidence[0]["valid"] is True


def test_evidence_hashes_verify(assessment) -> None:
    _, _, run_dir = assessment
    results = verify_run(run_dir)
    assert len(results) == 19
    assert all(row["ok"] for row in results), [row for row in results if not row["ok"]]


def test_tampering_is_detected(assessment, tmp_path: Path) -> None:
    _, _, run_dir = assessment
    copied = tmp_path / "tampered-run"
    shutil.copytree(run_dir, copied)
    artifact = next((copied / "evidence").rglob("*.json"))
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["content"] = {"tampered": True}
    artifact.write_text(json.dumps(payload), encoding="utf-8")

    results = verify_run(copied)
    assert not all(row["ok"] for row in results)
    assert any(not row["ok"] for row in results)


def test_bundle_contains_reports_and_evidence(assessment) -> None:
    _, _, run_dir = assessment
    with zipfile.ZipFile(run_dir / "audit-bundle.zip") as archive:
        names = set(archive.namelist())
    assert "run.json" in names
    assert "report.html" in names
    assert "report.md" in names
    assert any(name.startswith("evidence/") for name in names)
    assert any(name.startswith("evidence/manual/A.5.1/") for name in names)


def test_runs_are_listed(assessment) -> None:
    run, runs_dir, _ = assessment
    runs = list_runs(runs_dir)
    assert runs
    assert runs[0]["run_id"] == run.run_id
    assert runs[0]["score"] == run.summary["score"]
