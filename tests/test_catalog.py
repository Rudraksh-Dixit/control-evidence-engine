from __future__ import annotations

from cee.catalog import load_framework
from cee.checks.registry import build_checks, registered_ids


def test_registry_contains_core_checks() -> None:
    expected = {
        "github_mfa",
        "github_branch_protection",
        "github_secret_scanning",
        "aws_cloudtrail",
        "aws_root_mfa",
        "aws_s3_public_block",
        "aws_guardduty",
        "wazuh_alert_pipeline",
        "sigma_detection_coverage",
        "trivy_vulnerability_sla",
        "windows_password_policy",
        "windows_audit_policy",
        "backup_freshness",
    }
    assert expected.issubset(set(registered_ids()))


def test_framework_loads_with_unique_controls() -> None:
    framework = load_framework("iso27001-2022")
    assert framework.id == "iso27001-2022"
    assert 30 <= len(framework.controls) <= 93
    ids = [control.id for control in framework.controls]
    assert len(ids) == len(set(ids))
    assert all(control.title for control in framework.controls)
    assert all(control.objective for control in framework.controls)
    assert all(control.evidence_expectation for control in framework.controls)


def test_all_controls_use_known_themes_and_checks() -> None:
    framework = load_framework()
    valid_checks = set(registered_ids())
    for control in framework.controls:
        assert control.theme in {"organizational", "people", "physical", "technological"}
        assert set(control.check_ids).issubset(valid_checks), control.id
        assert control.automated == bool(control.check_ids)


def test_every_check_is_mapped_to_a_control() -> None:
    framework = load_framework()
    mapped = {check_id for control in framework.controls for check_id in control.check_ids}
    assert set(registered_ids()).issubset(mapped)
    checks = build_checks(sorted(mapped))
    assert len(checks) == len(mapped)


def test_automation_split_is_meaningful() -> None:
    framework = load_framework()
    automated = [control for control in framework.controls if control.automated]
    manual = [control for control in framework.controls if not control.automated]
    assert len(automated) >= 8
    assert len(manual) >= 15
