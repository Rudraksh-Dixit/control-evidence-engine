from __future__ import annotations

from cee.checks.aws import AwsCloudTrail, AwsGuardDuty, AwsRootMfa, AwsS3Protection
from cee.checks.backup import BackupFreshness
from cee.checks.github import GitHubBranchProtection, GitHubMFA, GitHubSecretScanning
from cee.checks.local import AuditPolicy, PasswordPolicy
from cee.checks.sigma import SigmaCoverage
from cee.checks.trivy import VulnerabilitySla
from cee.checks.wazuh import WazuhAlertPipeline
from cee.models import CheckStatus


def test_github_checks(context) -> None:
    mfa = GitHubMFA().run(context)
    assert mfa.status == CheckStatus.FAIL
    assert "2 of 9" in mfa.summary
    assert mfa.evidence and mfa.evidence[0].sha256 is None  # hashed when persisted

    branch = GitHubBranchProtection().run(context)
    assert branch.status == CheckStatus.PARTIAL
    assert "review" in branch.summary

    secrets = GitHubSecretScanning().run(context)
    assert secrets.status == CheckStatus.PASS


def test_aws_checks(context) -> None:
    cloudtrail = AwsCloudTrail().run(context)
    assert cloudtrail.status == CheckStatus.PARTIAL
    assert "multi-region" in cloudtrail.summary

    root = AwsRootMfa().run(context)
    assert root.status == CheckStatus.PASS

    s3 = AwsS3Protection().run(context)
    assert s3.status == CheckStatus.FAIL
    assert "acme-marketing-assets" in s3.detail

    guardduty = AwsGuardDuty().run(context)
    assert guardduty.status == CheckStatus.PASS


def test_siem_and_scan_checks(context) -> None:
    wazuh = WazuhAlertPipeline().run(context)
    assert wazuh.status == CheckStatus.PASS
    assert "high-severity" in wazuh.summary

    sigma = SigmaCoverage().run(context)
    assert sigma.status == CheckStatus.PARTIAL
    assert "67%" in sigma.summary or "66%" in sigma.summary or "7" in sigma.summary

    trivy = VulnerabilitySla().run(context)
    assert trivy.status == CheckStatus.FAIL
    assert "critical" in trivy.summary.lower()
    assert any("CVE-2026-1101" in (item["cve"] or "") for item in trivy.evidence[0].content["overdue_findings"])


def test_local_and_backup_checks(context) -> None:
    password = PasswordPolicy().run(context)
    assert password.status == CheckStatus.PARTIAL
    assert password.evidence[0].content["parsed"]["minimum_password_length"] == "8"

    audit = AuditPolicy().run(context)
    assert audit.status == CheckStatus.PASS

    backup = BackupFreshness().run(context)
    assert backup.status == CheckStatus.PASS
    assert backup.evidence[0].content["snapshot_count"] == 9


def test_evidence_is_structured_and_explainable(context) -> None:
    result = GitHubMFA().run(context)
    assert result.severity.value == "high"
    assert result.remediation
    assert result.evidence[0].content["members_without_2fa"] == ["ops-oncall", "contractor-raj"]
    assert result.evidence[0].content["admins_without_2fa"] == ["ops-oncall"]
