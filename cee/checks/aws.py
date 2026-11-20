from __future__ import annotations

from typing import Any

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity


def _live_snapshot(ctx: CheckContext) -> dict[str, Any]:
    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except ImportError as exc:
        raise CheckError(
            "boto3 is required for live AWS checks. Install it with: pip install boto3"
        ) from exc

    profile = str(ctx.setting("aws.profile", "") or "")
    regions = ctx.setting("aws.regions", ["us-east-1"]) or ["us-east-1"]
    primary = str(regions[0])

    try:
        session = boto3.Session(profile_name=profile or None)
        cloudtrail = session.client("cloudtrail", region_name=primary)
        trails: list[dict[str, Any]] = []
        for trail in cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", []):
            arn = trail.get("TrailARN", trail.get("Name", ""))
            try:
                status = cloudtrail.get_trail_status(Name=arn)
                logging = bool(status.get("IsLogging"))
            except ClientError:
                logging = False
            try:
                selectors = cloudtrail.get_event_selectors(TrailName=arn)
                event_selectors = selectors.get("EventSelectors") or []
                if event_selectors:
                    management = bool(event_selectors[0].get("IncludeManagementEvents", True))
                    read_write = str(event_selectors[0].get("ReadWriteType", "All"))
                else:
                    # No explicit selectors means the trail logs all management events.
                    management = True
                    read_write = "All"
            except ClientError:
                management = False
                read_write = "Unknown"
            trails.append(
                {
                    "name": trail.get("Name"),
                    "home_region": trail.get("HomeRegion"),
                    "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
                    "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
                    "is_logging": logging,
                    "management_events": management,
                    "read_write_type": read_write,
                }
            )
    except (BotoCoreError, ClientError) as exc:
        raise CheckError(f"AWS CloudTrail collection failed: {exc}") from exc

    try:
        s3 = session.client("s3", region_name=primary)
        buckets: list[dict[str, Any]] = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket.get("Name", "")
            encryption = "none"
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    algorithm = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    encryption = algorithm or "configured"
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code", ""))
                if code not in (
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "NoSuchBucket",
                ):
                    raise
            public_block = {
                "block_public_acls": False,
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False,
            }
            try:
                block = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                public_block = {key: bool(block.get(key, False)) for key in public_block}
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code", ""))
                if code not in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
                    raise
            buckets.append({"name": name, "encryption": encryption, "public_access_block": public_block})
    except (BotoCoreError, ClientError) as exc:
        raise CheckError(f"AWS S3 collection failed: {exc}") from exc

    try:
        iam = session.client("iam", region_name=primary)
        summary = iam.get_account_summary().get("SummaryMap", {})
        password_policy: dict[str, Any] = {}
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            password_policy = {
                "minimum_password_length": policy.get("MinimumPasswordLength"),
                "max_password_age": policy.get("MaxPasswordAge"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention"),
                "require_symbols": policy.get("RequireSymbols"),
                "require_numbers": policy.get("RequireNumbers"),
            }
        except ClientError as exc:
            if str(exc.response.get("Error", {}).get("Code", "")) != "NoSuchEntity":
                raise
    except (BotoCoreError, ClientError) as exc:
        raise CheckError(f"AWS IAM collection failed: {exc}") from exc

    try:
        detectors: list[str] = []
        covered_regions: list[str] = []
        for region in regions:
            guardduty = session.client("guardduty", region_name=region)
            found = guardduty.list_detectors().get("DetectorIds", [])
            if found:
                covered_regions.append(region)
                detectors.extend(found)
    except (BotoCoreError, ClientError) as exc:
        raise CheckError(f"AWS GuardDuty collection failed: {exc}") from exc

    return {
        "account_id": str(session.client("sts", region_name=primary).get_caller_identity().get("Account", "")),
        "regions": list(regions),
        "cloudtrail": {"trails": trails},
        "iam": {
            "root_mfa_enabled": bool(summary.get("AccountMFAEnabled", 0)),
            "root_access_keys": bool(summary.get("AccountAccessKeysPresent", 0)),
            "password_policy": password_policy,
        },
        "s3_buckets": buckets,
        "guardduty": {
            "enabled": bool(detectors),
            "detectors": detectors,
            "regions": covered_regions,
        },
    }


def _snapshot(ctx: CheckContext) -> dict[str, Any]:
    if "aws" not in ctx.cache:
        ctx.cache["aws"] = _live_snapshot(ctx) if ctx.live else ctx.fixture("aws_config.json")
    return ctx.cache["aws"]


@register
class AwsCloudTrail(Check):
    id = "aws_cloudtrail"
    title = "AWS CloudTrail logging and log integrity"
    description = "Verifies a multi-region CloudTrail with log-file validation and management events."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        trails = snapshot.get("cloudtrail", {}).get("trails", [])
        evidence = [
            EvidenceItem(
                title="CloudTrail configuration",
                kind="config_snapshot",
                source=f"aws://{snapshot.get('account_id')}/cloudtrail",
                summary=f"{len(trails)} trail(s) discovered.",
                content={"account_id": snapshot.get("account_id"), "trails": trails},
            )
        ]

        if not trails:
            return self.result(
                CheckStatus.FAIL,
                "No CloudTrail trail is configured.",
                detail="Management activity across the account is not being recorded.",
                remediation="Create an organization trail with multi-region coverage, log-file validation "
                "and management events enabled; ship logs to a protected central account.",
                evidence=evidence,
                severity=Severity.CRITICAL,
            )

        active = [t for t in trails if t.get("is_logging")]
        if not active:
            return self.result(
                CheckStatus.FAIL,
                "CloudTrail exists but logging is stopped.",
                remediation="Start logging on the trail and investigate why it was disabled.",
                evidence=evidence,
                severity=Severity.CRITICAL,
            )

        gaps = []
        if not any(t.get("is_multi_region") for t in active):
            gaps.append("not multi-region")
        if not any(t.get("log_file_validation") for t in active):
            gaps.append("log-file validation disabled")
        if not any(t.get("management_events") for t in active):
            gaps.append("management events not recorded")

        if gaps:
            return self.result(
                CheckStatus.PARTIAL,
                f"CloudTrail is logging but has gaps: {', '.join(gaps)}.",
                detail="Activity outside the home region or unvalidated log files reduce audit coverage.",
                remediation="Enable multi-region logging and log-file validation on the organization trail.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            "CloudTrail is logging management events with multi-region coverage and log validation.",
            evidence=evidence,
        )


@register
class AwsRootMfa(Check):
    id = "aws_root_mfa"
    title = "AWS root account MFA and access keys"
    description = "Verifies that the root user has MFA enabled and no long-lived access keys."
    severity = Severity.CRITICAL

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        iam = snapshot.get("iam", {})
        mfa = bool(iam.get("root_mfa_enabled"))
        keys = bool(iam.get("root_access_keys"))
        evidence = [
            EvidenceItem(
                title="AWS root account posture",
                kind="api_response",
                source=f"aws://{snapshot.get('account_id')}/iam",
                summary=f"root_mfa={mfa}, root_access_keys={keys}",
                content={
                    "account_id": snapshot.get("account_id"),
                    "root_mfa_enabled": mfa,
                    "root_access_keys_present": keys,
                },
            )
        ]

        if not mfa:
            return self.result(
                CheckStatus.FAIL,
                "The AWS root account does not have MFA enabled.",
                detail="Root credentials can take irreversible account-level actions without a second factor.",
                remediation="Enable a hardware MFA device on the root account and store recovery codes in a "
                "controlled vault. Do not use root for daily operations.",
                evidence=evidence,
            )
        if keys:
            return self.result(
                CheckStatus.FAIL,
                "The AWS root account has active access keys.",
                detail="Long-lived root access keys are one of the highest-impact credential risks.",
                remediation="Delete root access keys, rotate anything that used them, and use IAM roles or "
                "short-lived credentials instead.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            "Root MFA is enabled and no root access keys exist.",
            evidence=evidence,
        )


@register
class AwsS3Protection(Check):
    id = "aws_s3_public_block"
    title = "S3 encryption and public access protection"
    description = "Checks every bucket for default encryption and a complete public access block."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        buckets = snapshot.get("s3_buckets", [])
        if not buckets:
            return self.result(
                CheckStatus.NOT_APPLICABLE,
                "No S3 buckets were found in the account.",
            )

        violations: list[dict[str, Any]] = []
        for bucket in buckets:
            encryption = str(bucket.get("encryption", "none")).lower()
            block = bucket.get("public_access_block", {})
            missing_block = [key for key, value in block.items() if not value]
            if encryption in ("none", "") or missing_block:
                violations.append(
                    {
                        "bucket": bucket.get("name"),
                        "encryption": bucket.get("encryption", "none"),
                        "missing_public_access_block": missing_block,
                    }
                )

        evidence = [
            EvidenceItem(
                title="S3 bucket security configuration",
                kind="config_snapshot",
                source=f"aws://{snapshot.get('account_id')}/s3",
                summary=f"{len(violations)} of {len(buckets)} buckets have gaps.",
                content={
                    "account_id": snapshot.get("account_id"),
                    "bucket_count": len(buckets),
                    "violations": violations,
                    "buckets": buckets,
                },
            )
        ]

        if violations:
            names = ", ".join(str(v["bucket"]) for v in violations)
            return self.result(
                CheckStatus.FAIL,
                f"{len(violations)} of {len(buckets)} S3 buckets have encryption or public-access gaps.",
                detail=f"Affected buckets: {names}. Public or unencrypted storage can expose regulated data.",
                remediation="Enable default SSE-KMS or SSE-S3 encryption and turn on all four S3 Block "
                "Public Access settings at the account and bucket level.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            f"All {len(buckets)} S3 buckets are encrypted and fully block public access.",
            evidence=evidence,
        )


@register
class AwsGuardDuty(Check):
    id = "aws_guardduty"
    title = "AWS GuardDuty threat detection"
    description = "Verifies that GuardDuty is enabled across the configured AWS regions."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        guardduty = snapshot.get("guardduty", {})
        enabled = bool(guardduty.get("enabled"))
        detectors = guardduty.get("detectors", [])
        covered = guardduty.get("regions", [])
        configured = snapshot.get("regions", [])
        evidence = [
            EvidenceItem(
                title="GuardDuty detector coverage",
                kind="api_response",
                source=f"aws://{snapshot.get('account_id')}/guardduty",
                summary=f"{len(detectors)} detector(s) across {len(covered)} region(s).",
                content={
                    "account_id": snapshot.get("account_id"),
                    "configured_regions": configured,
                    "covered_regions": covered,
                    "detector_count": len(detectors),
                },
            )
        ]

        if not enabled:
            return self.result(
                CheckStatus.FAIL,
                "GuardDuty is not enabled in the account.",
                detail="Threat detection for AWS control-plane and data-plane activity is missing.",
                remediation="Enable GuardDuty in every active region, preferably through an AWS "
                "Organizations delegated administrator.",
                evidence=evidence,
            )
        missing = sorted(set(configured) - set(covered))
        if missing:
            return self.result(
                CheckStatus.PARTIAL,
                f"GuardDuty is enabled but not covering: {', '.join(missing)}.",
                remediation="Enable GuardDuty detectors in the remaining active regions.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            f"GuardDuty is enabled across all {len(covered)} configured region(s).",
            evidence=evidence,
        )
