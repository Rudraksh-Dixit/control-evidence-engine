from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlencode

import requests

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity, to_iso, utcnow

API = "https://api.github.com"
TIMEOUT = 20


def _headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "control-evidence-engine",
    }


def _get(path: str, token: str, params: dict[str, Any] | None = None) -> requests.Response:
    url = f"{API}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"
    try:
        return requests.get(url, headers=_headers(token), timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise CheckError(f"GitHub API request failed: {exc}") from exc


def _get_all(path: str, token: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    page = 1
    base_params = dict(params or {})
    while True:
        base_params.update({"per_page": 100, "page": page})
        response = _get(path, token, base_params)
        if response.status_code != 200:
            raise CheckError(f"GitHub API {path} returned {response.status_code}: {response.text[:200]}")
        payload = response.json()
        if not isinstance(payload, list):
            raise CheckError(f"GitHub API {path} did not return a list")
        items.extend(payload)
        if len(payload) < 100:
            break
        page += 1
    return items


def _live_snapshot(ctx: CheckContext) -> dict[str, Any]:
    org = str(ctx.setting("github.org", "") or "").strip()
    repo = str(ctx.setting("github.repo", "") or "").strip()
    token_env = str(ctx.setting("github.token_env", "GITHUB_TOKEN"))
    token = os.environ.get(token_env, "") or str(ctx.setting("github.token", "") or "")
    if not org or not repo:
        raise CheckError("github.org and github.repo must be configured in cee.yaml for live mode")
    if not token:
        raise CheckError(f"GitHub token not found. Set the {token_env} environment variable")

    repo_response = _get(f"/repos/{org}/{repo}", token)
    if repo_response.status_code != 200:
        raise CheckError(
            f"Cannot read GitHub repository {org}/{repo} "
            f"(HTTP {repo_response.status_code}). Check the token scope and repository name."
        )
    repo_data = repo_response.json()
    default_branch = repo_data.get("default_branch", "main")

    members: list[dict[str, Any]] = []
    mfa_known = True
    mfa_note = ""
    all_members = _get_all(f"/orgs/{org}/members", token)
    admin_response = _get(f"/orgs/{org}/members", token, {"role": "admin", "per_page": 100})
    admin_logins = (
        {item.get("login", "") for item in admin_response.json() if item.get("login")}
        if admin_response.status_code == 200
        else set()
    )
    disabled_response = _get(f"/orgs/{org}/members", token, {"filter": "2fa_disabled"})
    if disabled_response.status_code == 200:
        disabled = {item["login"] for item in disabled_response.json() if "login" in item}
        for member in all_members:
            login = member.get("login", "")
            members.append(
                {
                    "login": login,
                    "role": "admin" if login in admin_logins else "member",
                    "two_factor_enabled": login not in disabled,
                }
            )
    elif disabled_response.status_code in (403, 404):
        mfa_known = False
        mfa_note = (
            "GitHub did not expose org 2FA status. The token must belong to an organization owner "
            "with read:org scope."
        )
        for member in all_members:
            login = member.get("login", "")
            members.append(
                {
                    "login": login,
                    "role": "admin" if login in admin_logins else "member",
                    "two_factor_enabled": None,
                }
            )
    else:
        raise CheckError(
            f"GitHub 2FA query returned {disabled_response.status_code}: {disabled_response.text[:200]}"
        )

    protection: dict[str, Any] = {"enabled": False}
    protection_response = _get(f"/repos/{org}/{repo}/branches/{default_branch}/protection", token)
    if protection_response.status_code == 200:
        payload = protection_response.json()
        reviews = payload.get("required_pull_request_reviews") or {}
        protection = {
            "enabled": True,
            "required_approving_review_count": reviews.get("required_approving_review_count", 0),
            "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews", False)),
            "require_code_owner_reviews": bool(reviews.get("require_code_owner_reviews", False)),
            "enforce_admins": bool((payload.get("enforce_admins") or {}).get("enabled", False)),
            "allow_force_pushes": bool((payload.get("allow_force_pushes") or {}).get("enabled", False)),
            "required_status_checks": bool((payload.get("required_status_checks") or {}).get("enabled", False)),
        }
    elif protection_response.status_code == 404:
        protection = {"enabled": False}
    elif protection_response.status_code == 403:
        raise CheckError(
            "GitHub token cannot read branch protection (HTTP 403). Use a token with admin access "
            "to the repository."
        )
    else:
        raise CheckError(
            f"GitHub branch protection query returned {protection_response.status_code}: "
            f"{protection_response.text[:200]}"
        )

    security = repo_data.get("security_and_analysis") or {}

    def feature(name: str) -> str:
        node = security.get(name) or {}
        return str(node.get("status", "unavailable"))

    snapshot = {
        "org": org,
        "repo": repo,
        "default_branch": default_branch,
        "members": members,
        "members_2fa_known": mfa_known,
        "mfa_note": mfa_note,
        "repository": {
            "name": repo_data.get("name"),
            "private": bool(repo_data.get("private")),
            "branch_protection": protection,
            "security_and_analysis": {
                "secret_scanning": feature("secret_scanning"),
                "secret_scanning_push_protection": feature("secret_scanning_push_protection"),
            },
        },
        "collected_at": to_iso(utcnow()),
    }
    return snapshot


def _snapshot(ctx: CheckContext) -> dict[str, Any]:
    if "github" not in ctx.cache:
        ctx.cache["github"] = _live_snapshot(ctx) if ctx.live else ctx.fixture("github_org.json")
    return ctx.cache["github"]


@register
class GitHubMFA(Check):
    id = "github_mfa"
    title = "GitHub organization MFA enforcement"
    description = "Verifies that every member of the GitHub organization has two-factor authentication enabled."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        members = snapshot.get("members", [])
        total = len(members)
        known = bool(snapshot.get("members_2fa_known", True))
        disabled = [m.get("login", "") for m in members if m.get("two_factor_enabled") is False]
        admins = {m.get("login", "") for m in members if m.get("role") == "admin"}

        if not known:
            return self.result(
                CheckStatus.ERROR,
                "GitHub did not expose organization 2FA status, so MFA cannot be verified.",
                detail=snapshot.get("mfa_note", ""),
                remediation="Use a GitHub organization owner token with read:org scope, or provide a "
                "screenshot/export of the organization security settings as manual evidence.",
                evidence=[
                    EvidenceItem(
                        title="GitHub organization metadata",
                        kind="api_response",
                        source=f"github.com/{snapshot.get('org')}",
                        summary="MFA state unavailable from the API for this token.",
                        content={"org": snapshot.get("org"), "member_count": total, "error": "2fa_unavailable"},
                    )
                ],
            )

        if total == 0:
            return self.result(
                CheckStatus.ERROR,
                "No organization members were returned by GitHub.",
                remediation="Check github.org in cee.yaml and the token's read:org scope.",
            )

        evidence = [
            EvidenceItem(
                title="MFA status for organization members",
                kind="api_response",
                source=f"github.com/{snapshot.get('org')}",
                summary=f"{len(disabled)} of {total} members without 2FA.",
                content={
                    "org": snapshot.get("org"),
                    "member_count": total,
                    "members_without_2fa": disabled,
                    "admins_without_2fa": sorted(admins.intersection(disabled)),
                },
            )
        ]
        if disabled:
            return self.result(
                CheckStatus.FAIL,
                f"{len(disabled)} of {total} organization members do not have 2FA enabled.",
                detail="Affected accounts: " + ", ".join(sorted(disabled)) + ". Organization-wide MFA "
                "enforcement is not active.",
                remediation="Enable 'Require two-factor authentication' in GitHub organization settings "
                "and remove access for members who do not enroll.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            f"All {total} organization members have 2FA enabled.",
            evidence=evidence,
        )


@register
class GitHubBranchProtection(Check):
    id = "github_branch_protection"
    title = "Default branch protection and peer review"
    description = "Checks that the default branch requires pull-request review and blocks force pushes."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        repo = snapshot.get("repository", {})
        protection = repo.get("branch_protection", {})
        branch = snapshot.get("default_branch", "main")
        evidence = [
            EvidenceItem(
                title=f"Branch protection settings for {branch}",
                kind="config_snapshot",
                source=f"github.com/{snapshot.get('org')}/{snapshot.get('repo')}",
                summary=f"Protection enabled: {bool(protection.get('enabled'))}",
                content={
                    "repository": f"{snapshot.get('org')}/{snapshot.get('repo')}",
                    "branch": branch,
                    "protection": protection,
                },
            )
        ]

        if not protection.get("enabled"):
            return self.result(
                CheckStatus.FAIL,
                f"The default branch '{branch}' is not protected.",
                detail="Direct pushes, force pushes and branch deletion are possible without review.",
                remediation="Enable branch protection for the default branch with at least one required "
                "approving review, stale-review dismissal and force-push blocking.",
                evidence=evidence,
            )

        reviews = int(protection.get("required_approving_review_count", 0) or 0)
        gaps = []
        if reviews < 1:
            gaps.append("no required approving review")
        if not protection.get("dismiss_stale_reviews"):
            gaps.append("stale approvals are not dismissed")
        if protection.get("allow_force_pushes"):
            gaps.append("force pushes are allowed")
        if not protection.get("enforce_admins"):
            gaps.append("administrators can bypass protection")

        if not gaps:
            return self.result(
                CheckStatus.PASS,
                f"Branch protection on '{branch}' requires review and blocks force pushes.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PARTIAL,
            f"Branch protection exists on '{branch}' but has gaps: {', '.join(gaps)}.",
            detail="Protection is enabled, but the configuration does not fully enforce peer review "
            "and change control.",
            remediation="Require at least one approving review, dismiss stale approvals, disallow force "
            "pushes and include administrators in the rule.",
            evidence=evidence,
        )


@register
class GitHubSecretScanning(Check):
    id = "github_secret_scanning"
    title = "GitHub secret scanning and push protection"
    description = "Verifies that secret scanning is enabled and blocks pushes containing detected secrets."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        snapshot = _snapshot(ctx)
        repo = snapshot.get("repository", {})
        features = repo.get("security_and_analysis", {})
        scanning = str(features.get("secret_scanning", "unavailable"))
        push = str(features.get("secret_scanning_push_protection", "unavailable"))
        enabled = {"scanning": scanning == "enabled", "push_protection": push == "enabled"}

        evidence = [
            EvidenceItem(
                title="Secret scanning configuration",
                kind="config_snapshot",
                source=f"github.com/{snapshot.get('org')}/{snapshot.get('repo')}",
                summary=f"secret_scanning={scanning}, push_protection={push}",
                content={"repository": f"{snapshot.get('org')}/{snapshot.get('repo')}", **enabled},
            )
        ]

        if all(enabled.values()):
            return self.result(
                CheckStatus.PASS,
                "Secret scanning and push protection are both enabled.",
                evidence=evidence,
            )
        if any(enabled.values()):
            missing = [name for name, state in enabled.items() if not state]
            return self.result(
                CheckStatus.PARTIAL,
                f"Secret scanning is partially enabled; missing: {', '.join(missing)}.",
                remediation="Enable secret scanning and push protection for the repository (requires "
                "GitHub Advanced Security where applicable).",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.FAIL,
            "Secret scanning is not enabled for the repository.",
            detail="Committed credentials may not be detected or blocked.",
            remediation="Enable GitHub secret scanning and push protection. For non-GitHub systems, add "
            "a pre-commit secret scanner such as gitleaks.",
            evidence=evidence,
        )
