from __future__ import annotations

import locale
import platform
import re
import subprocess

from cee.checks.base import Check, CheckContext, CheckError
from cee.checks.registry import register
from cee.models import CheckResult, CheckStatus, EvidenceItem, Severity

PASSWORD_PATTERNS = {
    "minimum_password_length": r"Minimum password length:\s*(\S+)",
    "maximum_password_age": r"Maximum password age \(days\):\s*(\S+)",
    "lockout_threshold": r"Lockout threshold:\s*(\S+)",
    "lockout_duration": r"Lockout duration \(minutes\):\s*(\S+)",
    "password_history": r"Length of password history maintained:\s*(\S+)",
}


def _decode(data: bytes) -> str:
    for encoding in (locale.getpreferredencoding(False), "utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _run(args: list[str]) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(f"Could not run {' '.join(args)}: {exc}") from exc
    output = _decode(proc.stdout + b"\n" + proc.stderr).strip()
    if proc.returncode != 0:
        raise CheckError(f"{' '.join(args)} exited with {proc.returncode}: {output[:300]}")
    return output


def _parse_password_policy(text: str) -> dict[str, str]:
    policy: dict[str, str] = {}
    for key, pattern in PASSWORD_PATTERNS.items():
        match = re.search(pattern, text, re.IGNORECASE)
        policy[key] = match.group(1).strip() if match else ""
    return policy


def _as_int(value: str) -> int | None:
    if not value:
        return None
    if value.lower() in ("never", "unlimited", "none"):
        return 0
    try:
        return int(value)
    except ValueError:
        return None


@register
class PasswordPolicy(Check):
    id = "windows_password_policy"
    title = "Password policy strength"
    description = "Parses the local Windows password policy (net accounts) against hardening baselines."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        if ctx.live and platform.system() != "Windows":
            return self.result(
                CheckStatus.NOT_APPLICABLE,
                "Password policy check is only implemented for Windows hosts.",
            )
        if ctx.live:
            raw = _run(["net", "accounts"])
            source = "net accounts"
        else:
            raw = ctx.fixture_text("net_accounts.txt")
            source = "demo fixture: net accounts"

        policy = _parse_password_policy(raw)
        values = {key: _as_int(value) for key, value in policy.items()}

        components: dict[str, dict] = {}
        length = values.get("minimum_password_length")
        if length is None:
            components["minimum_length"] = {"value": policy.get("minimum_password_length"), "score": 0.0}
        elif length >= 12:
            components["minimum_length"] = {"value": length, "score": 1.0}
        elif length >= 8:
            components["minimum_length"] = {"value": length, "score": 0.5}
        else:
            components["minimum_length"] = {"value": length, "score": 0.0}

        max_age = values.get("maximum_password_age")
        if max_age is None or max_age > 180:
            components["maximum_age"] = {"value": policy.get("maximum_password_age"), "score": 0.0}
        elif 0 < max_age <= 90:
            components["maximum_age"] = {"value": max_age, "score": 1.0}
        elif max_age == 0:
            components["maximum_age"] = {"value": "never expires", "score": 0.0}
        else:
            components["maximum_age"] = {"value": max_age, "score": 0.5}

        threshold = values.get("lockout_threshold")
        if threshold is None or threshold == 0:
            components["lockout_threshold"] = {"value": policy.get("lockout_threshold"), "score": 0.0}
        elif threshold <= 10:
            components["lockout_threshold"] = {"value": threshold, "score": 1.0}
        else:
            components["lockout_threshold"] = {"value": threshold, "score": 0.5}

        history = values.get("password_history")
        if history is None:
            components["password_history"] = {"value": policy.get("password_history"), "score": 0.0}
        elif history >= 24:
            components["password_history"] = {"value": history, "score": 1.0}
        elif history >= 12:
            components["password_history"] = {"value": history, "score": 0.5}
        else:
            components["password_history"] = {"value": history, "score": 0.0}

        scores = [item["score"] for item in components.values()]
        average = sum(scores) / len(scores) if scores else 0.0
        evidence = [
            EvidenceItem(
                title="Local password policy",
                kind="command_output",
                source=source,
                summary=f"Minimum length {policy.get('minimum_password_length', 'unknown')}; "
                f"lockout threshold {policy.get('lockout_threshold', 'unknown')}.",
                content={"parsed": policy, "components": components},
            ),
            EvidenceItem(
                title="Raw net accounts output",
                kind="command_output",
                source=source,
                summary="Raw password policy output captured from the host.",
                content=raw,
            ),
        ]

        if any(score == 0 for score in scores):
            return self.result(
                CheckStatus.FAIL,
                "The password policy has weaknesses that fall below the hardening baseline.",
                detail="; ".join(
                    f"{name}={item['value']}" for name, item in components.items() if item["score"] == 0
                ),
                remediation="Require at least 12 characters, a maximum age of 90 days or less, lockout "
                "after at most 10 attempts, and 24 remembered passwords.",
                evidence=evidence,
            )
        if average < 1:
            return self.result(
                CheckStatus.PARTIAL,
                f"Password policy is partially aligned (score {average * 100:.0f}%).",
                detail="; ".join(
                    f"{name}={item['value']}" for name, item in components.items() if item["score"] < 1
                ),
                remediation="Raise the minimum length to 12+ characters and keep lockout and history "
                "settings at the baseline.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.PASS,
            "Password policy meets the configured hardening baseline.",
            evidence=evidence,
        )


AUDIT_SETTING_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z][A-Za-z /]+?)\s{2,}"
    r"(?P<setting>Success and Failure|Success|Failure|No Auditing)\s*$",
    re.IGNORECASE,
)


def _parse_audit_policy(text: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in text.splitlines():
        match = AUDIT_SETTING_RE.match(line)
        if not match:
            continue
        name = match.group("name").strip()
        # Keep specific subcategories, not category headers.
        if name.lower() in ("logon/logoff", "account logon", "system", "policy change"):
            continue
        settings[name] = match.group("setting").strip()
    return settings


@register
class AuditPolicy(Check):
    id = "windows_audit_policy"
    title = "Windows security audit policy"
    description = "Verifies that logon, logoff and account lockout events are audited for success and failure."
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        if ctx.live and platform.system() != "Windows":
            return self.result(
                CheckStatus.NOT_APPLICABLE,
                "Audit policy check is only implemented for Windows hosts.",
            )
        if ctx.live:
            raw = _run(["auditpol", "/get", "/category:*"])
            source = "auditpol /get /category:*"
        else:
            raw = ctx.fixture_text("auditpol.txt")
            source = "demo fixture: auditpol /get /category:*"

        settings = _parse_audit_policy(raw)
        relevant = {
            name: settings.get(name, "No Auditing")
            for name in ("Logon", "Logoff", "Account Lockout", "Special Logon")
        }

        def full(name: str) -> bool:
            return relevant.get(name, "").lower() == "success and failure"

        fully_audited = full("Logon") and full("Account Lockout")
        any_audited = any(setting.lower() != "no auditing" for setting in relevant.values())

        evidence = [
            EvidenceItem(
                title="Audit policy for identity events",
                kind="command_output",
                source=source,
                summary="; ".join(f"{name}: {setting}" for name, setting in relevant.items()),
                content={"relevant_subcategories": relevant, "all_subcategories": settings},
            ),
            EvidenceItem(
                title="Raw auditpol output",
                kind="command_output",
                source=source,
                summary="Raw advanced audit policy output captured from the host.",
                content=raw,
            ),
        ]

        if fully_audited:
            return self.result(
                CheckStatus.PASS,
                "Logon and account lockout events are audited for both success and failure.",
                evidence=evidence,
            )
        if any_audited:
            return self.result(
                CheckStatus.PARTIAL,
                "Audit policy is enabled but does not record both success and failure for logon and "
                "account lockout.",
                detail="; ".join(f"{name}: {setting}" for name, setting in relevant.items()),
                remediation="Enable Success and Failure auditing for Logon, Account Lockout and Logoff "
                "through the Advanced Audit Policy Configuration.",
                evidence=evidence,
            )
        return self.result(
            CheckStatus.FAIL,
            "Logon and account lockout events are not being audited.",
            detail="Authentication activity cannot be reconstructed from host logs.",
            remediation="Enable Success and Failure auditing for Logon/Logoff and Account Logon, and "
            "forward Security events to the SIEM.",
            evidence=evidence,
            severity=Severity.CRITICAL,
        )
