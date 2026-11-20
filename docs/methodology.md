# Methodology

This document explains how Control Evidence Engine turns system telemetry into a control assessment, and where the boundaries of that assessment are.

## 1. Evidence lifecycle

```text
collect -> normalize -> hash -> map -> assess -> report -> verify
```

1. **Collect.** A check talks to one system (GitHub API, AWS API, Wazuh log, Trivy report, Windows command, filesystem) and returns facts, not a verdict about compliance.
2. **Normalize.** Every check returns the same `CheckResult` shape: status, severity, summary, detail, remediation and a list of evidence items. Evidence items are structured JSON, not screenshots.
3. **Hash.** Evidence is written to `runs/<run-id>/evidence/<check>/` and hashed with SHA-256 over canonical JSON (`sort_keys=True`, compact separators, UTF-8). The artifact path and hash are recorded in `run.json`.
4. **Map.** The framework YAML maps each control to zero or more check IDs. The mapping is the only place where control semantics live.
5. **Assess.** The engine computes control status and score, generates findings, and builds theme summaries.
6. **Report.** Jinja2 renders a self-contained HTML report and a Markdown report.
7. **Verify.** `python -m cee verify` reloads each artifact, recomputes the canonical hash, and compares it with the recorded value. Manual documents are hashed as raw bytes.

## 2. Check contract

Every check subclasses `cee.checks.base.Check` and implements `run(ctx) -> CheckResult`:

```python
@register
class MyCheck(Check):
    id = "my_check"
    title = "What this verifies"
    severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> CheckResult:
        data = collect_something()
        return self.result(
            CheckStatus.PARTIAL,
            "One of three requirements is missing.",
            detail="...",
            remediation="...",
            evidence=[EvidenceItem(
                title="Configuration snapshot",
                kind="config_snapshot",
                source="system://path",
                content=data,
            )],
        )
```

Rules:

- **No control IDs in checks.** The catalog owns the mapping.
- **No swallowing exceptions.** Raise `CheckError` with a fixable message; the engine converts it to an `error` result.
- **No fabricated evidence.** If a system cannot be reached, the check errors.
- **Evidence must be explainable.** Include the configuration or log excerpt that justifies the status, plus a source string.
- **Remediation is mandatory for fail/partial results.** The report should tell an owner what to change.

Register the class in `cee/checks/__init__.py`, then add its ID to a control's `checks:` list in the framework YAML. `tests/test_catalog.py` fails if a catalog check is unknown or a registered check is unmapped.

## 3. Status model

| Check status | Score | Meaning |
|---|---:|---|
| `pass` | 1.0 | The check's requirements are fully met |
| `partial` | 0.5 | Some requirements met; a documented gap remains |
| `fail` | 0.0 | Requirements are not met |
| `error` | 0.0 | The check could not run or its evidence failed verification |
| `not_applicable` | excluded | Not relevant to this host or environment |

Control status:

| Control status | Derivation |
|---|---|
| `compliant` | All applicable checks passed |
| `partial` | At least one pass and at least one non-pass, or check scores average between 0 and 1 |
| `non_compliant` | No applicable check passed |
| `attested` | No automated check, and at least one valid manual attestation |
| `manual` | No automated check and no attestation |
| `error` | All checks errored, attestation hash mismatch, or configured check did not run |
| `not_applicable` | Every mapped check is not applicable |

A control with multiple checks averages their scores. Example from the demo: A.5.17 maps to `github_mfa` (fail = 0.0) and `windows_password_policy` (partial = 0.5), so the control score is 25% and its status is partial.

## 4. Assurance score

```text
score = mean(score of every compliant, partial, non-compliant or attested control)
```

Manual-pending controls are excluded. This is deliberate:

- A policy document that has not been attached is not evidence.
- A control with no automated check should not lower the technical score until evidence exists.
- The report always shows how many controls were excluded, so the score cannot be read as full-framework coverage.

Bands:

| Score | Band |
|---|---|
| 85.0–100 | strong |
| 65.0–84.9 | moderate |
| 40.0–64.9 | needs improvement |
| 0–39.9 | critical |

The demo scores 59.8% across 11 assessed controls: 3 compliant, 5 partial, 2 non-compliant, 1 attested.

## 5. Findings

A finding is created for every check with status `fail`, `partial` or `error`. Findings are ordered by severity (critical, high, medium, low, info) and then check ID. Each finding carries:

- a stable ID (`F-001`...),
- the originating check,
- all mapped controls,
- the observed condition,
- the remediation action.

Failures with `error` status are configuration or visibility gaps, not evidence of control failure; the report keeps them visible so they are not mistaken for passes.

## 6. Manual attestation

Manual controls are the majority of any ISO 27001 program. CEE does not pretend to automate them.

`python -m cee attest` copies the evidence file into `manual_evidence/<control>/`, records the SHA-256, attester, timestamp and note in `manual_evidence/index.json`, and copies valid files into the run bundle. During assessment a control becomes `attested` only if:

1. at least one attestation exists,
2. the file still exists, and
3. the current file hash matches the recorded hash.

Any mismatch produces an `error` control and a visible `HASH MISMATCH` in the report. Re-attest after changing a document.

## 7. Evidence integrity model

- Automated artifacts: SHA-256 over canonical JSON of the evidence content.
- Manual documents: SHA-256 over the raw file bytes.
- `run.json` binds each hash to an artifact path.
- `audit-bundle.zip` contains the report, run metadata and all artifacts.
- `verify` recomputes hashes; it cannot detect deletion of an entire run directory, so retain bundles in immutable storage for real audit use.

This is tamper-evident, not tamper-proof. An attacker with write access to both the artifacts and `run.json` can rewrite both. Production deployments should ship bundles to WORM storage or an append-only evidence store and sign `run.json` with an external key. That is on the roadmap.

## 8. Data handling

Evidence may include usernames, hostnames, bucket names, internal paths and alert descriptions. Before sharing a bundle externally:

- review `run.json` and artifacts for sensitive identifiers,
- avoid attaching raw authentication logs as manual evidence,
- prefer configuration snapshots and aggregated samples,
- redact data at the check level in a fork if needed.

Live credentials are read from the environment (`GITHUB_TOKEN`) or the standard AWS credential chain; they are never written to run output. `cee.yaml` is gitignored and should not contain secrets.

## 9. Adding a framework

Create `cee/frameworks/<id>.yaml`:

```yaml
framework:
  id: soc2-2017
  name: SOC 2 Trust Services Criteria
  version: "2017"
  description: ...
  source: ...
controls:
  - id: CC6.1
    title: Logical access controls
    theme: technological
    objective: ...
    evidence_expectation: ...
    checks:
      - github_mfa
      - aws_root_mfa
    references:
      - AICPA TSC CC6.1
```

`theme` must be one of `organizational`, `people`, `physical`, `technological`; the theme names are presentation concepts and can be adjusted for non-ISO frameworks. Then run `python -m cee assess --framework soc2-2017`.

## 10. Limitations

- 36 of 93 Annex A controls are cataloged. Coverage is intentionally focused on controls that engineering telemetry can support.
- Checks are point-in-time. There is no scheduler in this repository; GitHub Actions runs a demo assessment on every push and weekly.
- Windows checks are local and assume English output.
- The GitHub MFA check requires organization-owner access; otherwise it returns `error` rather than guessing.
- No risk-acceptance or exception lifecycle yet. Overdue findings cannot be formally accepted with an expiry date.
- No multi-tenant database. Runs are directories, which keeps the project portable and auditable.
- Compliance conclusions require human review. The tool supplies evidence and gap analysis; it does not certify anything.
