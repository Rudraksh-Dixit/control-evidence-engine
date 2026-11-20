"""Check implementations.

Importing this package registers every bundled check.
"""

from cee.checks.aws import (  # noqa: F401
    AwsCloudTrail,
    AwsGuardDuty,
    AwsRootMfa,
    AwsS3Protection,
)
from cee.checks.backup import BackupFreshness  # noqa: F401
from cee.checks.github import (  # noqa: F401
    GitHubBranchProtection,
    GitHubMFA,
    GitHubSecretScanning,
)
from cee.checks.local import (  # noqa: F401
    AuditPolicy,
    PasswordPolicy,
)
from cee.checks.sigma import SigmaCoverage  # noqa: F401
from cee.checks.trivy import VulnerabilitySla  # noqa: F401
from cee.checks.wazuh import WazuhAlertPipeline  # noqa: F401
