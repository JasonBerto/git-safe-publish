"""Author identity validation scanner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from git_safe_publish.config import Config
from git_safe_publish.git import (
    get_author_email,
    get_author_name,
    get_global_author_email,
    get_global_author_name,
    commit_signing_enabled,
)
from git_safe_publish.models import Finding, ScanResult, Severity


def scan_identity(repo: Path, config: Config) -> ScanResult:
    result = ScanResult()

    local_email = get_author_email(repo)
    local_name = get_author_name(repo)
    global_email = get_global_author_email()
    global_name = get_global_author_name()

    effective_email = local_email or global_email
    effective_name = local_name or global_name

    # Missing identity
    if not effective_email:
        result.add(Finding(
            severity=Severity.P1,
            category="Identity",
            check_name="missing-author-email",
            description="No git user.email configured. Commits will have an empty author email.",
            remediation="Run: git config user.email \"you@example.com\"",
        ))

    if not effective_name:
        result.add(Finding(
            severity=Severity.P2,
            category="Identity",
            check_name="missing-author-name",
            description="No git user.name configured.",
            remediation="Run: git config user.name \"Your Name\"",
        ))

    # Only global identity set (no repo-local override)
    if not local_email and global_email:
        result.add(Finding(
            severity=Severity.P2,
            category="Identity",
            check_name="global-email-only",
            description=(
                f"Using global git identity ({global_email}) — no repo-local user.email set. "
                "Commits may expose your personal email in a work/public repo."
            ),
            remediation=f"Run: git config user.email \"work@company.com\"  (in this repo)",
        ))

    # Required email pattern check
    if config.required_email_pattern and effective_email:
        if not re.match(config.required_email_pattern, effective_email):
            result.add(Finding(
                severity=Severity.P1,
                category="Identity",
                check_name="email-pattern-mismatch",
                description=(
                    f"Committer email '{effective_email}' does not match required pattern "
                    f"'{config.required_email_pattern}'."
                ),
                remediation=(
                    f"Run: git config user.email \"<email matching {config.required_email_pattern}>\""
                ),
            ))

    # Unsigned commits warning
    if config.require_signed_commits and not commit_signing_enabled(repo):
        result.add(Finding(
            severity=Severity.P2,
            category="Identity",
            check_name="unsigned-commits",
            description="Commit signing is not enabled for this repository.",
            remediation=(
                "Run: git config commit.gpgsign true\n"
                "  And ensure your GPG/SSH signing key is configured."
            ),
        ))

    return result
