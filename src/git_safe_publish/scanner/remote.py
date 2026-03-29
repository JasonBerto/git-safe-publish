"""Remote and branch safety scanner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from git_safe_publish.config import Config
from git_safe_publish.git import (
    get_current_branch,
    get_remote_url,
    get_remotes,
    would_require_force_push,
)
from git_safe_publish.models import Finding, ScanResult, Severity


# Known public hosting domains that warrant a warning for "private" pushes
_PUBLIC_HOSTS = re.compile(
    r"(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sourcehut\.org)",
    re.IGNORECASE,
)


def _is_public_remote(url: str) -> bool:
    return bool(_PUBLIC_HOSTS.search(url))


def _remote_looks_insecure(url: str) -> bool:
    return url.startswith("git://") or url.startswith("http://")


def scan_remote(
    repo: Path,
    config: Config,
    target_remote: str = "origin",
    target_branch: Optional[str] = None,
    force: bool = False,
) -> ScanResult:
    result = ScanResult()
    branch = target_branch or get_current_branch(repo)

    # ---- Remote URL checks ------------------------------------------------
    remotes = get_remotes(repo)
    if not remotes:
        result.add(Finding(
            severity=Severity.P2,
            category="Remote",
            check_name="no-remotes-configured",
            description="No git remotes configured. Nothing to push to.",
            remediation="Run: git remote add origin <url>",
        ))
        return result

    if target_remote not in remotes:
        result.add(Finding(
            severity=Severity.P1,
            category="Remote",
            check_name="remote-not-found",
            description=f"Remote '{target_remote}' does not exist. Available: {', '.join(remotes)}",
            remediation=f"Run: git remote add {target_remote} <url>",
        ))
        return result

    remote_url = get_remote_url(repo, target_remote)

    # Insecure protocol
    if _remote_looks_insecure(remote_url):
        result.add(Finding(
            severity=Severity.P1,
            category="Remote",
            check_name="insecure-remote-protocol",
            description=f"Remote '{target_remote}' uses an insecure protocol: {remote_url}",
            remediation="Switch to SSH (git@github.com:…) or HTTPS (https://github.com/…).",
        ))

    # Allowed remote pattern check
    if config.allowed_remotes:
        allowed = any(re.search(pattern, remote_url) for pattern in config.allowed_remotes)
        if not allowed:
            result.add(Finding(
                severity=Severity.P1,
                category="Remote",
                check_name="remote-not-in-allowlist",
                description=(
                    f"Remote URL '{remote_url}' is not in the configured allowed_remotes list."
                ),
                remediation=(
                    "Add this remote to allowed_remotes in .git-safe-publish.yml, "
                    "or verify you are pushing to the correct repository."
                ),
            ))

    # ---- Branch checks ----------------------------------------------------
    if branch in config.protected_branches:
        result.add(Finding(
            severity=Severity.P1,
            category="Branch",
            check_name="direct-push-to-protected",
            description=f"Pushing directly to protected branch '{branch}'. Consider using a pull request.",
            remediation=(
                f"Create a feature branch: git checkout -b feature/my-change\n"
                f"  Then open a PR to merge into '{branch}'."
            ),
        ))

    # Force push check
    if force and branch in config.protected_branches:
        result.add(Finding(
            severity=Severity.P0,
            category="Branch",
            check_name="force-push-to-protected",
            description=f"Force pushing to protected branch '{branch}' — this rewrites shared history.",
            remediation="Never force push to a shared/protected branch.",
        ))
    elif not force and would_require_force_push(repo, target_remote, branch):
        result.add(Finding(
            severity=Severity.P1,
            category="Branch",
            check_name="diverged-history-needs-force",
            description=(
                f"Local branch '{branch}' has diverged from '{target_remote}/{branch}'. "
                "A push would require --force."
            ),
            remediation=(
                f"Pull and rebase first: git pull --rebase {target_remote} {branch}\n"
                f"  If you intend to overwrite, use git-safe-push --force (will require confirmation)."
            ),
        ))

    return result
