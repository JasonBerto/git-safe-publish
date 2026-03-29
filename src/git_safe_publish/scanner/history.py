"""Full git history scanner (used by git-safe-search)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from git_safe_publish.config import Config
from git_safe_publish.git import get_all_commits, get_commit_diff, has_commits
from git_safe_publish.models import ScanResult
from git_safe_publish.scanner.secrets import scan_commit_message, scan_diff


def scan_history(
    repo: Path,
    config: Config,
    branch: str = "--all",
    limit: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> ScanResult:
    """
    Scan the full commit history for secrets.

    Args:
        repo:              Path to the repository root.
        config:            Loaded Config object.
        branch:            Which branch / ref to scan ("--all" = every ref).
        limit:             Maximum number of commits to scan (None = unlimited).
        progress_callback: Called as (current, total, sha) after each commit.

    Returns:
        A ScanResult aggregating all findings across all scanned commits.
    """
    result = ScanResult()

    if not has_commits(repo):
        return result

    commits = get_all_commits(repo, branch=branch)
    if limit:
        commits = commits[:limit]

    total = len(commits)

    for idx, commit in enumerate(commits, start=1):
        if progress_callback:
            progress_callback(idx, total, commit.sha)

        # Scan the diff (added lines only)
        diff = get_commit_diff(commit.sha, repo)
        diff_result = scan_diff(diff, config, commit_sha=commit.sha, commit_message=commit.message)
        result.merge(diff_result)

        # Scan the commit message itself
        msg_result = scan_commit_message(commit.message, commit.sha, config)
        result.merge(msg_result)

    return result
