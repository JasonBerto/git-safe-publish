"""Full git history scanner (used by git-safe-search) with exposure window tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from git_safe_publish.config import Config
from git_safe_publish.git import get_all_commits, get_commit_date, get_commit_diff, has_commits
from git_safe_publish.models import Finding, ScanResult
from git_safe_publish.scanner.secrets import scan_commit_message, scan_diff


# ---------------------------------------------------------------------------
# Exposure window
# ---------------------------------------------------------------------------

@dataclass
class ExposureWindow:
    check_name: str
    filename: str
    first_commit_sha: str
    first_commit_date: str
    last_commit_sha: str
    last_commit_date: str
    commit_count: int

    @property
    def summary(self) -> str:
        return (
            f"{self.check_name} in '{self.filename}': "
            f"first seen {self.first_commit_date[:10]}, "
            f"last seen {self.last_commit_date[:10]} "
            f"({self.commit_count} commit(s))"
        )


def _window_key(finding: Finding) -> str:
    return f"{finding.check_name}|{finding.filename}"


def compute_exposure_windows(findings: List[Finding]) -> List[ExposureWindow]:
    """
    Given a list of findings from a history scan (oldest→newest commit order),
    compute how long each unique (check_name, filename) pair was exposed.
    """
    windows: Dict[str, dict] = {}
    for f in findings:
        if not f.commit_sha or not f.commit_date if hasattr(f, "commit_date") else False:
            continue
        key = _window_key(f)
        if key not in windows:
            windows[key] = {
                "check_name": f.check_name,
                "filename": f.filename,
                "first_sha": f.commit_sha,
                "first_date": getattr(f, "commit_date", ""),
                "last_sha": f.commit_sha,
                "last_date": getattr(f, "commit_date", ""),
                "count": 0,
            }
        windows[key]["last_sha"] = f.commit_sha
        windows[key]["last_date"] = getattr(f, "commit_date", "")
        windows[key]["count"] += 1

    return [
        ExposureWindow(
            check_name=v["check_name"],
            filename=v["filename"],
            first_commit_sha=v["first_sha"],
            first_commit_date=v["first_date"],
            last_commit_sha=v["last_sha"],
            last_commit_date=v["last_date"],
            commit_count=v["count"],
        )
        for v in windows.values()
    ]


# ---------------------------------------------------------------------------
# History scanner
# ---------------------------------------------------------------------------

def scan_history(
    repo: Path,
    config: Config,
    branch: str = "--all",
    limit: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    track_dates: bool = False,
    commits: Optional[list] = None,
) -> ScanResult:
    """
    Scan a set of commits for secrets.

    Args:
        repo:              Path to the repository root.
        config:            Loaded Config object.
        branch:            Which branch / ref to scan if *commits* is None.
        limit:             Maximum number of commits to scan (only used if *commits* is None).
        progress_callback: Called as (current, total, sha) after each commit.
        track_dates:       If True, attach commit_date to findings (for exposure windows).
        commits:           Pre-filtered list of Commit objects; if provided, branch/limit are ignored.

    Returns:
        A ScanResult aggregating all findings across all scanned commits.
    """
    result = ScanResult()

    if not has_commits(repo):
        return result

    if commits is None:
        commits = get_all_commits(repo, branch=branch)
        if limit:
            commits = commits[:limit]

    total = len(commits)

    for idx, commit in enumerate(commits, start=1):
        if progress_callback:
            progress_callback(idx, total, commit.sha)

        diff = get_commit_diff(commit.sha, repo)
        diff_result = scan_diff(diff, config, commit_sha=commit.sha, commit_message=commit.message)

        if track_dates:
            date = commit.date
            for f in diff_result.findings:
                f.__dict__["commit_date"] = date

        result.merge(diff_result)

        msg_result = scan_commit_message(commit.message, commit.sha, config)
        if track_dates:
            for f in msg_result.findings:
                f.__dict__["commit_date"] = commit.date
        result.merge(msg_result)

    return result
    """
    Scan the full commit history for secrets.

    Args:
        repo:              Path to the repository root.
        config:            Loaded Config object.
        branch:            Which branch / ref to scan ("--all" = every ref).
        limit:             Maximum number of commits to scan (None = unlimited).
        progress_callback: Called as (current, total, sha) after each commit.
        track_dates:       If True, attach commit_date to findings (for exposure windows).

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

        diff = get_commit_diff(commit.sha, repo)
        diff_result = scan_diff(diff, config, commit_sha=commit.sha, commit_message=commit.message)

        if track_dates:
            date = commit.date
            for f in diff_result.findings:
                f.__dict__["commit_date"] = date

        result.merge(diff_result)

        msg_result = scan_commit_message(commit.message, commit.sha, config)
        if track_dates:
            for f in msg_result.findings:
                f.__dict__["commit_date"] = commit.date
        result.merge(msg_result)

    return result
