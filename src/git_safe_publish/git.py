"""Thin subprocess wrapper around git CLI operations."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


class GitError(Exception):
    pass


class NotAGitRepo(GitError):
    pass


# ---------------------------------------------------------------------------
# Low-level runner
# ---------------------------------------------------------------------------

def _run(
    *args: str,
    cwd: Optional[Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise GitError(result.stderr.strip() or result.stdout.strip())
    return result


def _out(*args: str, cwd: Optional[Path] = None) -> str:
    """Run git command, return stripped stdout (empty string on failure)."""
    try:
        return _run(*args, cwd=cwd).stdout.strip()
    except GitError:
        return ""


# ---------------------------------------------------------------------------
# Repo detection
# ---------------------------------------------------------------------------

def find_repo_root(path: Optional[Path] = None) -> Path:
    """Return the root of the git repo containing *path* (default: cwd)."""
    cwd = path or Path.cwd()
    result = _run("rev-parse", "--show-toplevel", cwd=cwd, check=False)
    if result.returncode != 0:
        raise NotAGitRepo(f"Not inside a git repository: {cwd}")
    return Path(result.stdout.strip())


def is_git_repo(path: Optional[Path] = None) -> bool:
    cwd = path or Path.cwd()
    r = _run("rev-parse", "--git-dir", cwd=cwd, check=False)
    return r.returncode == 0


def has_commits(repo: Path) -> bool:
    r = _run("rev-parse", "HEAD", cwd=repo, check=False)
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Author / identity
# ---------------------------------------------------------------------------

def get_config_value(key: str, repo: Optional[Path] = None) -> str:
    return _out("config", key, cwd=repo)


def get_author_name(repo: Optional[Path] = None) -> str:
    return get_config_value("user.name", repo)


def get_author_email(repo: Optional[Path] = None) -> str:
    return get_config_value("user.email", repo)


def get_global_author_email() -> str:
    r = _run("config", "--global", "user.email", check=False)
    return r.stdout.strip()


def get_global_author_name() -> str:
    r = _run("config", "--global", "user.name", check=False)
    return r.stdout.strip()


def commit_signing_enabled(repo: Optional[Path] = None) -> bool:
    val = get_config_value("commit.gpgsign", repo).lower()
    return val in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Diffs
# ---------------------------------------------------------------------------

def get_staged_diff(repo: Path) -> str:
    """Return unified diff of staged (index vs HEAD) changes."""
    if not has_commits(repo):
        # First commit: diff against empty tree
        empty_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        return _out("diff", "--cached", empty_tree, cwd=repo)
    return _out("diff", "--cached", "HEAD", cwd=repo)


def get_unstaged_diff(repo: Path) -> str:
    return _out("diff", "HEAD", cwd=repo)


def get_commit_diff(sha: str, repo: Path) -> str:
    return _out("show", "--patch", "--no-color", sha, cwd=repo)


# ---------------------------------------------------------------------------
# Commit log
# ---------------------------------------------------------------------------

@dataclass
class Commit:
    sha: str
    author_name: str
    author_email: str
    message: str
    date: str


def get_all_commits(repo: Path, branch: str = "--all") -> List[Commit]:
    """Return all commits reachable from *branch* (default: all refs)."""
    sep = "\x00"
    fmt = f"%H{sep}%an{sep}%ae{sep}%s{sep}%ci"
    flags = [branch] if branch != "--all" else ["--all"]
    raw = _out("log", *flags, f"--format={fmt}", "--no-merges", cwd=repo)
    commits = []
    for line in raw.splitlines():
        parts = line.split(sep)
        if len(parts) == 5:
            sha, name, email, msg, date = parts
            commits.append(Commit(sha, name, email, msg, date))
    return commits


def get_commits_to_push(repo: Path, remote: str = "origin", branch: Optional[str] = None) -> List[Commit]:
    """Return commits that exist locally but not on the remote."""
    current = branch or get_current_branch(repo)
    remote_ref = f"{remote}/{current}"
    r = _run("rev-parse", "--verify", remote_ref, cwd=repo, check=False)
    if r.returncode != 0:
        # Branch not on remote yet — return all commits on branch
        return get_all_commits(repo, branch=current)

    sep = "\x00"
    fmt = f"%H{sep}%an{sep}%ae{sep}%s{sep}%ci"
    raw = _out("log", f"{remote_ref}..{current}", f"--format={fmt}", cwd=repo)
    commits = []
    for line in raw.splitlines():
        parts = line.split(sep)
        if len(parts) == 5:
            sha, name, email, msg, date = parts
            commits.append(Commit(sha, name, email, msg, date))
    return commits


# ---------------------------------------------------------------------------
# Branch / remote
# ---------------------------------------------------------------------------

def get_current_branch(repo: Path) -> str:
    r = _run("branch", "--show-current", cwd=repo, check=False)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    # Detached HEAD
    return _out("rev-parse", "--short", "HEAD", cwd=repo) or "HEAD"


def get_remotes(repo: Path) -> List[str]:
    raw = _out("remote", cwd=repo)
    return [r for r in raw.splitlines() if r]


def get_remote_url(repo: Path, remote: str = "origin") -> str:
    return _out("remote", "get-url", remote, cwd=repo)


def remote_branch_exists(repo: Path, remote: str, branch: str) -> bool:
    ref = f"refs/remotes/{remote}/{branch}"
    r = _run("rev-parse", "--verify", ref, cwd=repo, check=False)
    return r.returncode == 0


def would_require_force_push(repo: Path, remote: str = "origin", branch: Optional[str] = None) -> bool:
    """Return True if a push would require --force (local and remote have diverged)."""
    current = branch or get_current_branch(repo)
    remote_ref = f"{remote}/{current}"
    r = _run("rev-parse", "--verify", remote_ref, cwd=repo, check=False)
    if r.returncode != 0:
        return False
    r2 = _run("merge-base", "--is-ancestor", remote_ref, "HEAD", cwd=repo, check=False)
    return r2.returncode != 0


# ---------------------------------------------------------------------------
# Tracked files / .gitignore
# ---------------------------------------------------------------------------

def get_tracked_files(repo: Path) -> List[str]:
    raw = _out("ls-files", cwd=repo)
    return [f for f in raw.splitlines() if f]


def get_staged_files(repo: Path) -> List[Tuple[str, str]]:
    """Return list of (status, filename) for staged files."""
    if not has_commits(repo):
        empty_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        raw = _out("diff", "--cached", "--name-status", empty_tree, cwd=repo)
    else:
        raw = _out("diff", "--cached", "--name-status", "HEAD", cwd=repo)
    result = []
    for line in raw.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            result.append((parts[0].strip(), parts[1].strip()))
    return result


def get_gitignore_path(repo: Path) -> Optional[Path]:
    p = repo / ".gitignore"
    return p if p.exists() else None


def get_file_content_at(sha: str, filepath: str, repo: Path) -> str:
    """Return the content of a file at a specific commit."""
    r = _run("show", f"{sha}:{filepath}", cwd=repo, check=False)
    return r.stdout if r.returncode == 0 else ""


def get_diff_from_base(repo: Path, base: str) -> str:
    """Return diff of all changes between base and HEAD (for PR-style checks)."""
    return _out("diff", f"{base}...HEAD", cwd=repo)


def get_all_branch_names(repo: Path) -> List[str]:
    raw = _out("branch", "-a", "--format=%(refname:short)", cwd=repo)
    return [b.strip() for b in raw.splitlines() if b.strip()]


def get_tag_list(repo: Path) -> List[Tuple[str, str]]:
    """Return list of (tag_name, subject_line) for all tags."""
    raw = _out(
        "for-each-ref", "--format=%(refname:short)|%(subject)",
        "refs/tags", cwd=repo,
    )
    result = []
    for line in raw.splitlines():
        parts = line.split("|", 1)
        if len(parts) == 2:
            result.append((parts[0].strip(), parts[1].strip()))
    return result


def get_stash_list(repo: Path) -> List[str]:
    raw = _out("stash", "list", cwd=repo)
    return [l for l in raw.splitlines() if l]


def get_stash_diff(stash_ref: str, repo: Path) -> str:
    return _out("stash", "show", "-p", "--no-color", stash_ref, cwd=repo)


def get_commit_date(sha: str, repo: Path) -> str:
    return _out("log", "-1", "--format=%ci", sha, cwd=repo)
