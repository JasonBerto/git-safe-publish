"""gitignore coverage auditor.

Checks whether common sensitive file patterns are missing from .gitignore,
and detects tracked files that should be ignored.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import List, Optional

from git_safe_publish.config import Config
from git_safe_publish.models import Finding, ScanResult, Severity
from git_safe_publish.scanner.files import SENSITIVE_FILE_PATTERNS


# Patterns that should appear in every project's .gitignore
RECOMMENDED_IGNORES = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    ".aws/credentials",
    "*.tfvars",
    "*.tfstate",
    "*.log",
]


def _read_gitignore(repo: Path) -> List[str]:
    gi = repo / ".gitignore"
    if not gi.exists():
        return []
    lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]


def _is_covered(pattern: str, gitignore_lines: List[str]) -> bool:
    """Return True if *pattern* is covered by an existing .gitignore rule."""
    for line in gitignore_lines:
        # Exact match
        if line == pattern or line == f"/{pattern}":
            return True
        # The gitignore rule already subsumes the pattern via wildcard
        if fnmatch.fnmatch(pattern, line.lstrip("/")):
            return True
        # The pattern is a glob that subsumes the gitignore rule
        if fnmatch.fnmatch(line.lstrip("/"), pattern):
            return True
    return False


def scan_gitignore(repo: Path, config: Config) -> ScanResult:
    result = ScanResult()

    if not config.check_gitignore:
        return result

    gi_path = repo / ".gitignore"
    if not gi_path.exists():
        result.add(Finding(
            severity=Severity.P1,
            category=".gitignore",
            check_name="missing-gitignore",
            description="No .gitignore file found. Sensitive files may be accidentally committed.",
            remediation=(
                "Create a .gitignore file. Run `git-safe-check` to see recommended entries, "
                "or use https://gitignore.io to generate one for your stack."
            ),
        ))
        return result

    gi_lines = _read_gitignore(repo)

    missing: List[str] = []
    for pattern in RECOMMENDED_IGNORES:
        if not _is_covered(pattern, gi_lines):
            missing.append(pattern)

    if missing:
        result.add(Finding(
            severity=Severity.P2,
            category=".gitignore",
            check_name="gitignore-missing-patterns",
            description=(
                f"The following sensitive file patterns are not covered by .gitignore:\n"
                + "\n".join(f"    {p}" for p in missing)
            ),
            remediation=(
                "Add the missing patterns to .gitignore:\n"
                + "\n".join(f"  echo '{p}' >> .gitignore" for p in missing)
            ),
        ))

    return result


def suggest_gitignore_additions(repo: Path) -> List[str]:
    """Return a sorted list of .gitignore patterns worth adding."""
    gi_lines = _read_gitignore(repo)
    suggestions = []
    for pattern in RECOMMENDED_IGNORES:
        if not _is_covered(pattern, gi_lines):
            suggestions.append(pattern)
    return sorted(set(suggestions))
