"""Configuration loading for git-safe-publish.

Merges (in priority order):
  1. Repo-local  .git-safe-publish.yml
  2. Global      ~/.git-safe-publish.yml
  3. Built-in defaults
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS: Dict[str, Any] = {
    # Remotes that are considered "safe" to push to (regex list).
    # Empty means all remotes are allowed (with a warning for public ones).
    "allowed_remotes": [],

    # Branches that block force-push.
    "protected_branches": ["main", "master", "production", "prod", "release"],

    # Require committer email to match this regex (empty = no check).
    "required_email_pattern": "",

    # Warn (not block) if commits are unsigned.
    "require_signed_commits": False,

    # Extra regex patterns to scan for secrets (list of {name, regex, severity, category, description}).
    "custom_patterns": [],

    # Paths / globs to exclude from scanning.
    "ignore_paths": [],

    # Minimum severity to fail on: "P0" | "P1" | "P2" | "P3"
    "severity_threshold": "P0",

    # Whether to block on P0 or just warn.
    "block_on_secrets": True,

    # Whether to check .gitignore coverage.
    "check_gitignore": True,

    # Whether to validate author identity.
    "check_identity": True,

    # Whether to validate remote / branch safety.
    "check_remote": True,
}

CONFIG_FILENAMES = [".git-safe-publish.yml", ".git-safe-publish.yaml", ".git-safe-publish.json"]


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

class Config:
    def __init__(self, data: Dict[str, Any]) -> None:
        merged = {**DEFAULTS, **data}
        self.allowed_remotes: List[str] = merged["allowed_remotes"]
        self.protected_branches: List[str] = merged["protected_branches"]
        self.required_email_pattern: str = merged["required_email_pattern"]
        self.require_signed_commits: bool = bool(merged["require_signed_commits"])
        self.custom_patterns: List[Dict[str, str]] = merged["custom_patterns"]
        self.ignore_paths: List[str] = merged["ignore_paths"]
        self.severity_threshold: str = merged["severity_threshold"]
        self.block_on_secrets: bool = bool(merged["block_on_secrets"])
        self.check_gitignore: bool = bool(merged["check_gitignore"])
        self.check_identity: bool = bool(merged["check_identity"])
        self.check_remote: bool = bool(merged["check_remote"])

    def is_path_ignored(self, filepath: str) -> bool:
        import fnmatch
        for pattern in self.ignore_paths:
            if fnmatch.fnmatch(filepath, pattern):
                return True
        return False


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _load_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    if not _HAS_YAML:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


def load_config(repo_root: Optional[Path] = None) -> Config:
    """Load and merge config from repo-local and global locations."""
    # Global config
    global_path = Path.home() / ".git-safe-publish.yml"
    global_data = _load_file(global_path)

    # Repo-local config
    local_data: Dict[str, Any] = {}
    if repo_root:
        for name in CONFIG_FILENAMES:
            candidate = repo_root / name
            if candidate.exists():
                local_data = _load_file(candidate)
                break

    # Merge: global provides base, local overrides
    merged = {**global_data, **local_data}
    return Config(merged)


def write_default_config(path: Path) -> None:
    """Write a commented default config file to *path*."""
    template = """\
# git-safe-publish configuration
# https://github.com/your-org/git-safe-publish

# Regex patterns for allowed remote URLs (empty = all allowed, with warnings)
allowed_remotes: []

# Branches that cannot be force-pushed to
protected_branches:
  - main
  - master
  - production

# Require committer email to match this regex (empty = no check)
required_email_pattern: ""

# Require GPG/SSH signed commits
require_signed_commits: false

# Minimum severity level to report: P0 | P1 | P2 | P3
severity_threshold: "P0"

# Whether to block a push when secrets are found (vs. warn only)
block_on_secrets: true

# Enable/disable individual checks
check_gitignore: true
check_identity: true
check_remote: true

# Paths/globs to exclude from secret scanning
ignore_paths: []
#  - "tests/**"
#  - "*.example"

# Add custom secret patterns
custom_patterns: []
#  - name: my-internal-token
#    regex: "MYCO-[A-Za-z0-9]{32}"
#    severity: P0
#    category: Internal
#    description: "Acme Corp internal service token"
"""
    path.write_text(template, encoding="utf-8")
