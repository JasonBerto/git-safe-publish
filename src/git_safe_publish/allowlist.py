"""Allowlist support for persistent false-positive suppression.

Findings can be suppressed in two ways:
  1. Inline:  add `# gsp-ignore` or `# gsp-ignore: check-name` on the offending line.
  2. Allowlist file: `.git-safe-allowlist.yml` in the repo root (or global ~/.git-safe-allowlist.yml).

Allowlist file format:
  - check_name: aws-access-key-id
    filename: tests/fixtures/config.py   # optional, "" = any file
    line_hash: sha256 of the line content # optional, "" = any line
    reason: "Test fixture, not a real key"
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from git_safe_publish.models import Finding


# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------

_GSP_IGNORE_RE = re.compile(
    r"#\s*gsp-ignore(?:\s*:\s*([a-z0-9\-]+(?:\s*,\s*[a-z0-9\-]+)*))?",
    re.IGNORECASE,
)


def is_inline_suppressed(line: str, check_name: str) -> bool:
    """Return True if *line* contains a gsp-ignore comment covering *check_name*."""
    m = _GSP_IGNORE_RE.search(line)
    if not m:
        return False
    names_str = m.group(1)
    if not names_str:
        return True  # bare `# gsp-ignore` suppresses everything
    names = {n.strip().lower() for n in names_str.split(",")}
    return check_name.lower() in names


# ---------------------------------------------------------------------------
# Allowlist entry & file
# ---------------------------------------------------------------------------

@dataclass
class AllowlistEntry:
    check_name: str               # "" = match any check
    filename: str = ""            # "" = match any file
    line_hash: str = ""           # SHA-256 of stripped line content, "" = match any
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.check_name and self.check_name != finding.check_name:
            return False
        if self.filename and self.filename not in finding.filename:
            return False
        if self.line_hash:
            actual = hashlib.sha256(finding.line_content.encode()).hexdigest()
            if actual != self.line_hash:
                return False
        return True


@dataclass
class Allowlist:
    entries: List[AllowlistEntry] = field(default_factory=list)

    def is_allowed(self, finding: Finding) -> bool:
        return any(e.matches(finding) for e in self.entries)

    def filter(self, findings: list) -> list:
        return [f for f in findings if not self.is_allowed(f)]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_ALLOWLIST_FILENAMES = [".git-safe-allowlist.yml", ".git-safe-allowlist.yaml"]


def _load_entries(path: Path) -> List[AllowlistEntry]:
    if not path.exists() or not _HAS_YAML:
        return []
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    if not isinstance(data, list):
        return []
    entries = []
    for item in data:
        if not isinstance(item, dict):
            continue
        entries.append(AllowlistEntry(
            check_name=str(item.get("check_name", "")),
            filename=str(item.get("filename", "")),
            line_hash=str(item.get("line_hash", "")),
            reason=str(item.get("reason", "")),
        ))
    return entries


def load_allowlist(repo_root: Optional[Path] = None) -> Allowlist:
    """Load and merge allowlist from repo-local and global locations."""
    entries: List[AllowlistEntry] = []

    global_path = Path.home() / ".git-safe-allowlist.yml"
    entries.extend(_load_entries(global_path))

    if repo_root:
        for name in _ALLOWLIST_FILENAMES:
            candidate = repo_root / name
            if candidate.exists():
                entries.extend(_load_entries(candidate))
                break

    return Allowlist(entries=entries)


def write_allowlist_entry(
    finding: Finding,
    repo_root: Path,
    reason: str = "",
) -> None:
    """Append a finding as an allowlist entry to the repo-local allowlist file."""
    path = repo_root / ".git-safe-allowlist.yml"
    line_hash = hashlib.sha256(finding.line_content.encode()).hexdigest()

    entry_yaml = (
        f"- check_name: {finding.check_name}\n"
        f"  filename: {finding.filename}\n"
        f"  line_hash: {line_hash}\n"
        f"  reason: \"{reason or 'Manually allowed'}\"\n"
    )

    with open(path, "a", encoding="utf-8") as fh:
        if path.stat().st_size == 0:
            fh.write("# git-safe-publish allowlist\n# https://github.com/JasonBerto/git-safe-publish\n\n")
        fh.write(entry_yaml)
