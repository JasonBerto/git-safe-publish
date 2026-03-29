"""Git metadata scanners: branch names, tag annotations, stash, submodules,
.git/hooks integrity, and GitHub Actions misconfiguration.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from git_safe_publish.config import Config
from git_safe_publish.models import Finding, ScanResult, Severity
from git_safe_publish.patterns import PATTERNS


def _build_patterns(config: Config):
    from git_safe_publish.scanner.secrets import _build_effective_patterns
    return _build_effective_patterns(config)


def _sev(s: str) -> Severity:
    return {"P0": Severity.P0, "P1": Severity.P1, "P2": Severity.P2, "P3": Severity.P3}.get(s, Severity.P2)


def _scan_text_for_secrets(text: str, source_label: str, config: Config) -> List[Finding]:
    """Run all patterns against a short piece of text (branch name, tag message, etc.)."""
    from git_safe_publish.scanner.secrets import _build_effective_patterns, _scan_line
    patterns = _build_effective_patterns(config)
    threshold = _sev(config.severity_threshold)
    findings = []
    for finding in _scan_line(text, source_label, 0, patterns, config):
        if finding.severity <= threshold:
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Branch name scanning
# ---------------------------------------------------------------------------

def scan_branch_names(repo: Path, config: Config) -> ScanResult:
    """Scan all local and remote branch names for embedded secrets."""
    from git_safe_publish.git import _out
    result = ScanResult()
    raw = _out("branch", "-a", "--format=%(refname:short)", cwd=repo)
    for branch_name in raw.splitlines():
        branch_name = branch_name.strip()
        if not branch_name:
            continue
        for finding in _scan_text_for_secrets(branch_name, f"<branch: {branch_name}>", config):
            finding.description = f"Secret found in branch name '{branch_name}': {finding.description}"
            finding.remediation = (
                f"Rename the branch: git branch -m {branch_name} <safe-name>\n"
                "  Then delete the old remote branch: git push origin --delete <old-name>"
            )
            result.add(finding)
    return result


# ---------------------------------------------------------------------------
# Tag annotation scanning
# ---------------------------------------------------------------------------

def scan_tag_annotations(repo: Path, config: Config) -> ScanResult:
    """Scan annotated tag messages for secrets."""
    from git_safe_publish.git import _out
    result = ScanResult()
    raw = _out(
        "for-each-ref", "--format=%(refname:short)|%(subject)|%(body)",
        "refs/tags", cwd=repo
    )
    for line in raw.splitlines():
        parts = line.split("|", 2)
        tag_name = parts[0].strip()
        message = " ".join(p.strip() for p in parts[1:] if p.strip())
        if not message:
            continue
        for finding in _scan_text_for_secrets(message, f"<tag: {tag_name}>", config):
            finding.description = f"Secret found in tag annotation '{tag_name}': {finding.description}"
            finding.remediation = (
                f"Delete and recreate the tag without the secret:\n"
                f"  git tag -d {tag_name}\n"
                f"  git push origin --delete {tag_name}\n"
                f"  git tag {tag_name} <commit-sha>"
            )
            result.add(finding)
    return result


# ---------------------------------------------------------------------------
# Stash scanning
# ---------------------------------------------------------------------------

def scan_stash(repo: Path, config: Config) -> ScanResult:
    """Scan git stash entries (descriptions and diffs) for secrets."""
    from git_safe_publish.git import _out
    from git_safe_publish.scanner.secrets import scan_diff, scan_commit_message

    result = ScanResult()
    raw = _out("stash", "list", cwd=repo)
    if not raw:
        return result

    for line in raw.splitlines():
        # Format: stash@{N}: WIP on branch: hash message
        stash_ref = line.split(":")[0].strip()
        description = line.strip()

        # Scan the stash description itself
        msg_result = scan_commit_message(description, stash_ref, config)
        for f in msg_result.findings:
            f.description = f"[stash] {f.description}"
            f.remediation = f"Drop this stash: git stash drop {stash_ref}"
        result.merge(msg_result)

        # Scan the stash diff
        diff = _out("stash", "show", "-p", stash_ref, cwd=repo)
        if diff:
            diff_result = scan_diff(diff, config, commit_sha=stash_ref, commit_message=description)
            for f in diff_result.findings:
                f.description = f"[stash] {f.description}"
                f.remediation = f"Drop this stash: git stash drop {stash_ref}"
            result.merge(diff_result)

    return result


# ---------------------------------------------------------------------------
# Submodule URL scanning
# ---------------------------------------------------------------------------

_INTERNAL_HOST_RE = re.compile(
    r"(internal|corp|private|intranet|local|dev|staging|prod)\.",
    re.IGNORECASE,
)
_PRIVATE_IP_RE = re.compile(
    r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
)


def scan_submodules(repo: Path, config: Config) -> ScanResult:
    """Scan .gitmodules for internal/private submodule URLs."""
    result = ScanResult()
    gitmodules = repo / ".gitmodules"
    if not gitmodules.exists():
        return result

    content = gitmodules.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line.startswith("url"):
            continue
        url = line.split("=", 1)[-1].strip()

        if _INTERNAL_HOST_RE.search(url):
            result.add(Finding(
                severity=Severity.P2,
                category="Submodules",
                check_name="submodule-internal-url",
                description=f"Submodule URL may point to an internal/private host: {url}",
                filename=".gitmodules",
                line_number=i,
                line_content=line,
                remediation=(
                    "If this repo is public, submodule URLs reveal internal infrastructure.\n"
                    "Consider mirroring the submodule to a public-facing URL."
                ),
            ))

        if _PRIVATE_IP_RE.search(url):
            result.add(Finding(
                severity=Severity.P1,
                category="Submodules",
                check_name="submodule-private-ip",
                description=f"Submodule URL contains a private IP address: {url}",
                filename=".gitmodules",
                line_number=i,
                line_content=line,
                remediation="Replace the private IP with a public-facing hostname.",
            ))

    return result


# ---------------------------------------------------------------------------
# Malicious hooks detection
# ---------------------------------------------------------------------------

_EXPECTED_HOOK_NAMES = {
    "pre-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "pre-push", "pre-rebase", "post-rewrite", "post-merge", "post-checkout",
    "pre-applypatch", "applypatch-msg", "post-applypatch",
    "pre-receive", "update", "post-receive", "post-update",
    "push-to-checkout", "pre-auto-gc", "post-index-change",
    "fsmonitor-watchman",
}

_GSP_MARKER = "# installed by git-safe-publish"


def scan_git_hooks(repo: Path, config: Config) -> ScanResult:
    """Detect unexpected or suspicious executable scripts in .git/hooks/."""
    result = ScanResult()
    hooks_dir = repo / ".git" / "hooks"
    if not hooks_dir.exists():
        return result

    for hook_path in hooks_dir.iterdir():
        name = hook_path.name
        if name.endswith(".sample"):
            continue
        if not hook_path.is_file():
            continue

        # Flag hooks with unknown names
        base_name = name.replace("-gsp", "")
        if base_name not in _EXPECTED_HOOK_NAMES:
            result.add(Finding(
                severity=Severity.P2,
                category="Hooks",
                check_name="unexpected-hook-file",
                description=f"Unexpected file in .git/hooks/: {name}",
                filename=f".git/hooks/{name}",
                remediation=(
                    f"Inspect and remove if not trusted: cat .git/hooks/{name}\n"
                    f"  rm .git/hooks/{name}"
                ),
            ))
            continue

        # Flag executable hooks not installed by git-safe-publish (in a cloned repo)
        if hook_path.stat().st_mode & 0o111:
            try:
                content = hook_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            if _GSP_MARKER not in content:
                result.add(Finding(
                    severity=Severity.P3,
                    category="Hooks",
                    check_name="unmanaged-hook",
                    description=(
                        f"Executable hook .git/hooks/{name} was not installed by git-safe-publish. "
                        "Verify its contents before trusting it."
                    ),
                    filename=f".git/hooks/{name}",
                    remediation=f"Review: cat .git/hooks/{name}",
                ))

    return result


# ---------------------------------------------------------------------------
# GitHub Actions misconfiguration checks
# ---------------------------------------------------------------------------

def scan_github_actions(repo: Path, config: Config) -> ScanResult:
    """Check .github/workflows/ for dangerous misconfigurations."""
    result = ScanResult()
    workflows_dir = repo / ".github" / "workflows"
    if not workflows_dir.exists():
        return result

    for wf_path in workflows_dir.glob("*.yml"):
        try:
            content = wf_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(wf_path.relative_to(repo))

        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            # Dangerous trigger: pull_request_target with checkout of fork code
            if "pull_request_target" in stripped:
                result.add(Finding(
                    severity=Severity.P1,
                    category="CI/CD",
                    check_name="gh-actions-pull-request-target",
                    description=(
                        "Workflow uses 'pull_request_target' trigger. "
                        "If fork code is checked out, this allows untrusted PRs to access repo secrets."
                    ),
                    filename=rel,
                    line_number=i,
                    line_content=stripped,
                    remediation=(
                        "Use 'pull_request' instead, or carefully scope what code runs.\n"
                        "  See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
                    ),
                ))

            # Overly permissive token permissions
            if re.search(r"permissions\s*:\s*write-all", stripped, re.IGNORECASE):
                result.add(Finding(
                    severity=Severity.P1,
                    category="CI/CD",
                    check_name="gh-actions-write-all-permissions",
                    description="Workflow sets permissions: write-all, granting excessive GITHUB_TOKEN scope.",
                    filename=rel,
                    line_number=i,
                    line_content=stripped,
                    remediation=(
                        "Scope permissions to the minimum needed, e.g.:\n"
                        "  permissions:\n"
                        "    contents: read"
                    ),
                ))

            # Actions pinned by tag not SHA
            m = re.search(r"uses:\s+([^@\s]+)@(v\d[\w\.\-]*)$", stripped)
            if m:
                action, ref = m.group(1), m.group(2)
                result.add(Finding(
                    severity=Severity.P3,
                    category="CI/CD",
                    check_name="gh-actions-unpinned-action",
                    description=(
                        f"Action '{action}@{ref}' is pinned by tag, not commit SHA. "
                        "A compromised tag could execute malicious code."
                    ),
                    filename=rel,
                    line_number=i,
                    line_content=stripped,
                    remediation=(
                        f"Pin by SHA: uses: {action}@<full-commit-sha>  # {ref}\n"
                        "  Use a tool like 'pin-github-action' to automate this."
                    ),
                ))

    return result
