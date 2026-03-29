"""Secret pattern scanner.

Scans unified diff output and raw file content for secrets.
Only added lines in diffs are scanned (lines starting with +),
reducing false positives from removed/context lines.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from git_safe_publish.config import Config
from git_safe_publish.models import Finding, ScanResult, Severity
from git_safe_publish.patterns import (
    PATTERNS,
    Pattern,
    is_high_entropy_b64,
    is_high_entropy_hex,
    is_placeholder,
)


# ---------------------------------------------------------------------------
# Redaction helper
# ---------------------------------------------------------------------------

_REDACT_RE = re.compile(r"([A-Za-z0-9/+=\-_]{6})[A-Za-z0-9/+=\-_]{8,}([A-Za-z0-9/+=\-_]{4})")


def _redact(line: str) -> str:
    """Replace the middle portion of secret-like strings with ***."""
    return _REDACT_RE.sub(r"\1***\2", line)


# ---------------------------------------------------------------------------
# Diff parser
# ---------------------------------------------------------------------------

def parse_diff_added_lines(diff: str) -> List[Tuple[str, int, str]]:
    """
    Parse a unified diff and return (filename, line_number, content)
    for every *added* line (prefix '+', excluding '+++' header lines).
    """
    results: List[Tuple[str, int, str]] = []
    current_file = "<unknown>"
    current_line = 0

    for raw_line in diff.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            current_line = 0
        elif raw_line.startswith("+++ /dev/null"):
            current_file = "<deleted>"
        elif raw_line.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw_line)
            if m:
                current_line = int(m.group(1)) - 1
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            results.append((current_file, current_line, raw_line[1:]))
        elif not raw_line.startswith("-"):
            current_line += 1

    return results


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def _build_effective_patterns(config: Config) -> List[Pattern]:
    patterns = list(PATTERNS)
    for cp in config.custom_patterns:
        try:
            patterns.append(Pattern(
                name=cp.get("name", "custom"),
                regex=cp["regex"],
                severity=cp.get("severity", "P1"),
                category=cp.get("category", "Custom"),
                description=cp.get("description", "Custom pattern"),
            ))
        except (KeyError, re.error):
            pass
    return patterns


def _severity_from_str(s: str) -> Severity:
    return {"P0": Severity.P0, "P1": Severity.P1, "P2": Severity.P2, "P3": Severity.P3}.get(s, Severity.P2)


def _scan_line(
    content: str,
    filename: str,
    line_number: int,
    patterns: List[Pattern],
    config: Config,
    commit_sha: str = "",
    commit_message: str = "",
) -> List[Finding]:
    from git_safe_publish.allowlist import is_inline_suppressed

    findings: List[Finding] = []

    for pattern in patterns:
        if is_inline_suppressed(content, pattern.name):
            continue
        for match in pattern.findall(content):
            matched_value = match.group(0)
            # Grab the last capturing group if present (usually the secret value).
            # Fall back to the full match if the group is None (optional group that didn't participate).
            if match.groups():
                captured = match.group(len(match.groups())) or matched_value
            else:
                captured = matched_value
            if is_placeholder(captured):
                continue
            findings.append(Finding(
                severity=_severity_from_str(pattern.severity),
                category=pattern.category,
                check_name=pattern.name,
                description=pattern.description,
                filename=filename,
                line_number=line_number,
                line_content=_redact(content.strip()),
                commit_sha=commit_sha,
                commit_message=commit_message,
                remediation=_remediation_for(pattern.name),
            ))
            break  # one finding per pattern per line is enough

    # High-entropy heuristic on token-like substrings
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", content):
        if is_high_entropy_b64(token) and not is_placeholder(token):
            findings.append(Finding(
                severity=Severity.P2,
                category="Generic",
                check_name="high-entropy-base64",
                description=f"High-entropy base64-like string ({len(token)} chars)",
                filename=filename,
                line_number=line_number,
                line_content=_redact(content.strip()),
                commit_sha=commit_sha,
                commit_message=commit_message,
                remediation="Verify this is not a hardcoded secret. Use environment variables or a secrets manager.",
            ))
            break  # one per line

    for token in re.findall(r"[0-9a-fA-F]{32,}", content):
        if is_high_entropy_hex(token) and not is_placeholder(token):
            findings.append(Finding(
                severity=Severity.P2,
                category="Generic",
                check_name="high-entropy-hex",
                description=f"High-entropy hex string ({len(token)} chars)",
                filename=filename,
                line_number=line_number,
                line_content=_redact(content.strip()),
                commit_sha=commit_sha,
                commit_message=commit_message,
                remediation="Verify this is not a hardcoded secret.",
            ))
            break

    return findings


def _remediation_for(pattern_name: str) -> str:
    remediations = {
        "aws-access-key-id": "Revoke this key immediately at https://console.aws.amazon.com/iam. Use IAM roles or aws-vault.",
        "aws-secret-access-key": "Revoke this key immediately at https://console.aws.amazon.com/iam. Use IAM roles or aws-vault.",
        "github-token-classic": "Revoke at https://github.com/settings/tokens. Use environment variables or GitHub Actions secrets.",
        "github-token-fine-grained": "Revoke at https://github.com/settings/tokens. Use GitHub Actions secrets.",
        "gitlab-pat": "Revoke at GitLab → Profile → Access Tokens. Use CI/CD variables.",
        "private-key-pem": "This key is now compromised. Generate a new key pair and revoke/replace the exposed one.",
        "stripe-secret-key": "Revoke at https://dashboard.stripe.com/apikeys immediately.",
        "openai-api-key": "Revoke at https://platform.openai.com/api-keys. Use environment variables.",
        "anthropic-api-key": "Revoke at https://console.anthropic.com/settings/keys.",
        "slack-bot-token": "Revoke at https://api.slack.com/apps. Regenerate the token.",
        "database-url-with-creds": "Rotate the database password immediately. Use environment variables or a secrets manager.",
        "generic-password-assignment": "Move this value to an environment variable or secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).",
        "generic-api-key-assignment": "Move this value to an environment variable or secrets manager.",
        "generic-secret-assignment": "Move this value to an environment variable or secrets manager.",
        "generic-token-assignment": "Move this value to an environment variable or secrets manager.",
    }
    default = "Remove this secret from source code. Use environment variables, a secrets manager, or git-crypt."
    return remediations.get(pattern_name, default)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_diff(
    diff: str,
    config: Config,
    commit_sha: str = "",
    commit_message: str = "",
) -> ScanResult:
    """Scan a unified diff for secrets (added lines only)."""
    result = ScanResult()
    patterns = _build_effective_patterns(config)
    threshold = _severity_from_str(config.severity_threshold)

    for filename, line_number, content in parse_diff_added_lines(diff):
        if config.is_path_ignored(filename):
            continue
        for finding in _scan_line(content, filename, line_number, patterns, config, commit_sha, commit_message):
            if finding.severity <= threshold:
                result.add(finding)

    return result


def scan_commit_message(
    message: str,
    commit_sha: str,
    config: Config,
) -> ScanResult:
    """Scan a commit message for embedded secrets."""
    result = ScanResult()
    patterns = _build_effective_patterns(config)
    threshold = _severity_from_str(config.severity_threshold)

    for finding in _scan_line(message, "<commit message>", 0, patterns, config, commit_sha, message):
        if finding.severity <= threshold:
            result.add(finding)

    return result


def scan_file_content(
    content: str,
    filename: str,
    config: Config,
) -> ScanResult:
    """Scan the full content of a file line-by-line."""
    result = ScanResult()
    patterns = _build_effective_patterns(config)
    threshold = _severity_from_str(config.severity_threshold)

    if config.is_path_ignored(filename):
        return result

    for line_number, line in enumerate(content.splitlines(), start=1):
        for finding in _scan_line(line, filename, line_number, patterns, config):
            if finding.severity <= threshold:
                result.add(finding)

    return result
