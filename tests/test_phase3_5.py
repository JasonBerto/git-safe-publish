"""Tests for Phase 3–5 features: allowlist, metadata scanner, inline suppression,
new CLI commands (hooks, fix, scan), and output formats (SARIF, markdown).
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from git_safe_publish.allowlist import Allowlist, AllowlistEntry, is_inline_suppressed
from git_safe_publish.models import Finding, ScanResult, Severity
from git_safe_publish.patterns import PATTERNS, PATTERN_MAP


# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------

class TestInlineSuppression:
    def test_bare_gsp_ignore_suppresses_all(self):
        assert is_inline_suppressed("STRIPE_KEY = 'sk_live_xxx'  # gsp-ignore", "stripe-secret-key")

    def test_specific_check_suppressed(self):
        assert is_inline_suppressed(
            "KEY = 'xyz'  # gsp-ignore: aws-access-key-id", "aws-access-key-id"
        )

    def test_specific_check_does_not_suppress_other(self):
        assert not is_inline_suppressed(
            "KEY = 'xyz'  # gsp-ignore: aws-access-key-id", "stripe-secret-key"
        )

    def test_multiple_checks_suppressed(self):
        line = "URL = 'x'  # gsp-ignore: stripe-secret-key, aws-access-key-id"
        assert is_inline_suppressed(line, "stripe-secret-key")
        assert is_inline_suppressed(line, "aws-access-key-id")

    def test_no_marker_not_suppressed(self):
        assert not is_inline_suppressed("KEY = 'real_secret_value'", "aws-access-key-id")

    def test_case_insensitive(self):
        assert is_inline_suppressed("key = 'x'  # GSP-IGNORE", "any-check")

    def test_scan_line_respects_suppression(self):
        """The _scan_line function should skip flagged lines with gsp-ignore."""
        from git_safe_publish.scanner.secrets import _scan_line, _build_effective_patterns
        from git_safe_publish.config import load_config

        config = load_config(None)
        patterns = _build_effective_patterns(config)

        # Stripe key on a suppressed line should produce no findings
        line = "STRIPE_KEY = 'sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # gsp-ignore"
        findings = _scan_line(line, "test.py", 1, patterns, config)
        assert len(findings) == 0, "Suppressed line should produce no findings"


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:
    def _finding(self, check_name="aws-access-key-id", filename="src/config.py",
                 line_content="AKIAIOSFODNN7EXAMPLE") -> Finding:
        return Finding(
            severity=Severity.P0,
            category="Cloud — AWS",
            check_name=check_name,
            description="AWS access key",
            filename=filename,
            line_number=1,
            line_content=line_content,
        )

    def test_empty_allowlist_allows_nothing(self):
        al = Allowlist()
        f = self._finding()
        assert not al.is_allowed(f)

    def test_exact_match_allowed(self):
        import hashlib
        line = "AKIAIOSFODNN7EXAMPLE"
        h = hashlib.sha256(line.encode()).hexdigest()
        al = Allowlist(entries=[AllowlistEntry(
            check_name="aws-access-key-id",
            filename="src/config.py",
            line_hash=h,
        )])
        assert al.is_allowed(self._finding())

    def test_wildcard_check_name(self):
        """Empty check_name matches any check."""
        al = Allowlist(entries=[AllowlistEntry(check_name="", filename="")])
        assert al.is_allowed(self._finding())

    def test_wrong_filename_not_allowed(self):
        import hashlib
        line = "AKIAIOSFODNN7EXAMPLE"
        h = hashlib.sha256(line.encode()).hexdigest()
        al = Allowlist(entries=[AllowlistEntry(
            check_name="aws-access-key-id",
            filename="other/file.py",
            line_hash=h,
        )])
        assert not al.is_allowed(self._finding())

    def test_filter_removes_allowed(self):
        al = Allowlist(entries=[AllowlistEntry(check_name="aws-access-key-id", filename="")])
        f1 = self._finding(check_name="aws-access-key-id")
        f2 = self._finding(check_name="stripe-secret-key")
        result = al.filter([f1, f2])
        assert len(result) == 1
        assert result[0].check_name == "stripe-secret-key"


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

class TestSARIF:
    def _result(self) -> ScanResult:
        return ScanResult([
            Finding(
                severity=Severity.P0,
                category="Cloud — AWS",
                check_name="aws-access-key-id",
                description="AWS access key ID",
                filename="src/config.py",
                line_number=10,
                line_content="AKIAIOSFODNN7EXAMPLE",
                commit_sha="abc123",
            )
        ])

    def test_sarif_top_level_structure(self):
        from git_safe_publish.report import format_as_sarif
        sarif = format_as_sarif(self._result())
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_has_rules(self):
        from git_safe_publish.report import format_as_sarif
        sarif = format_as_sarif(self._result())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert any(r["id"] == "aws-access-key-id" for r in rules)

    def test_sarif_results_count(self):
        from git_safe_publish.report import format_as_sarif
        sarif = format_as_sarif(self._result())
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_result_level_p0(self):
        from git_safe_publish.report import format_as_sarif
        sarif = format_as_sarif(self._result())
        r = sarif["runs"][0]["results"][0]
        assert r["level"] == "error"

    def test_sarif_empty_result(self):
        from git_safe_publish.report import format_as_sarif
        sarif = format_as_sarif(ScanResult())
        assert sarif["runs"][0]["results"] == []

    def test_sarif_to_json(self):
        import json
        from git_safe_publish.report import format_as_sarif
        sarif = format_as_sarif(self._result())
        # Must be JSON-serialisable
        text = json.dumps(sarif)
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

class TestMarkdown:
    def _result(self) -> ScanResult:
        return ScanResult([
            Finding(
                severity=Severity.P1,
                category="Cloud — AWS",
                check_name="aws-secret-access-key",
                description="AWS secret access key",
                filename="settings.py",
                line_number=5,
                line_content="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            )
        ])

    def test_markdown_has_header(self):
        from git_safe_publish.report import format_as_markdown
        md = format_as_markdown(self._result())
        assert "## git-safe-publish report" in md

    def test_markdown_clean_result(self):
        from git_safe_publish.report import format_as_markdown
        md = format_as_markdown(ScanResult())
        assert "No issues found" in md

    def test_markdown_table_contains_check_name(self):
        from git_safe_publish.report import format_as_markdown
        md = format_as_markdown(self._result())
        assert "aws-secret-access-key" in md
        assert "settings.py" in md

    def test_markdown_scope_in_output(self):
        from git_safe_publish.report import format_as_markdown
        md = format_as_markdown(ScanResult(), scope="PR #42")
        assert "PR #42" in md


# ---------------------------------------------------------------------------
# Absolute path disclosure pattern
# ---------------------------------------------------------------------------

class TestAbsolutePathPattern:
    def test_home_user_path_detected(self):
        assert "absolute-path-disclosure" in PATTERN_MAP
        pat = PATTERN_MAP["absolute-path-disclosure"]
        assert re.search(pat.regex, "/home/jsmith/secrets/database.conf")

    def test_users_macos_path_detected(self):
        pat = PATTERN_MAP["absolute-path-disclosure"]
        assert re.search(pat.regex, "/Users/jdoe/work/project/config.py")

    def test_relative_path_not_detected(self):
        pat = PATTERN_MAP["absolute-path-disclosure"]
        assert not re.search(pat.regex, "./relative/path.conf")

    def test_short_path_not_detected(self):
        pat = PATTERN_MAP["absolute-path-disclosure"]
        # Only one level after username
        assert not re.search(pat.regex, "/home/jsmith/file.py")


# ---------------------------------------------------------------------------
# CI template generation
# ---------------------------------------------------------------------------

class TestCITemplates:
    def test_github_template_contains_sarif(self):
        from git_safe_publish.cli import _CI_TEMPLATES
        github = _CI_TEMPLATES["github"]
        assert "sarif" in github.lower()
        assert "git-safe-search" in github

    def test_gitlab_template_contains_image(self):
        from git_safe_publish.cli import _CI_TEMPLATES
        gitlab = _CI_TEMPLATES["gitlab"]
        assert "python:" in gitlab

    def test_pre_commit_template_has_hook(self):
        from git_safe_publish.cli import _CI_TEMPLATES
        pc = _CI_TEMPLATES["pre-commit"]
        assert "git-safe-check" in pc


# ---------------------------------------------------------------------------
# Hook templates
# ---------------------------------------------------------------------------

class TestHookTemplates:
    def test_pre_commit_hook_has_marker(self):
        from git_safe_publish.cli import _HOOK_TEMPLATES
        assert "git-safe-publish" in _HOOK_TEMPLATES["pre-commit"]

    def test_all_three_hooks_defined(self):
        from git_safe_publish.cli import _HOOK_TEMPLATES
        assert "pre-commit" in _HOOK_TEMPLATES
        assert "commit-msg" in _HOOK_TEMPLATES
        assert "pre-push" in _HOOK_TEMPLATES

    def test_hooks_are_sh_scripts(self):
        from git_safe_publish.cli import _HOOK_TEMPLATES
        for name, content in _HOOK_TEMPLATES.items():
            assert content.startswith("#!/bin/sh"), f"{name} hook missing shebang"


# ---------------------------------------------------------------------------
# Patterns count sanity check
# ---------------------------------------------------------------------------

class TestPatternsCount:
    def test_patterns_count_grew(self):
        """Should have more patterns than v0.2.0 (which had ~34)."""
        assert len(PATTERNS) >= 35, f"Expected at least 35 patterns, got {len(PATTERNS)}"

    def test_absolute_path_pattern_present(self):
        names = {p.name for p in PATTERNS}
        assert "absolute-path-disclosure" in names
