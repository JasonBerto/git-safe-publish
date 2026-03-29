"""Tests for git-safe-commit specific logic."""

import pytest
from git_safe_publish.config import Config
from git_safe_publish.scanner.secrets import scan_commit_message


def _config(**kwargs) -> Config:
    from git_safe_publish.config import DEFAULTS
    return Config({**DEFAULTS, **kwargs})


# ---------------------------------------------------------------------------
# _extract_commit_message (imported from cli)
# ---------------------------------------------------------------------------

from git_safe_publish.cli import _extract_commit_message


class TestExtractCommitMessage:
    def test_short_flag(self):
        assert _extract_commit_message(("-m", "feat: add login")) == "feat: add login"

    def test_long_flag(self):
        assert _extract_commit_message(("--message", "fix: broken auth")) == "fix: broken auth"

    def test_long_flag_equals_form(self):
        assert _extract_commit_message(("--message=my commit",)) == "my commit"

    def test_short_flag_attached(self):
        assert _extract_commit_message(("-mmy commit",)) == "my commit"

    def test_no_message_flag(self):
        assert _extract_commit_message(("--amend", "--no-edit")) is None

    def test_empty_args(self):
        assert _extract_commit_message(()) is None

    def test_message_with_other_flags(self):
        result = _extract_commit_message(("--all", "-m", "docs: update readme", "--signoff"))
        assert result == "docs: update readme"

    def test_returns_first_message_flag(self):
        result = _extract_commit_message(("-m", "first message", "-m", "second"))
        assert result == "first message"


# ---------------------------------------------------------------------------
# scan_commit_message
# ---------------------------------------------------------------------------

class TestScanCommitMessage:
    def test_clean_message(self):
        result = scan_commit_message("feat: add login page", "abc123", _config())
        assert result.is_clean

    def test_detects_aws_key_in_message(self):
        msg = "debug: hardcoded key AKIAIOSFODNN7EXAMPLE for testing"
        result = scan_commit_message(msg, "abc123", _config())
        assert not result.is_clean
        assert any(f.check_name == "aws-access-key-id" for f in result.findings)

    def test_detects_generic_api_key_in_message(self):
        # generic-api-key-assignment is P2, so requires severity_threshold P2 to surface
        msg = "wip: api_key = 'supersecretapikey'"
        result = scan_commit_message(msg, "abc123", _config(severity_threshold="P2"))
        assert not result.is_clean

    def test_commit_sha_stored_in_finding(self):
        msg = "AKIAIOSFODNN7EXAMPLE leaked in message"
        result = scan_commit_message(msg, "deadbeef", _config())
        assert not result.is_clean
        assert result.findings[0].commit_sha == "deadbeef"

    def test_placeholder_not_flagged(self):
        msg = "docs: update api_key = 'your-api-key-here'"
        result = scan_commit_message(msg, "abc123", _config())
        # The placeholder filter should suppress this
        aws = [f for f in result.findings if f.check_name == "aws-access-key-id"]
        assert not aws
