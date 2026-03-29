"""Tests for the diff scanner."""

import pytest
from git_safe_publish.config import Config
from git_safe_publish.scanner.secrets import parse_diff_added_lines, scan_diff, scan_file_content


def _config(**kwargs) -> Config:
    from git_safe_publish.config import DEFAULTS
    return Config({**DEFAULTS, **kwargs})


# ---------------------------------------------------------------------------
# parse_diff_added_lines
# ---------------------------------------------------------------------------

SAMPLE_DIFF = """\
diff --git a/config.py b/config.py
index abc..def 100644
--- a/config.py
+++ b/config.py
@@ -1,4 +1,6 @@
 import os
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
+PASSWORD = "hunter2"
-OLD_LINE = "gone"
 OTHER = "fine"
"""


class TestParseDiff:
    def test_extracts_added_lines(self):
        lines = parse_diff_added_lines(SAMPLE_DIFF)
        contents = [c for _, _, c in lines]
        assert any("AKIAIOSFODNN7EXAMPLE" in c for c in contents)
        assert any("hunter2" in c for c in contents)

    def test_skips_removed_lines(self):
        lines = parse_diff_added_lines(SAMPLE_DIFF)
        contents = [c for _, _, c in lines]
        assert not any("OLD_LINE" in c for c in contents)

    def test_skips_context_lines(self):
        lines = parse_diff_added_lines(SAMPLE_DIFF)
        contents = [c for _, _, c in lines]
        assert not any("import os" in c for c in contents)

    def test_correct_filename(self):
        lines = parse_diff_added_lines(SAMPLE_DIFF)
        assert all(f == "config.py" for f, _, _ in lines)


# ---------------------------------------------------------------------------
# scan_diff
# ---------------------------------------------------------------------------

class TestScanDiff:
    def test_detects_aws_key(self):
        diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""
        result = scan_diff(diff, _config())
        assert not result.is_clean
        check_names = [f.check_name for f in result.findings]
        assert "aws-access-key-id" in check_names

    def test_detects_private_key(self):
        diff = """\
diff --git a/id_rsa b/id_rsa
--- /dev/null
+++ b/id_rsa
@@ -0,0 +1,1 @@
+-----BEGIN RSA PRIVATE KEY-----
"""
        result = scan_diff(diff, _config())
        assert not result.is_clean

    def test_clean_diff_returns_no_findings(self):
        diff = """\
diff --git a/readme.md b/readme.md
--- a/readme.md
+++ b/readme.md
@@ -1,1 +1,1 @@
+# Hello world
"""
        result = scan_diff(diff, _config())
        assert result.is_clean

    def test_ignored_path_skipped(self):
        diff = """\
diff --git a/tests/fixture.py b/tests/fixture.py
--- /dev/null
+++ b/tests/fixture.py
@@ -0,0 +1,1 @@
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
"""
        result = scan_diff(diff, _config(ignore_paths=["tests/**"]))
        # Should be empty because path is ignored
        aws_findings = [f for f in result.findings if f.check_name == "aws-access-key-id"]
        assert not aws_findings

    def test_removed_lines_not_flagged(self):
        diff = """\
diff --git a/old.py b/old.py
--- a/old.py
+++ b/old.py
@@ -1,1 +1,0 @@
-SECRET = "AKIAIOSFODNN7EXAMPLE"
"""
        result = scan_diff(diff, _config())
        assert result.is_clean


# ---------------------------------------------------------------------------
# scan_file_content
# ---------------------------------------------------------------------------

class TestScanFileContent:
    def test_detects_stripe_key(self):
        content = 'STRIPE_KEY = "sk_live_' + "a" * 24 + '"'
        result = scan_file_content(content, "settings.py", _config())
        assert not result.is_clean
        assert any(f.check_name == "stripe-secret-key" for f in result.findings)

    def test_clean_content(self):
        content = "x = 1\ny = 2\n"
        result = scan_file_content(content, "math.py", _config())
        assert result.is_clean

    def test_line_numbers_correct(self):
        content = "# comment\n# comment\nAPI_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        result = scan_file_content(content, "app.py", _config())
        aws = [f for f in result.findings if f.check_name == "aws-access-key-id"]
        assert aws
        assert aws[0].line_number == 3
