"""Tests for secret pattern detection."""

import pytest
from git_safe_publish.patterns import PATTERNS, is_placeholder, is_high_entropy_b64, is_high_entropy_hex


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _matches(pattern_name: str, text: str) -> bool:
    pat = next((p for p in PATTERNS if p.name == pattern_name), None)
    assert pat is not None, f"Pattern '{pattern_name}' not found"
    return bool(pat.compiled.search(text))


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

class TestAWSPatterns:
    def test_access_key_id_matches(self):
        assert _matches("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE")

    def test_access_key_id_no_match_short(self):
        assert not _matches("aws-access-key-id", "AKIAI123")

    def test_secret_access_key_matches(self):
        line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert _matches("aws-secret-access-key", line)

    def test_access_key_in_env(self):
        assert _matches("aws-access-key-id", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

class TestGitHubPatterns:
    def test_classic_pat(self):
        assert _matches("github-token-classic", "ghp_" + "A" * 36)

    def test_oauth_token(self):
        assert _matches("github-oauth-token", "gho_" + "B" * 36)

    def test_app_token(self):
        assert _matches("github-app-token", "ghs_" + "C" * 36)

    def test_fine_grained(self):
        assert _matches("github-token-fine-grained", "github_pat_" + "D" * 82)

    def test_no_match_random_string(self):
        assert not _matches("github-token-classic", "not_a_token_abc123")


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------

class TestGitLabPatterns:
    def test_pat_matches(self):
        assert _matches("gitlab-pat", "glpat-" + "x" * 20)

    def test_no_match_short(self):
        assert not _matches("gitlab-pat", "glpat-short")


# ---------------------------------------------------------------------------
# Private key
# ---------------------------------------------------------------------------

class TestPrivateKeyPattern:
    def test_rsa_key(self):
        assert _matches("private-key-pem", "-----BEGIN RSA PRIVATE KEY-----")

    def test_ec_key(self):
        assert _matches("private-key-pem", "-----BEGIN EC PRIVATE KEY-----")

    def test_openssh_key(self):
        assert _matches("private-key-pem", "-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_generic_private_key(self):
        assert _matches("private-key-pem", "-----BEGIN PRIVATE KEY-----")


# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------

class TestStripePatterns:
    def test_live_secret(self):
        assert _matches("stripe-secret-key", "sk_live_" + "a" * 24)

    def test_live_restricted(self):
        assert _matches("stripe-restricted-key", "rk_live_" + "b" * 24)

    def test_publishable_key(self):
        assert _matches("stripe-publishable-key", "pk_live_" + "c" * 24)

    def test_test_key_no_match(self):
        assert not _matches("stripe-secret-key", "sk_test_" + "a" * 24)


# ---------------------------------------------------------------------------
# Database URLs
# ---------------------------------------------------------------------------

class TestDatabaseURLPatterns:
    def test_postgres_url(self):
        assert _matches("database-url-with-creds", "postgresql://user:pass@localhost/db")

    def test_mysql_url(self):
        assert _matches("database-url-with-creds", "mysql://admin:secret@db.host/mydb")

    def test_mongodb_url(self):
        assert _matches("database-url-with-creds", "mongodb://root:hunter2@mongo:27017/db")

    def test_url_without_creds_no_match(self):
        assert not _matches("database-url-with-creds", "postgresql://localhost/db")


# ---------------------------------------------------------------------------
# Generic patterns
# ---------------------------------------------------------------------------

class TestGenericPatterns:
    def test_api_key_assignment_single_quotes(self):
        assert _matches("generic-api-key-assignment", "api_key = 'abcdefghijklmnop'")

    def test_api_key_assignment_double_quotes(self):
        assert _matches("generic-api-key-assignment", 'API_KEY = "supersecretvalue"')

    def test_password_assignment(self):
        assert _matches("generic-password-assignment", 'password = "myS3cr3tPass!"')

    def test_short_password_no_match(self):
        # Passwords < 4 chars not matched
        assert not _matches("generic-password-assignment", 'password = "abc"')

    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert _matches("jwt-token", token)


# ---------------------------------------------------------------------------
# OpenAI / Anthropic
# ---------------------------------------------------------------------------

class TestAIPatterns:
    def test_openai_key(self):
        assert _matches("openai-api-key", "sk-" + "a" * 48)

    def test_anthropic_key(self):
        assert _matches("anthropic-api-key", "sk-ant-api03-" + "x" * 93)


# ---------------------------------------------------------------------------
# Placeholder filter
# ---------------------------------------------------------------------------

class TestPlaceholderFilter:
    def test_your_api_key(self):
        assert is_placeholder("your-api-key-here")

    def test_example_value(self):
        assert is_placeholder("example_token")

    def test_template_syntax(self):
        assert is_placeholder("${MY_SECRET}")

    def test_real_value_not_placeholder(self):
        assert not is_placeholder("AKIAIOSFODNN7EXAMPLE")


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

class TestEntropyHelpers:
    def test_high_entropy_b64_real(self):
        # A base64-encoded 32-byte random key has high entropy
        import base64, os
        random_b64 = base64.b64encode(os.urandom(32)).decode()
        assert is_high_entropy_b64(random_b64)

    def test_low_entropy_b64(self):
        assert not is_high_entropy_b64("AAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    def test_short_string_not_high_entropy(self):
        assert not is_high_entropy_b64("abc")

    def test_high_entropy_hex(self):
        import secrets
        hex_token = secrets.token_hex(32)
        assert is_high_entropy_hex(hex_token)

    def test_low_entropy_hex(self):
        assert not is_high_entropy_hex("0" * 32)
