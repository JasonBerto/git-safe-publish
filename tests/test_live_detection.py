"""Live detection demo test.

Creates real temporary files containing common security risks and runs the
scanner against them, printing a full findings report. This test is intended
to show exactly how git-safe-publish catches secrets in practice.

Run it directly:
    pytest tests/test_live_detection.py -v -s

Or via any git-safe-* command:
    git-safe-check --test

NOTE: Secret literals are assembled at runtime from parts so that GitHub push
protection does not block this repository. The assembled values are only ever
written to pytest tmp_path directories and never committed to git history.
"""

import textwrap
from pathlib import Path

import pytest
from rich.console import Console
from rich.rule import Rule

from git_safe_publish.config import Config, DEFAULTS
from git_safe_publish.models import Severity
from git_safe_publish.scanner.secrets import scan_file_content

console = Console()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _config(threshold: str = "P2") -> Config:
    return Config({**DEFAULTS, "severity_threshold": threshold})


def _s(*parts: str) -> str:
    """Join parts at runtime — prevents static secret literals in source text."""
    return "".join(parts)


def _print_demo_header(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))


def _print_findings_report(result, filepath: Path) -> None:
    """Print a human-readable findings report for the demo."""
    from git_safe_publish.report import print_findings, print_summary
    console.print(f"\n[dim]File scanned:[/dim] [bold]{filepath.name}[/bold]")
    print_findings(result, show_remediation=True)
    print_summary(result, scope=filepath.name)


# ---------------------------------------------------------------------------
# Runtime-assembled secret values (split so GitHub push protection won't flag)
# ---------------------------------------------------------------------------

_AWS_KEY_ID      = _s("AKIA", "IOSFODNN7EXAMPLE")
_AWS_SECRET      = _s("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")
_STRIPE_KEY      = _s("sk_live_", "abcdefghijklmnopqrstuvwx")
_SENDGRID_KEY    = _s("SG.", "abcdefghijklmnopqrstuv", ".", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
_SLACK_TOKEN     = _s("xoxb-", "123456789012-123456789012-", "abcdefghijklmnopqrstuvwx")
_GITHUB_PAT      = _s("ghp_", "B" * 36)
_OPENAI_KEY      = _s("sk-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst")
_DB_URL_CREDS    = _s("postgresql://admin:hunter2@db.prod.internal/myapp")


# ---------------------------------------------------------------------------
# Demo file templates (built at import time from assembled values)
# ---------------------------------------------------------------------------

DEMO_CONFIG_PY = f"""\
# config.py  ← example app configuration with accidental secrets
import os

# Cloud credentials — should come from environment variables
AWS_ACCESS_KEY_ID     = "{_AWS_KEY_ID}"
AWS_SECRET_ACCESS_KEY = "{_AWS_SECRET}"

# Database — connection string with embedded password
DATABASE_URL = "{_DB_URL_CREDS}"

# Third-party API keys
STRIPE_SECRET_KEY = "{_STRIPE_KEY}"
OPENAI_API_KEY    = "{_OPENAI_KEY}"
GITHUB_TOKEN      = "{_GITHUB_PAT}"

# Private key (loaded inline for "convenience")
PRIVATE_KEY = \"\"\"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7bQM
-----END RSA PRIVATE KEY-----
\"\"\"

# JWT used as a static token (never do this)
SESSION_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Internal infrastructure URL
INTERNAL_API = "http://10.0.1.42/api/v2"

# Generic hardcoded password
DB_PASSWORD = "Sup3rS3cr3tP@ssw0rd!"
"""

DEMO_DOTENV = f"""\
# .env  ← should NEVER be committed — add to .gitignore
AWS_ACCESS_KEY_ID={_AWS_KEY_ID}
AWS_SECRET_ACCESS_KEY={_AWS_SECRET}
STRIPE_SECRET_KEY={_STRIPE_KEY}
DATABASE_URL=postgresql://root:password123@localhost/production
SENDGRID_API_KEY={_SENDGRID_KEY}
SLACK_BOT_TOKEN={_SLACK_TOKEN}
"""

DEMO_DOCKERFILE = f"""\
# Dockerfile  ← secrets baked into image layers
FROM python:3.11-slim

# BAD: secret in ARG/ENV — visible in docker history
ARG  STRIPE_KEY={_STRIPE_KEY}
ENV  AWS_ACCESS_KEY_ID={_AWS_KEY_ID}

# BAD: secret in RUN — baked into intermediate layer
RUN curl https://api.service.io/setup \\
    -H "Authorization: Bearer {_GITHUB_PAT}"

COPY . /app
"""


# ---------------------------------------------------------------------------
# Demo tests
# ---------------------------------------------------------------------------

class TestLiveDetection:
    """
    Each test writes a realistic file to a temporary directory, runs the
    scanner, prints the report, and asserts the expected findings are caught.
    """

    def test_config_py_with_secrets(self, tmp_path: Path) -> None:
        """Realistic Python config file with multiple hardcoded credentials."""
        _print_demo_header("DEMO 1 — Python config file with hardcoded secrets")

        target = tmp_path / "test_file_config.py"
        target.write_text(textwrap.dedent(DEMO_CONFIG_PY), encoding="utf-8")

        console.print(f"\n[dim]Contents of[/dim] {target.name}:\n")
        for i, line in enumerate(target.read_text().splitlines(), 1):
            console.print(f"  [dim]{i:>3}[/dim]  {line}")

        result = scan_file_content(target.read_text(), target.name, _config(threshold="P2"))
        _print_findings_report(result, target)

        assert not result.is_clean, "Expected secrets to be detected in config.py"

        check_names = {f.check_name for f in result.findings}
        assert "aws-access-key-id"       in check_names, "Should detect AWS Access Key ID"
        assert "private-key-pem"         in check_names, "Should detect RSA private key"
        assert "database-url-with-creds" in check_names, "Should detect database URL"
        assert "stripe-secret-key"       in check_names, "Should detect Stripe live secret key"
        assert "github-token-classic"    in check_names, "Should detect GitHub PAT"

        console.print(
            f"\n  [green]✔[/green] Caught [bold]{len(result.findings)}[/bold] issue(s) "
            f"across [bold]{len(check_names)}[/bold] distinct check(s)."
        )

    def test_dotenv_with_secrets(self, tmp_path: Path) -> None:
        """.env file that was accidentally staged."""
        _print_demo_header("DEMO 2 — .env file with multiple service credentials")

        target = tmp_path / "test_file_.env"
        target.write_text(textwrap.dedent(DEMO_DOTENV), encoding="utf-8")

        console.print(f"\n[dim]Contents of[/dim] {target.name}:\n")
        for i, line in enumerate(target.read_text().splitlines(), 1):
            console.print(f"  [dim]{i:>3}[/dim]  {line}")

        result = scan_file_content(target.read_text(), target.name, _config(threshold="P1"))
        _print_findings_report(result, target)

        assert not result.is_clean, "Expected secrets in .env to be detected"

        check_names = {f.check_name for f in result.findings}
        assert "aws-access-key-id" in check_names, "Should detect AWS key"
        assert "stripe-secret-key" in check_names, "Should detect Stripe key"
        assert "sendgrid-api-key"  in check_names, "Should detect SendGrid key"
        assert "slack-bot-token"   in check_names, "Should detect Slack token"

        console.print(
            f"\n  [green]✔[/green] Caught [bold]{len(result.findings)}[/bold] issue(s) "
            f"in {target.name}."
        )

    def test_dockerfile_with_secrets(self, tmp_path: Path) -> None:
        """Dockerfile baking secrets into image layers."""
        _print_demo_header("DEMO 3 — Dockerfile with secrets baked into image layers")

        target = tmp_path / "test_file_Dockerfile"
        target.write_text(textwrap.dedent(DEMO_DOCKERFILE), encoding="utf-8")

        console.print(f"\n[dim]Contents of[/dim] {target.name}:\n")
        for i, line in enumerate(target.read_text().splitlines(), 1):
            console.print(f"  [dim]{i:>3}[/dim]  {line}")

        result = scan_file_content(target.read_text(), target.name, _config(threshold="P1"))
        _print_findings_report(result, target)

        assert not result.is_clean, "Expected secrets in Dockerfile to be detected"

        check_names = {f.check_name for f in result.findings}
        assert "aws-access-key-id"    in check_names, "Should detect AWS key in ENV"
        assert "stripe-secret-key"    in check_names, "Should detect Stripe key in ARG"
        assert "github-token-classic" in check_names, "Should detect GitHub token in RUN"

        console.print(
            f"\n  [green]✔[/green] Caught [bold]{len(result.findings)}[/bold] issue(s) "
            f"in {target.name}."
        )

    def test_clean_file_produces_no_findings(self, tmp_path: Path) -> None:
        """A properly written config file using environment variables only."""
        _print_demo_header("DEMO 4 — Clean config using environment variables (no findings expected)")

        clean_content = """\
# config.py  ← safe: all secrets come from environment variables
import os

AWS_ACCESS_KEY_ID     = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DATABASE_URL          = os.environ["DATABASE_URL"]
STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
GITHUB_TOKEN          = os.environ.get("GITHUB_TOKEN", "")
"""
        target = tmp_path / "test_file_clean_config.py"
        target.write_text(clean_content, encoding="utf-8")

        console.print(f"\n[dim]Contents of[/dim] {target.name}:\n")
        for line in clean_content.splitlines():
            console.print(f"         {line}")

        result = scan_file_content(target.read_text(), target.name, _config(threshold="P2"))
        _print_findings_report(result, target)

        assert result.is_clean, (
            f"Expected no findings in clean config, but got: "
            f"{[f.check_name for f in result.findings]}"
        )
        console.print("\n  [green]✔[/green] No secrets found — this is how your config should look.")
