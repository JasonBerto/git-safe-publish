"""Sensitive file type detection scanner.

Checks whether any staged or tracked files match patterns known to contain
credentials, private keys, database dumps, or other sensitive content.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from git_safe_publish.models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Sensitive file pattern registry
# ---------------------------------------------------------------------------

@dataclass
class SensitiveFilePattern:
    glob: str
    severity: Severity
    category: str
    description: str
    remediation: str


SENSITIVE_FILE_PATTERNS: List[SensitiveFilePattern] = [
    # Environment / secrets files
    SensitiveFilePattern(".env",               Severity.P0, "Secrets File", ".env file (may contain all application secrets)", "Add .env to .gitignore. Use .env.example with placeholder values instead."),
    SensitiveFilePattern(".env.*",             Severity.P0, "Secrets File", ".env variant file", "Add .env.* to .gitignore. Never commit real environment files."),
    SensitiveFilePattern("*.env",              Severity.P0, "Secrets File", ".env file", "Add *.env to .gitignore."),

    # Private keys & certificates
    SensitiveFilePattern("*.pem",              Severity.P0, "Cryptography", "PEM-encoded certificate or private key", "Never commit private keys. Add *.pem to .gitignore. Regenerate if exposed."),
    SensitiveFilePattern("*.key",              Severity.P0, "Cryptography", "Private key file", "Add *.key to .gitignore. Use a secrets manager for key storage."),
    SensitiveFilePattern("*.p12",              Severity.P0, "Cryptography", "PKCS#12 certificate/key bundle", "Add *.p12 to .gitignore."),
    SensitiveFilePattern("*.pfx",              Severity.P0, "Cryptography", "PKCS#12 certificate/key bundle", "Add *.pfx to .gitignore."),
    SensitiveFilePattern("id_rsa",             Severity.P0, "Cryptography", "SSH RSA private key", "This is your SSH private key! Add id_rsa to .gitignore immediately."),
    SensitiveFilePattern("id_ed25519",         Severity.P0, "Cryptography", "SSH Ed25519 private key", "Add id_ed25519 to .gitignore immediately."),
    SensitiveFilePattern("id_ecdsa",           Severity.P0, "Cryptography", "SSH ECDSA private key", "Add id_ecdsa to .gitignore immediately."),
    SensitiveFilePattern("*.ppk",              Severity.P0, "Cryptography", "PuTTY private key file", "Add *.ppk to .gitignore."),
    SensitiveFilePattern("*.jks",              Severity.P1, "Cryptography", "Java KeyStore file", "Add *.jks to .gitignore."),
    SensitiveFilePattern("*.keystore",         Severity.P1, "Cryptography", "Java KeyStore file", "Add *.keystore to .gitignore."),

    # Cloud credentials
    SensitiveFilePattern("credentials.json",   Severity.P0, "Cloud — GCP", "GCP / Firebase service account credentials", "Add credentials.json to .gitignore. Use GOOGLE_APPLICATION_CREDENTIALS env var."),
    SensitiveFilePattern("service-account.json", Severity.P0, "Cloud — GCP", "GCP service account JSON", "Add service-account.json to .gitignore."),
    SensitiveFilePattern("*service_account*.json", Severity.P0, "Cloud — GCP", "GCP service account JSON", "Add to .gitignore. Use workload identity or env vars."),
    SensitiveFilePattern(".aws/credentials",   Severity.P0, "Cloud — AWS", "AWS credentials file", "Add .aws/credentials to .gitignore. Use IAM roles or aws-vault."),
    SensitiveFilePattern("aws-credentials*",   Severity.P0, "Cloud — AWS", "AWS credentials file", "Use IAM roles instead of static credentials."),

    # Infrastructure secrets
    SensitiveFilePattern("terraform.tfvars",   Severity.P0, "Infrastructure", "Terraform variables (may contain secrets)", "Use terraform.tfvars.example for templates. Add terraform.tfvars to .gitignore."),
    SensitiveFilePattern("*.tfvars",           Severity.P0, "Infrastructure", "Terraform variables file", "Add *.tfvars to .gitignore or use -var-file with a CI-managed file."),
    SensitiveFilePattern("*.tfstate",          Severity.P0, "Infrastructure", "Terraform state file (contains resource secrets)", "Store state in a remote backend (S3, Terraform Cloud). Add *.tfstate to .gitignore."),
    SensitiveFilePattern("*.tfstate.backup",   Severity.P0, "Infrastructure", "Terraform state backup", "Add *.tfstate.backup to .gitignore."),
    SensitiveFilePattern("kubeconfig",         Severity.P0, "Infrastructure", "Kubernetes cluster config with credentials", "Add kubeconfig to .gitignore. Use KUBECONFIG env var."),
    SensitiveFilePattern("*.kubeconfig",       Severity.P0, "Infrastructure", "Kubernetes config file", "Add *.kubeconfig to .gitignore."),

    # Application secrets
    SensitiveFilePattern("config/master.key",  Severity.P0, "Rails", "Rails master key", "Add config/master.key to .gitignore (Rails does this by default)."),
    SensitiveFilePattern("config/secrets.yml", Severity.P1, "Rails", "Rails secrets file", "Use encrypted credentials (rails credentials:edit) instead."),
    SensitiveFilePattern("config/database.yml", Severity.P1, "App Config", "Database configuration (may contain credentials)", "Use environment variable interpolation. Add to .gitignore if it contains real values."),
    SensitiveFilePattern("wp-config.php",      Severity.P1, "WordPress", "WordPress config with DB credentials", "Add wp-config.php to .gitignore. Use environment variables."),
    SensitiveFilePattern("settings_local.py",  Severity.P1, "Django", "Django local settings (may contain secrets)", "Add settings_local.py to .gitignore."),
    SensitiveFilePattern("local_settings.py",  Severity.P1, "Django", "Django local settings", "Add local_settings.py to .gitignore."),

    # Data / database dumps
    SensitiveFilePattern("*.sql",              Severity.P1, "Data", "SQL dump (may contain PII or credentials)", "Never commit database dumps. Use a secure transfer method."),
    SensitiveFilePattern("*.dump",             Severity.P1, "Data", "Database dump file", "Add *.dump to .gitignore."),
    SensitiveFilePattern("*.bak",              Severity.P1, "Data", "Backup file", "Add *.bak to .gitignore."),

    # Secrets manager exports
    SensitiveFilePattern("vault-token*",       Severity.P0, "Secrets Manager", "HashiCorp Vault token", "Never commit Vault tokens."),
    SensitiveFilePattern(".vault-token",       Severity.P0, "Secrets Manager", "HashiCorp Vault token file", "Add .vault-token to .gitignore."),
    SensitiveFilePattern("*.asc",              Severity.P1, "Cryptography", "ASCII-armored PGP/GPG key", "Add *.asc to .gitignore unless it is a PUBLIC key."),

    # Docker / CI secrets
    SensitiveFilePattern(".npmrc",             Severity.P1, "Package Registry", ".npmrc (may contain auth tokens)", "Add .npmrc to .gitignore. Use npm login or NPM_TOKEN env var in CI."),
    SensitiveFilePattern(".pypirc",            Severity.P1, "Package Registry", ".pypirc (may contain PyPI credentials)", "Add .pypirc to .gitignore. Use TWINE_PASSWORD env var."),
    SensitiveFilePattern(".netrc",             Severity.P1, "Auth", ".netrc (contains username/password pairs)", "Add .netrc to .gitignore."),
    SensitiveFilePattern("docker-compose.override.yml", Severity.P1, "Docker", "Docker Compose override (may inject secrets)", "Add docker-compose.override.yml to .gitignore."),

    # History / log files
    SensitiveFilePattern("*.log",              Severity.P2, "Logs", "Log file (may contain tokens, PII, stack traces)", "Add *.log to .gitignore."),
    SensitiveFilePattern("npm-debug.log*",     Severity.P2, "Logs", "npm debug log", "Add npm-debug.log* to .gitignore."),
]

# Build a quick-lookup dict by glob
_PATTERN_MAP: Dict[str, SensitiveFilePattern] = {p.glob: p for p in SENSITIVE_FILE_PATTERNS}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _matches_any(filename: str, patterns: List[SensitiveFilePattern]) -> Optional[SensitiveFilePattern]:
    """Return the first matching SensitiveFilePattern, or None."""
    basename = filename.split("/")[-1]
    for pat in patterns:
        if fnmatch.fnmatch(basename, pat.glob) or fnmatch.fnmatch(filename, pat.glob):
            return pat
    return None


def scan_staged_files(
    staged_files: List[Tuple[str, str]],  # [(status, filename), ...]
    config,
) -> ScanResult:
    """Detect staged files that match sensitive file patterns."""
    result = ScanResult()
    for status, filename in staged_files:
        if status == "D":
            continue  # deleted file — no longer a risk
        if config.is_path_ignored(filename):
            continue
        match = _matches_any(filename, SENSITIVE_FILE_PATTERNS)
        if match:
            result.add(Finding(
                severity=match.severity,
                category=match.category,
                check_name="sensitive-file-staged",
                description=f"Sensitive file staged for commit: {match.description}",
                filename=filename,
                remediation=match.remediation,
            ))
    return result


def scan_tracked_files(tracked_files: List[str], config) -> ScanResult:
    """Detect already-tracked files that match sensitive file patterns."""
    result = ScanResult()
    for filename in tracked_files:
        if config.is_path_ignored(filename):
            continue
        match = _matches_any(filename, SENSITIVE_FILE_PATTERNS)
        if match:
            result.add(Finding(
                severity=match.severity,
                category=match.category,
                check_name="sensitive-file-tracked",
                description=f"Sensitive file is tracked by git: {match.description}",
                filename=filename,
                remediation=f"{match.remediation}\n  To stop tracking: git rm --cached {filename}",
            ))
    return result
