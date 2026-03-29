"""Secret detection patterns for git-safe-publish.

Each Pattern has a name, regex, severity, category, and description.
Patterns are applied to added lines in diffs and raw file content.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Pattern dataclass
# ---------------------------------------------------------------------------

@dataclass
class Pattern:
    name: str
    regex: str
    severity: str        # "P0" | "P1" | "P2" | "P3"
    category: str
    description: str
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    @property
    def compiled(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.regex, re.IGNORECASE)
        return self._compiled

    def findall(self, text: str) -> list[re.Match]:
        return list(self.compiled.finditer(text))


# ---------------------------------------------------------------------------
# False-positive skip list — values that look like secrets but aren't
# ---------------------------------------------------------------------------

PLACEHOLDER_VALUES = re.compile(
    r"^(your[_\-]?|my[_\-]?|example[_\-]?|test[_\-]?|fake[_\-]?|dummy[_\-]?|"
    r"placeholder|todo|fixme|change[_\-]?me|replace[_\-]?me|"
    r"x{3,}|0{8,}|1{8,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|"
    r"none|null|undefined|true|false|password|secret|token|key)",
    re.IGNORECASE,
)

SKIP_EXTENSIONS = {
    ".test", ".spec", ".mock", ".fixture", ".snap",
    ".min.js", ".min.css",
}


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_VALUES.match(value.strip()))


# ---------------------------------------------------------------------------
# Shannon entropy helpers (high-entropy string heuristic)
# ---------------------------------------------------------------------------

_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def is_high_entropy_b64(s: str, min_len: int = 20, threshold: float = 4.5) -> bool:
    return (
        len(s) >= min_len
        and set(s).issubset(_B64_CHARS)
        and _entropy(s) > threshold
    )


def is_high_entropy_hex(s: str, min_len: int = 32, threshold: float = 3.5) -> bool:
    return (
        len(s) >= min_len
        and set(s.lower()).issubset(set("0123456789abcdef"))
        and _entropy(s) > threshold
    )


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

PATTERNS: List[Pattern] = [

    # ------------------------------------------------------------------ P0 --

    Pattern(
        name="aws-access-key-id",
        regex=r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        severity="P0",
        category="Cloud — AWS",
        description="AWS Access Key ID",
    ),
    Pattern(
        name="aws-secret-access-key",
        regex=r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity="P0",
        category="Cloud — AWS",
        description="AWS Secret Access Key",
    ),
    Pattern(
        name="github-token-classic",
        regex=r"ghp_[A-Za-z0-9]{36}",
        severity="P0",
        category="VCS — GitHub",
        description="GitHub Personal Access Token (classic)",
    ),
    Pattern(
        name="github-token-fine-grained",
        regex=r"github_pat_[A-Za-z0-9_]{82}",
        severity="P0",
        category="VCS — GitHub",
        description="GitHub Fine-Grained Personal Access Token",
    ),
    Pattern(
        name="github-oauth-token",
        regex=r"gho_[A-Za-z0-9]{36}",
        severity="P0",
        category="VCS — GitHub",
        description="GitHub OAuth Access Token",
    ),
    Pattern(
        name="github-app-token",
        regex=r"(ghs|ghu)_[A-Za-z0-9]{36}",
        severity="P0",
        category="VCS — GitHub",
        description="GitHub App / User-to-Server Token",
    ),
    Pattern(
        name="gitlab-pat",
        regex=r"glpat-[A-Za-z0-9\-_]{20}",
        severity="P0",
        category="VCS — GitLab",
        description="GitLab Personal Access Token",
    ),
    Pattern(
        name="private-key-pem",
        regex=r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        severity="P0",
        category="Cryptography",
        description="PEM-encoded private key block",
    ),
    Pattern(
        name="stripe-secret-key",
        regex=r"sk_live_[A-Za-z0-9]{24,}",
        severity="P0",
        category="Payment — Stripe",
        description="Stripe live secret key",
    ),
    Pattern(
        name="stripe-restricted-key",
        regex=r"rk_live_[A-Za-z0-9]{24,}",
        severity="P0",
        category="Payment — Stripe",
        description="Stripe live restricted key",
    ),
    Pattern(
        name="gcp-service-account",
        regex=r'"type"\s*:\s*"service_account"',
        severity="P0",
        category="Cloud — GCP",
        description="GCP service account JSON credential",
    ),
    Pattern(
        name="azure-storage-connection",
        regex=r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}",
        severity="P0",
        category="Cloud — Azure",
        description="Azure Storage connection string with AccountKey",
    ),
    Pattern(
        name="azure-sas-token",
        regex=r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=&[a-z0-9&=%]+sig=[A-Za-z0-9%+/=]{40,}",
        severity="P0",
        category="Cloud — Azure",
        description="Azure SAS token",
    ),

    # ------------------------------------------------------------------ P1 --

    Pattern(
        name="openai-api-key",
        regex=r"sk-[A-Za-z0-9]{48}",
        severity="P1",
        category="AI Services",
        description="OpenAI API key",
    ),
    Pattern(
        name="openai-project-key",
        regex=r"sk-proj-[A-Za-z0-9_\-]{40,}",
        severity="P1",
        category="AI Services",
        description="OpenAI project API key",
    ),
    Pattern(
        name="anthropic-api-key",
        regex=r"sk-ant-api\d{2}-[A-Za-z0-9\-_]{93}",
        severity="P1",
        category="AI Services",
        description="Anthropic API key",
    ),
    Pattern(
        name="slack-bot-token",
        regex=r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        severity="P1",
        category="Messaging — Slack",
        description="Slack Bot/App/User/Webhook token",
    ),
    Pattern(
        name="slack-webhook",
        regex=r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        severity="P1",
        category="Messaging — Slack",
        description="Slack incoming webhook URL",
    ),
    Pattern(
        name="sendgrid-api-key",
        regex=r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        severity="P1",
        category="Email — SendGrid",
        description="SendGrid API key",
    ),
    Pattern(
        name="twilio-auth-token",
        regex=r"SK[0-9a-fA-F]{32}",
        severity="P1",
        category="Messaging — Twilio",
        description="Twilio Auth Token / SID",
    ),
    Pattern(
        name="database-url-with-creds",
        regex=r"(?i)(postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:@\s]+:[^@\s]+@[^\s\"']+",
        severity="P1",
        category="Database",
        description="Database URL containing credentials",
    ),
    Pattern(
        name="mailgun-api-key",
        regex=r"key-[0-9a-zA-Z]{32}",
        severity="P1",
        category="Email — Mailgun",
        description="Mailgun API key",
    ),
    Pattern(
        name="npm-access-token",
        regex=r"npm_[A-Za-z0-9]{36}",
        severity="P1",
        category="Package Registry",
        description="npm access token",
    ),
    Pattern(
        name="pypi-token",
        regex=r"pypi-[A-Za-z0-9\-_]{40,}",
        severity="P1",
        category="Package Registry",
        description="PyPI upload token",
    ),
    Pattern(
        name="digitalocean-token",
        regex=r"dop_v1_[a-f0-9]{64}",
        severity="P1",
        category="Cloud — DigitalOcean",
        description="DigitalOcean personal access token",
    ),
    Pattern(
        name="stripe-publishable-key",
        regex=r"pk_live_[A-Za-z0-9]{24,}",
        severity="P1",
        category="Payment — Stripe",
        description="Stripe live publishable key",
    ),
    Pattern(
        name="heroku-api-key",
        regex=r"(?i)heroku[_\-\s]?api[_\-\s]?key\s*[=:]\s*['\"]?([0-9a-fA-F\-]{36})['\"]?",
        severity="P1",
        category="Cloud — Heroku",
        description="Heroku API key",
    ),
    Pattern(
        name="ssh-password-in-url",
        regex=r"ssh://[^:@\s]+:[^@\s]+@",
        severity="P1",
        category="Cryptography",
        description="SSH URL with embedded password",
    ),

    # ------------------------------------------------------------------ P2 --

    Pattern(
        name="generic-api-key-assignment",
        regex=r"(?i)\bapi[_\-]?key\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        severity="P2",
        category="Generic",
        description="Generic api_key assignment",
    ),
    Pattern(
        name="generic-secret-assignment",
        regex=r"(?i)\bsecret[_\-]?(key|token|value)?\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        severity="P2",
        category="Generic",
        description="Generic secret assignment",
    ),
    Pattern(
        name="generic-token-assignment",
        regex=r"(?i)\b(access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        severity="P2",
        category="Generic",
        description="Generic token assignment",
    ),
    Pattern(
        name="generic-password-assignment",
        regex=r"(?i)\bpassword\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
        severity="P2",
        category="Generic",
        description="Hardcoded password assignment",
    ),
    Pattern(
        name="private-key-passphrase",
        regex=r"(?i)\bpassphrase\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
        severity="P2",
        category="Cryptography",
        description="Hardcoded key passphrase",
    ),
    Pattern(
        name="internal-ip-address",
        regex=r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)",
        severity="P2",
        category="Infrastructure",
        description="Private / internal IP address",
    ),
    Pattern(
        name="jwt-token",
        regex=r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        severity="P2",
        category="Auth",
        description="JSON Web Token (JWT)",
    ),
    Pattern(
        name="basic-auth-in-url",
        regex=r"https?://[^:@/\s]+:[^@/\s]+@",
        severity="P2",
        category="Generic",
        description="HTTP URL with embedded credentials",
    ),
    Pattern(
        name="google-oauth-client-secret",
        regex=r"(?i)client[_\-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{24,})['\"]?",
        severity="P2",
        category="Cloud — GCP",
        description="OAuth client secret",
    ),
    Pattern(
        name="firebase-config",
        regex=r'"apiKey"\s*:\s*"AIza[A-Za-z0-9\-_]{35}"',
        severity="P2",
        category="Cloud — GCP",
        description="Firebase / Google API key",
    ),

    # ------------------------------------------------------------------ P3 --

    Pattern(
        name="todo-credentials",
        regex=r"(?i)#\s*(todo|fixme|hack|xxx)\s*:?\s*(password|credential|secret|token|api.?key)",
        severity="P3",
        category="Code Quality",
        description="TODO/FIXME comment referencing credentials",
    ),
    Pattern(
        name="commented-out-credentials",
        regex=r"(?i)#\s*(password|api[_\-]?key|secret|token)\s*[=:]\s*\S+",
        severity="P3",
        category="Code Quality",
        description="Commented-out credential",
    ),
]


# ---------------------------------------------------------------------------
# Quick lookup by name
# ---------------------------------------------------------------------------

PATTERN_MAP: dict[str, Pattern] = {p.name: p for p in PATTERNS}
