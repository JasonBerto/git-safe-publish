# git-safe-publish

A CLI toolchain that analyzes git repositories, commit history, and staged content to detect and prevent the accidental publication of sensitive data. It acts as a safety layer between a developer's local work and any remote push.

## Features

- **Secret detection** — 30+ built-in patterns covering AWS, GCP, Azure, GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, database URLs, PEM private keys, JWTs, and more
- **High-entropy heuristics** — catches custom/unknown secrets via Shannon entropy analysis
- **Sensitive file detection** — flags `.env`, `*.pem`, `*.key`, `terraform.tfvars`, `*.tfstate`, `kubeconfig`, `credentials.json`, and 30+ other risky file types
- **Author identity validation** — confirms committer email/name matches expectations
- **Push safety** — guards against wrong remotes, force-pushing protected branches, insecure protocols
- **.gitignore auditing** — detects missing coverage for common sensitive patterns
- **Full history scan** — surfaces secrets buried in old commits
- **Custom patterns** — extend via `.git-safe-publish.yml`

## Installation

```bash
pip install git-safe-publish
```

Or install from source:

```bash
git clone https://github.com/your-org/git-safe-publish
cd git-safe-publish
pip install -e ".[dev]"
```

## Commands

| Command | Description |
|---|---|
| `git-safe-check` | Scan staged/tracked files. Exits 0 = clean, 1 = issues, 2 = error. |
| `git-safe-push` | Drop-in for `git push` — runs checks before pushing. |
| `git-safe-publish` | Interactive full check + confirm identity + push. |
| `git-safe-search` | Deep-scan entire commit history. |

## Usage

### Check before committing

```bash
# Scan staged changes and tracked files
git-safe-check

# Staged changes only (ideal as a pre-commit hook)
git-safe-check --staged

# JSON output (for CI pipelines)
git-safe-check --json
```

### Push safely

```bash
# Drop-in for git push
git-safe-push origin main

# Full interactive flow with confirmation
git-safe-publish --remote origin --branch main
```

### Scan history

```bash
# Scan all commits on all branches
git-safe-search

# Scan last 50 commits on current branch
git-safe-search --branch HEAD --limit 50

# Output as JSON
git-safe-search --json
```

## Configuration

Create `.git-safe-publish.yml` in your repo root:

```bash
git-safe-check --init-config
```

Key options:

```yaml
# Branches that block force-push
protected_branches: [main, master, production]

# Require committer email to match regex
required_email_pattern: ".*@yourcompany\\.com$"

# Require GPG/SSH commit signing
require_signed_commits: false

# Minimum severity to fail on: P0 | P1 | P2 | P3
severity_threshold: "P0"

# Paths/globs to skip
ignore_paths:
  - "tests/**"
  - "*.example"

# Custom secret patterns
custom_patterns:
  - name: my-internal-token
    regex: "MYCO-[A-Za-z0-9]{32}"
    severity: P0
    category: Internal
    description: "Acme Corp internal service token"
```

## Use as a git hook

```bash
# Install as a pre-push hook
echo '#!/bin/sh\ngit-safe-check --staged' > .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no issues at or above the configured severity threshold |
| `1` | Issues found |
| `2` | Tool error (not a git repo, git command failed, etc.) |

## Severity levels

| Level | Label | Examples |
|---|---|---|
| P0 | CRITICAL | AWS key, private key, Stripe live key |
| P1 | HIGH | OpenAI key, database URL with credentials, GitHub PAT |
| P2 | MEDIUM | Generic hardcoded password, JWT, internal IP |
| P3 | LOW | Commented-out credentials, TODO referencing secrets |
