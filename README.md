# git-safe-publish

![git-safe-publish logo](git-safe-publish-logo.png)

A CLI toolchain that analyzes git repositories, commit history, and staged content to detect and prevent the accidental publication of sensitive data. It acts as a safety layer between a developer's local work and any remote push.

## Features

- **Secret detection** — 35+ built-in patterns: AWS, GCP, Azure, GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, database URLs, PEM keys, JWTs, and more
- **High-entropy heuristics** — catches unknown/custom secrets via Shannon entropy analysis
- **Sensitive file detection** — flags `.env`, `*.pem`, `*.key`, `terraform.tfvars`, `*.tfstate`, `kubeconfig`, and 30+ other risky types
- **Metadata scanning** — checks branch names, tag annotations, git stash, submodule URLs, `.git/hooks` integrity, and GitHub Actions misconfigurations
- **Author identity validation** — confirms committer email/name matches expectations
- **Push safety** — guards against wrong remotes, force-pushing protected branches, insecure protocols
- **.gitignore auditing** — detects missing coverage for common sensitive patterns
- **Full history scan** — surfaces secrets buried in old commits with exposure window reporting
- **Guided remediation** — generates exact `git filter-repo` commands to remove secrets from history
- **SARIF / Markdown output** — integrate with GitHub Code Scanning or post findings as PR comments
- **Inline suppression** — suppress individual findings with `# gsp-ignore` comments
- **Allowlist** — persist false-positive suppressions in `.git-safe-allowlist.yml`
- **Custom patterns** — extend detection via `.git-safe-publish.yml`

## Installation

```bash
pip install git-safe-publish
```

Or install from source:

```bash
git clone https://github.com/your-org/git-safe-publish
cd git-safe-publish
pip install -e .
```

## Commands

| Command | Description |
|---|---|
| `git-safe-check` | Scan staged/tracked content. Exits 0 = clean, 1 = issues, 2 = error. |
| `git-safe-commit` | Drop-in for `git commit` — scans staged changes and commit message. |
| `git-safe-push` | Drop-in for `git push` — runs checks before pushing. |
| `git-safe-publish` | Interactive full check + identity confirm + push. |
| `git-safe-search` | Deep-scan entire commit history. |
| `git-safe-hooks` | Install, remove, and manage git hooks. |
| `git-safe-fix` | Generate guided `git filter-repo` remediation commands. |
| `git-safe-scan` | Scan arbitrary files or directories — no git repo required. |

## Usage

### Commit safely

```bash
# Drop-in for git commit — scans staged changes and commit message
git-safe-commit -m "feat: add login page"

# Skip checks (e.g. amending with --no-edit)
git-safe-commit --amend --no-edit --skip-checks
```

### Check staged content

```bash
# Scan staged changes and all tracked files
git-safe-check

# Staged changes only
git-safe-check --staged

# PR/CI mode — scan only lines changed vs. a base branch
git-safe-check --base main

# Re-run every 3 seconds (Ctrl+C to stop)
git-safe-check --watch

# Show all 35+ built-in patterns
git-safe-check --list-patterns

# Test a custom regex against a sample value
git-safe-check --test-pattern "MYCO-[A-Z0-9]{20}" --against "MYCO-ABC123DEF456GHI789JK"

# Also scan branch names, tags, submodules, hooks, and GitHub Actions
git-safe-check --metadata
```

### Push safely

```bash
# Drop-in for git push
git-safe-push origin main

# Full interactive flow with identity confirmation
git-safe-publish --remote origin --branch main
```

### Scan history

```bash
# Scan all commits on all branches
git-safe-search

# Filter by date or author
git-safe-search --since 2024-01-01 --author "@yourcompany.com"

# Show exposure windows (first / last seen per finding)
git-safe-search --exposure

# Scan only last 50 commits on current branch
git-safe-search --branch HEAD --limit 50

# Include branch names, tags, stash, and metadata
git-safe-search --metadata
```

### Output formats

All commands support `--format` and `--output`:

```bash
# Write SARIF for GitHub Code Scanning
git-safe-search --format sarif --output results.sarif

# Write a Markdown report (e.g. for a PR comment)
git-safe-check --format markdown --output report.md

# JSON for custom tooling
git-safe-search --format json --output findings.json
```

### Guided remediation

```bash
# Scan history and generate a git filter-repo remediation script
git-safe-fix --history --output fix.sh
cat fix.sh   # review before running!
```

### Scan arbitrary files

```bash
# Scan a directory with no git repo needed
git-safe-scan ./config-backup/
git-safe-scan /tmp/archive/ --severity P1 --format sarif --output scan.sarif

# Scan specific files
git-safe-scan settings.py .env
```

### Manage git hooks

```bash
# Install all three hooks (pre-commit, commit-msg, pre-push)
git-safe-hooks install

# Install a specific hook
git-safe-hooks install --hook pre-commit

# Show hook status
git-safe-hooks status

# Remove all managed hooks
git-safe-hooks uninstall
```

### Generate CI integration

```bash
# Print a ready-to-use GitHub Actions workflow with SARIF upload
git-safe-hooks ci github

# Write it directly to .github/workflows/
git-safe-hooks ci github --output .github/workflows/git-safe-publish.yml

# GitLab CI snippet
git-safe-hooks ci gitlab

# pre-commit framework config
git-safe-hooks ci pre-commit
```

## Inline suppression

Add `# gsp-ignore` to a line to suppress all findings on it. Specify a check name to be more precise:

```python
# Suppress everything on this line
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"  # gsp-ignore

# Suppress a specific check only
STRIPE_WEBHOOK = os.getenv("STRIPE_WEBHOOK")  # gsp-ignore: stripe-secret-key

# Suppress multiple checks
DB_URL = "postgres://..."  # gsp-ignore: postgres-url, basic-auth-in-url
```

## Allowlist

For persistent false-positive suppression, create `.git-safe-allowlist.yml` in your repo:

```yaml
# .git-safe-allowlist.yml
- check_name: aws-access-key-id
  filename: tests/fixtures/config.py
  line_hash: <sha256-of-line-content>
  reason: "Test fixture — not a real key"

- check_name: generic-password-assignment
  filename: ""    # matches any file
  reason: "Default config example values"
```

## Configuration

Generate a starter config:

```bash
git-safe-check --init-config
```

Key options in `.git-safe-publish.yml`:

```yaml
# Minimum severity to fail: P0 | P1 | P2 | P3
severity_threshold: "P0"

# Block commit/push when blockers found
block_on_secrets: true

# Branches that block force-push
protected_branches: [main, master, production]

# Require committer email to match a regex
required_email_pattern: ".*@yourcompany\\.com$"

# Require GPG/SSH commit signing
require_signed_commits: false

# Paths/globs to skip
ignore_paths:
  - "tests/**"
  - "*.example"

# Custom patterns
custom_patterns:
  - name: my-internal-token
    regex: "MYCO-[A-Za-z0-9]{32}"
    severity: P0
    category: Internal
    description: "Acme Corp internal service token"
```

A global config at `~/.git-safe-publish.yml` applies to all repositories.

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
| P1 | HIGH | OpenAI key, database URL with credentials, GitHub PAT, pull_request_target misconfiguration |
| P2 | MEDIUM | Generic hardcoded password, JWT, absolute path disclosure, unpinned GitHub Action |
| P3 | LOW | Commented-out credentials, TODO referencing secrets, unmanaged hook |
