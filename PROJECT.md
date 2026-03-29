# git-safe-publish — Product Spec

## Overview

`git-safe-publish` is a CLI toolchain that analyzes git repositories, commit history, and staged content to detect and prevent the accidental publication of sensitive data. It acts as a safety layer between a developer's local work and any remote push, scanning for secrets, validating identity, and enforcing configurable publish policies.

Reference `SECURITY_RISKS.md` for the full threat model this tool addresses.

---

## Goals

1. **Prevent secrets from leaving the developer's machine** — catch API keys, credentials, private keys, and high-entropy strings before they reach any remote.
2. **Surface secrets already in history** — scan full commit history so developers know what has already been exposed and needs remediation.
3. **Validate author identity** — confirm the committer email/name matches expectations before pushing, preventing PII leaks and identity confusion.
4. **Protect remote targets** — guard against pushing to the wrong remote, wrong branch, or making a private repo public.
5. **Be composable** — work standalone or as a pre-push git hook, CI step, or GitHub Action.
6. **Zero false-negative tolerance for P0 risks** — prefer flagging false positives over missing a real secret.

---

## Features

### Secrets Detection
- Scan staged files, working tree, latest commit, or full history for secret patterns
- Built-in pattern library covering: AWS, GCP, Azure, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, OpenAI, Anthropic, database URLs, PEM blocks, and more
- High-entropy string detection (base64, hex) for unknown/custom secrets
- Detect secrets in commit messages, branch names, and tag annotations
- Flag sensitive file types: `.env`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, `credentials.json`, `terraform.tfvars`, `*.tfstate`, `kubeconfig`, `*.sql`/`*.dump`
- Check CI/CD config files (`.github/workflows/`, `.gitlab-ci.yml`, `Dockerfile`) for hardcoded secrets

### Identity Validation
- Confirm `user.email` and `user.name` match configured expectations for the repo
- Warn when using a global git identity that differs from the expected project identity
- Optionally require GPG/SSH commit signing

### Push Safety
- Validate target remote URL before pushing (warn on unexpected/public remotes)
- Prevent force push to protected branches (`main`, `master`, configurable)
- Warn when pushing directly to `main`/`master` without a PR
- Detect if a repository's visibility is public when a private push is expected

### `.gitignore` Auditing
- Detect common sensitive file patterns not covered by `.gitignore`
- Warn when a file is already tracked that should be ignored
- Suggest `.gitignore` additions

### History Scanning
- Full repository history scan for any of the above issues
- Output a report of all affected commits, files, and line numbers
- Estimate exposure window (first commit date → last commit date of affected content)

---

## Commands

### Implemented (v0.2.0)

| Command | Description |
|---|---|
| `git-safe-check` | Scan staged/tracked files. Exits 0 = clean, 1 = issues, 2 = error. |
| `git-safe-commit` | Drop-in for `git commit` — scans staged changes and commit message before committing. |
| `git-safe-push` | Drop-in for `git push` — runs pre-push safety checks. |
| `git-safe-publish` | Interactive full check + confirm identity + push. |
| `git-safe-search` | Deep-scan entire commit history. |

### Planned

| Command | Description | Priority |
|---|---|---|
| `git-safe-hooks` | Install / uninstall / status git hooks (pre-commit, commit-msg, pre-push). Single command onboarding. | P0 |
| `git-safe-fix` | Guided remediation — generate exact `git filter-repo` / BFG commands to remove secrets from history. | P0 |
| `git-safe-scan` | Scan arbitrary files or directories outside a git repository (archives, backups, exports). | P1 |

---

## Planned Features & Options

### Phase 3 — Usability & Hook Integration

#### `git-safe-hooks` command
- `git-safe-hooks install` — writes `pre-commit`, `commit-msg`, and `pre-push` hook scripts
- `git-safe-hooks uninstall` — removes managed hooks
- `git-safe-hooks status` — shows which hooks are installed and their content

#### Inline suppression (`# gsp-ignore`)
- Add `# gsp-ignore: <check-name>` comment on a line to suppress a specific finding
- `# gsp-ignore` (no check name) suppresses all findings on that line
- Without this, repos with test fixtures or example credentials will always fail — kills adoption

#### `--base BRANCH` option for `git-safe-check`
- Scan only lines changed relative to a base branch (e.g., `--base main`)
- Critical for CI/CD PR checks — avoids re-scanning the entire codebase on every PR
- Example: `git-safe-check --base origin/main`

#### `--watch` option for `git-safe-check`
- Re-scan on file save, providing a real-time developer feedback loop
- Powered by filesystem events (polling fallback for compatibility)

#### `--output FILE` for `git-safe-search`
- Write the findings report to a file for audit archiving
- Supports `--format` selection (table, json, markdown, sarif)

### Phase 4 — Advanced Detection & Remediation

#### Missing checks from threat model
- **Branch name scanning** — detect secrets in branch names (`fix/prod-token-abc123`)
- **Tag annotation scanning** — scan annotated tag messages for secrets
- **Git stash scanning** — scan stash entries (`git stash list`)
- **Submodule URL scanning** — warn when submodule URLs point to internal/private repos
- **Absolute path disclosure** — flag `/home/username/...` paths leaking internal usernames
- **Malicious hook detection** — warn when unexpected executable scripts exist in `.git/hooks/`
- **GitHub Actions misconfig** — detect `pull_request_target` trigger and `write-all` permissions

#### `git-safe-fix` command
- For each finding in history, generate the exact remediation command:
  - `git filter-repo --path <file> --invert-paths` to purge a file
  - `git filter-repo --replace-text <expressions-file>` to redact a value
  - BFG Repo Cleaner equivalent commands
- Interactive mode: walk through each finding with a suggested fix
- Exposure window report: "This secret was in your history from 2024-01-15 to 2024-03-22 (66 days)"

#### Allowlist file (`.git-safe-allowlist.yml`)
- Persist false-positive suppressions by `check_name + filename + content-hash`
- `git-safe-check --allow <finding-id>` to add a finding to the allowlist
- Companion to inline suppression for binary files or third-party files

### Phase 5 — CI/CD Integration & Output Formats

#### SARIF output (`--format sarif`)
- SARIF (Static Analysis Results Interchange Format) — uploadable to GitHub Code Scanning
- Enables inline PR annotations on the GitHub UI
- `git-safe-search --format sarif --output results.sarif`

#### Markdown output (`--format markdown`)
- Formatted for posting as a PR comment via GitHub Actions
- Includes severity badges, file links, and remediation hints

#### CI integration helper
- `git-safe-hooks ci github` — generate a ready-to-use `.github/workflows/git-safe-publish.yml`
- `git-safe-hooks ci gitlab` — generate `.gitlab-ci.yml` snippet
- `git-safe-hooks ci pre-commit` — generate `.pre-commit-config.yaml` entry

#### Pattern testing utility
- `git-safe-check --test-pattern "MYCO-[A-Za-z0-9]{32}" --against "MYCO-abc123..."` — verify a custom pattern matches before adding to config
- `git-safe-check --list-patterns` — print all built-in patterns with examples

#### `git-safe-scan` command
- Scan arbitrary files or directories, no git repo required
- `git-safe-scan ./config-backup/ --format json`
- Useful for scanning archives, exported configs, CI artifacts

---

## Configuration

Configured via `.git-safe-publish.yml` (or `.json`) in the repo root, or a global `~/.git-safe-publish.yml`.

Key options (TBD as we implement):
- `allowed_remotes` — list of trusted remote URL patterns
- `protected_branches` — branches that block force-push
- `required_email_pattern` — regex the committer email must match
- `require_signed_commits` — boolean
- `custom_patterns` — additional regex patterns to scan for
- `ignore_paths` — paths/globs to exclude from scanning
- `severity_threshold` — minimum severity level to fail on (`p0`, `p1`, `p2`, `p3`)

---

## Repository Layout

```
git-safe-publish/
├── PROJECT.md
├── LOGS.md
├── RULES.md
├── README.md
├── DESIGN.md
├── SECURITY_RISKS.md
├── pyproject.toml
└── src/
    └── git_safe_publish/
        ├── __init__.py
        ├── cli.py          # All Click commands
        ├── config.py       # YAML config loading
        ├── git.py          # Subprocess git wrapper
        ├── models.py       # Finding, ScanResult, Severity
        ├── patterns.py     # 30+ regex patterns + entropy helpers
        ├── report.py       # Rich terminal output
        └── scanner/
            ├── files.py        # Sensitive file type detection
            ├── gitignore.py    # .gitignore coverage audit
            ├── history.py      # Full commit history scan
            ├── identity.py     # Author identity validation
            ├── remote.py       # Remote/branch safety
            └── secrets.py      # Diff + content secret scanning
```

---

## Engineering Expectations

- **Language / runtime** — Python 3.9+
- **Distribution** — installable via pip; single binary via PyInstaller/Nuitka planned
- **No runtime dependencies on the target repo** — works on any git repo regardless of language/ecosystem
- **Usable as a git hook** — `git-safe-hooks install` (Phase 3)
- **Exit codes** — `0` clean, `1` issues found, `2` tool error (distinguishable for CI)
- **Output** — human-readable by default; `--json` flag for machine-readable output; `--format sarif` planned
