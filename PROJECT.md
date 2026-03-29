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

| Command | Description |
|---|---|
| `git-safe-publish` | Full pre-publish check: secrets, identity, remote safety, `.gitignore`. Interactive confirmation before push. |
| `git-safe-push` | Drop-in replacement for `git push`. Runs safety checks then pushes if clean. |
| `git-safe-check` | Run all checks without pushing. Outputs a report. Exit code 0 = clean. |
| `git-safe-search` | Deep scan of full commit history. Finds secrets/issues buried in old commits. |

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
└── (src/ — TBD based on language/framework choice)
```

---

## Engineering Expectations

- **Language / runtime** — TBD
- **Distribution** — installable via a package manager (npm, pip, brew, etc.) + single binary option
- **No runtime dependencies on the target repo** — must work on any git repo regardless of language/ecosystem
- **Usable as a git hook** — `pre-push` hook installation should be one command
- **Exit codes** — `0` clean, `1` issues found, `2` tool error (distinguishable for CI)
- **Output** — human-readable by default; `--json` flag for machine-readable output
