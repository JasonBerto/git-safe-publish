# Implementation Log

## Phase 0 — Project Setup - 2026-03-28

- [x] Created reference files (PROJECT.md, LOGS.md, RULES.md, README.md, DESIGN.md)

---

## Phase 1 — Core Implementation - 2026-03-28

Full Python implementation of the `git-safe-publish` CLI toolchain.

### What was built

- [x] `pyproject.toml` — package manifest with `hatchling` build backend, `click`, `rich`, `pyyaml` dependencies, and four `[project.scripts]` entry points
- [x] `src/git_safe_publish/models.py` — `Finding`, `ScanResult`, `Severity` (P0–P3) data model
- [x] `src/git_safe_publish/patterns.py` — 30+ compiled regex patterns (AWS, GCP, Azure, GitHub, GitLab, Stripe, OpenAI, Anthropic, Slack, DB URLs, PEM keys, JWTs, generics) plus Shannon entropy helpers
- [x] `src/git_safe_publish/git.py` — subprocess wrapper for all git operations (diff, log, config, remote, branch, tracked files)
- [x] `src/git_safe_publish/config.py` — YAML config loader merging repo-local + global `~/.git-safe-publish.yml` with documented defaults
- [x] `src/git_safe_publish/scanner/secrets.py` — diff parser (added-lines only), line scanner, entropy heuristics, redaction
- [x] `src/git_safe_publish/scanner/files.py` — 40+ sensitive file type patterns (`.env`, `*.pem`, `*.key`, `*.tfstate`, `kubeconfig`, etc.)
- [x] `src/git_safe_publish/scanner/identity.py` — author email/name validation, required-email-pattern check, signing check
- [x] `src/git_safe_publish/scanner/remote.py` — remote URL validation, insecure protocol detection, force-push guard, protected branch check
- [x] `src/git_safe_publish/scanner/gitignore.py` — `.gitignore` coverage audit with recommended additions
- [x] `src/git_safe_publish/scanner/history.py` — full commit history scanner with progress callback
- [x] `src/git_safe_publish/report.py` — `rich`-based terminal output (tables, panels, severity badges, redaction, JSON mode)
- [x] `src/git_safe_publish/cli.py` — four Click commands: `git-safe-check`, `git-safe-push`, `git-safe-search`, `git-safe-publish`
- [x] `tests/test_patterns.py` — unit tests for all pattern categories
- [x] `tests/test_secrets_scanner.py` — unit tests for diff parser and scanners
- [x] `.gitignore` — comprehensive Python project ignore list
- [x] `README.md` — full public documentation with usage examples

### Architecture decisions

- **`src/` layout** — standard Python packaging best practice, prevents accidental imports of un-installed code
- **Subprocess over GitPython** — no heavy dependency, full control over git invocations
- **Diff-only scanning (added lines)** — avoids false positives from removed/context lines
- **Severity threshold config** — allows projects to tune from strict (P0 only) to verbose (P3)
- **Exit codes 0/1/2** — distinguishable by CI (clean / issues / tool error)

---
