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

## Phase 2 — `git-safe-commit`, `--test` flag, Demo Tests, v0.2.0 - 2026-03-28

- [x] Added `git-safe-commit` command — drop-in for `git commit` with staged diff, sensitive file, commit message, identity, and `.gitignore` scanning
- [x] Added `--test` flag to all five commands — runs `pytest tests/` via subprocess, output visible via `-s`
- [x] Added `tests/test_commit.py` — 13 tests for `_extract_commit_message` and `scan_commit_message`
- [x] Added `tests/test_live_detection.py` — 4 demo scenarios creating real `test_file_*` temp files with embedded secrets (config.py, .env, Dockerfile, clean config)
- [x] Fixed `AttributeError` in `_scan_line` when optional regex capture group returns `None`
- [x] Bumped version to `0.2.0` in both `pyproject.toml` and `__init__.py`
- [x] 68 tests passing

---

## Phase 3 — Planned: Usability & Hook Integration

### Scope
- [ ] `git-safe-hooks` command (install / uninstall / status for pre-commit, commit-msg, pre-push)
- [ ] Inline suppression comments (`# gsp-ignore: <check-name>`)
- [ ] `--base BRANCH` option for `git-safe-check` (PR diff mode — scan only changed lines)
- [ ] `--watch` option for `git-safe-check` (re-scan on file change)
- [ ] `--output FILE` for `git-safe-search`
- [ ] `--list-patterns` for `git-safe-check`

---

## Phase 4 — Planned: Advanced Detection & Remediation

### Scope
- [ ] Branch name scanning for embedded secrets
- [ ] Tag annotation scanning
- [ ] Git stash scanning
- [ ] Submodule URL scanning (internal repos in public projects)
- [ ] Absolute path disclosure detection (`/home/username/...`)
- [ ] Malicious `.git/hooks` detection
- [ ] GitHub Actions misconfiguration checks (`pull_request_target`, `write-all`)
- [ ] `git-safe-fix` command — guided remediation with `git filter-repo` / BFG commands
- [ ] Exposure window reporting (first introduced → last seen date)
- [ ] Allowlist file (`.git-safe-allowlist.yml`) for persistent false-positive suppression

---

## Phase 5 — Planned: CI/CD Integration & Output Formats

### Scope
- [ ] SARIF output (`--format sarif`) — GitHub Code Scanning integration
- [ ] Markdown output (`--format markdown`) — PR comment formatting
- [ ] CI integration helper (`git-safe-hooks ci github/gitlab/pre-commit`)
- [ ] Pattern testing utility (`--test-pattern`, `--list-patterns`)
- [ ] `git-safe-scan` command — scan arbitrary files/dirs outside a git repo

