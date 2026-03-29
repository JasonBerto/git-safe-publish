"""CLI entry points for git-safe-publish.

Commands:
  git-safe-check    — scan staged/tracked content, report issues, exit 0/1/2
  git-safe-commit   — drop-in for `git commit` with pre-commit safety checks
  git-safe-search   — deep-scan full commit history
  git-safe-push     — drop-in for `git push` with pre-push safety checks
  git-safe-publish  — interactive full check + push flow
  git-safe-hooks    — install/uninstall/status/ci git hooks
  git-safe-fix      — guided remediation for history findings
  git-safe-scan     — scan arbitrary files/dirs outside a git repo
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

import click

from git_safe_publish import __version__
from git_safe_publish.config import load_config, write_default_config
from git_safe_publish.git import (
    GitError,
    NotAGitRepo,
    find_repo_root,
    get_current_branch,
    get_diff_from_base,
    get_remote_url,
    get_remotes,
    get_staged_diff,
    get_staged_files,
    get_tracked_files,
    has_commits,
)
from git_safe_publish.models import ScanResult, Severity
from git_safe_publish.report import (
    confirm,
    console,
    output_result,
    print_findings,
    print_header,
    print_json,
    print_patterns_table,
    print_progress,
    print_progress_done,
    print_remediation_detail,
    print_summary,
)
from git_safe_publish.scanner.files import scan_staged_files, scan_tracked_files
from git_safe_publish.scanner.gitignore import scan_gitignore
from git_safe_publish.scanner.history import scan_history
from git_safe_publish.scanner.identity import scan_identity
from git_safe_publish.scanner.remote import scan_remote
from git_safe_publish.scanner.secrets import scan_diff, scan_file_content


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _find_tests_dir() -> Optional[Path]:
    candidate = Path(__file__).parent.parent.parent / "tests"
    if candidate.is_dir():
        return candidate.resolve()
    try:
        repo_tests = find_repo_root() / "tests"
        if repo_tests.is_dir():
            return repo_tests.resolve()
    except NotAGitRepo:
        pass
    return None


def _run_tests(verbose: bool = False) -> int:
    tests_dir = _find_tests_dir()
    if tests_dir is None:
        console.print("[bold red]Error:[/bold red] Could not find a tests/ directory.")
        console.print(
            "[dim]--test is intended for development use. "
            "Run from the project root, or install in editable mode.[/dim]"
        )
        return 2
    print_header("git-safe-publish — test suite")
    console.print(f"[dim]Running tests from: {tests_dir}[/dim]\n")
    cmd = [sys.executable, "-m", "pytest", str(tests_dir), "-v", "-s"]
    proc = subprocess.run(cmd)
    if proc.returncode == 0:
        console.print("\n[bold green]✔  All tests passed.[/bold green]")
    else:
        console.print("\n[bold red]✖  Tests failed.[/bold red]")
    return proc.returncode


def _get_repo() -> Path:
    try:
        return find_repo_root()
    except NotAGitRepo as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(2)


def _load(repo: Path):
    return load_config(repo)


def _exit_code(result: ScanResult, config) -> int:
    if result.is_clean:
        return 0
    threshold = {"P0": Severity.P0, "P1": Severity.P1, "P2": Severity.P2, "P3": Severity.P3}.get(
        config.severity_threshold, Severity.P0
    )
    if any(f.severity <= threshold for f in result.findings):
        return 1
    return 0


def _apply_allowlist(result: ScanResult, repo: Path) -> ScanResult:
    from git_safe_publish.allowlist import load_allowlist
    allowlist = load_allowlist(repo)
    if not allowlist.entries:
        return result
    filtered = allowlist.filter(result.findings)
    suppressed = len(result.findings) - len(filtered)
    if suppressed:
        console.print(f"[dim]  {suppressed} finding(s) suppressed by allowlist.[/dim]")
    return ScanResult(filtered)


def _run_full_check(
    repo: Path,
    config,
    staged_only: bool = False,
    check_remote_flag: bool = True,
    target_remote: str = "origin",
    target_branch: Optional[str] = None,
    force: bool = False,
    base_branch: Optional[str] = None,
    include_metadata: bool = False,
    verbose: bool = False,
) -> ScanResult:

    def _step(label: str, fn, *args, **kwargs) -> ScanResult:
        """Run a check, optionally printing a verbose step line."""
        if verbose:
            console.print(f"  [dim]→[/dim]  {label:<45}", end="")
        sub = fn(*args, **kwargs)
        if verbose:
            count = len(sub.findings)
            if count == 0:
                console.print("[green]✔  clean[/green]")
            elif any(f.severity.value in ("P0", "P1") for f in sub.findings):
                console.print(f"[red]✖  {count} finding(s)[/red]")
            else:
                console.print(f"[yellow]⚠  {count} finding(s)[/yellow]")
        return sub

    result = ScanResult()

    # 1. Secret scan on staged diff (or base-diff if --base provided)
    if base_branch:
        diff = get_diff_from_base(repo, base_branch)
    else:
        diff = get_staged_diff(repo)
    if diff:
        result.merge(_step("Scanning staged diff for secrets…", scan_diff, diff, config))
    elif verbose:
        console.print("  [dim]→[/dim]  [dim]Scanning staged diff for secrets…[/dim]" + " " * 3 + "[dim]—  nothing staged[/dim]")

    # 2. Sensitive file detection
    staged_files = get_staged_files(repo)
    if staged_files:
        result.merge(_step("Scanning staged file types…", scan_staged_files, staged_files, config))
    elif verbose:
        console.print("  [dim]→[/dim]  [dim]Scanning staged file types…[/dim]" + " " * 13 + "[dim]—  nothing staged[/dim]")

    if not staged_only and not base_branch:
        tracked = get_tracked_files(repo)
        if tracked:
            result.merge(_step("Scanning tracked file types…", scan_tracked_files, tracked, config))

    # 3. .gitignore audit
    if config.check_gitignore:
        result.merge(_step("Auditing .gitignore coverage…", scan_gitignore, repo, config))

    # 4. Identity check
    if config.check_identity:
        result.merge(_step("Checking committer identity…", scan_identity, repo, config))

    # 5. Remote / branch safety
    if check_remote_flag and config.check_remote and get_remotes(repo):
        result.merge(_step("Checking remote & branch safety…", scan_remote, repo, config,
                           target_remote, target_branch, force))

    # 6. Metadata checks (Phase 4)
    if include_metadata:
        from git_safe_publish.scanner.metadata import (
            scan_branch_names, scan_tag_annotations, scan_submodules,
            scan_git_hooks, scan_github_actions,
        )
        result.merge(_step("Scanning branch names…", scan_branch_names, repo, config))
        result.merge(_step("Scanning tag annotations…", scan_tag_annotations, repo, config))
        result.merge(_step("Scanning submodule URLs…", scan_submodules, repo, config))
        result.merge(_step("Checking .git/hooks integrity…", scan_git_hooks, repo, config))
        result.merge(_step("Scanning GitHub Actions workflows…", scan_github_actions, repo, config))

    if verbose:
        console.print()

    return _apply_allowlist(result, repo)


def _extract_commit_message(git_args: Tuple[str, ...]) -> Optional[str]:
    args = list(git_args)
    for flag in ("-m", "--message"):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                return args[idx + 1]
        prefix = flag + ("=" if flag.startswith("--") else "")
        for arg in args:
            if arg.startswith(prefix) and len(arg) > len(prefix):
                return arg[len(prefix):]
    return None


# ---------------------------------------------------------------------------
# --format option shared definition
# ---------------------------------------------------------------------------

_FORMAT_CHOICES = click.Choice(["table", "json", "sarif", "markdown"], case_sensitive=False)


# ---------------------------------------------------------------------------
# git-safe-check
# ---------------------------------------------------------------------------

@click.command("git-safe-check")
@click.option("--staged", is_flag=True, default=False, help="Check staged changes only.")
@click.option("--base", "base_branch", default=None, help="Scan only lines changed vs. this branch (e.g. --base main). Ideal for CI PR checks.")
@click.option("--remote", "target_remote", default="origin", show_default=True)
@click.option("--branch", "target_branch", default=None)
@click.option("--format", "output_fmt", type=_FORMAT_CHOICES, default="table", show_default=True)
@click.option("--json", "output_json", is_flag=True, default=False, hidden=True, help="Shorthand for --format json.")
@click.option("--output", "output_file", default=None, help="Write report to FILE instead of stdout.")
@click.option("--no-remote", is_flag=True, default=False)
@click.option("--remediate", is_flag=True, default=False, help="Show full remediation steps.")
@click.option("--metadata", is_flag=True, default=False, help="Also scan branch names, tags, submodules, hooks, and GitHub Actions.")
@click.option("--watch", is_flag=True, default=False, help="Re-run checks every 3 seconds (Ctrl+C to stop).")
@click.option("--init-config", is_flag=True, default=False, help="Write default .git-safe-publish.yml and exit.")
@click.option("--list-patterns", is_flag=True, default=False, help="Print all built-in secret patterns and exit.")
@click.option("--test-pattern", default=None, metavar="REGEX", help="Test a custom regex against --against value.")
@click.option("--against", default=None, metavar="VALUE", help="Value to test with --test-pattern.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Print each check as it runs with a pass/fail indicator.")
@click.option("--test", "run_test", is_flag=True, default=False, help="Run the test suite and exit.")
@click.version_option(__version__, prog_name="git-safe-check")
def check(
    staged, base_branch, target_remote, target_branch,
    output_fmt, output_json, output_file,
    no_remote, remediate, metadata, watch,
    init_config, list_patterns, test_pattern, against,
    verbose, run_test,
) -> None:
    """Scan staged/tracked content for secrets and safety issues.

    Exits 0 if clean, 1 if issues found, 2 on error.
    """
    if run_test:
        sys.exit(_run_tests())

    if list_patterns:
        print_patterns_table()
        sys.exit(0)

    if test_pattern:
        import re
        value = against or ""
        try:
            m = re.search(test_pattern, value)
            if m:
                console.print(f"[green]✔  Pattern matched:[/green] {m.group(0)!r}")
                sys.exit(0)
            else:
                console.print(f"[yellow]✖  No match[/yellow] for pattern against {value!r}")
                sys.exit(1)
        except re.error as e:
            console.print(f"[red]Invalid regex:[/red] {e}")
            sys.exit(2)

    repo = _get_repo()
    config = _load(repo)

    if init_config:
        cfg_path = repo / ".git-safe-publish.yml"
        write_default_config(cfg_path)
        console.print(f"[green]✔[/green] Config written to {cfg_path}")
        sys.exit(0)

    fmt = "json" if output_json else output_fmt

    def _run_once():
        result = _run_full_check(
            repo, config,
            staged_only=staged,
            check_remote_flag=not no_remote,
            target_remote=target_remote,
            target_branch=target_branch,
            base_branch=base_branch,
            include_metadata=metadata,
            verbose=verbose,
        )
        if fmt == "table":
            print_header("git-safe-check")
        output_result(result, fmt=fmt, scope="check", output_path=output_file, show_remediation=remediate)
        return result

    if watch:
        console.print("[dim]Watch mode — press Ctrl+C to stop[/dim]\n")
        try:
            while True:
                result = _run_once()
                console.print(f"[dim]Next scan in 3s…[/dim]", end="\r")
                time.sleep(3)
                console.print("\n" + "─" * 60)
        except KeyboardInterrupt:
            console.print("\n[dim]Watch stopped.[/dim]")
            sys.exit(0)

    result = _run_once()
    sys.exit(_exit_code(result, config))


# ---------------------------------------------------------------------------
# git-safe-commit
# ---------------------------------------------------------------------------

@click.command(
    "git-safe-commit",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("git_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--skip-checks", is_flag=True, default=False)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Print each check as it runs with a pass/fail indicator.")
@click.option("--test", "run_test", is_flag=True, default=False)
@click.version_option(__version__, prog_name="git-safe-commit")
@click.pass_context
def commit(ctx, git_args, skip_checks, verbose, run_test) -> None:
    """Drop-in replacement for `git commit` with pre-commit safety checks.

    Scans staged changes, sensitive files, commit message, and identity.
    All arguments are passed directly to `git commit`.
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    if not skip_checks:
        print_header("git-safe-commit")
        result = ScanResult()

        def _vstep(label: str, sub: ScanResult) -> ScanResult:
            if verbose:
                count = len(sub.findings)
                tag = (
                    "[green]✔  clean[/green]" if count == 0
                    else f"[red]✖  {count} finding(s)[/red]" if any(f.severity.value in ("P0", "P1") for f in sub.findings)
                    else f"[yellow]⚠  {count} finding(s)[/yellow]"
                )
                console.print(f"  [dim]→[/dim]  {label:<45}{tag}")
            return sub

        diff = get_staged_diff(repo)
        if diff:
            result.merge(_vstep("Scanning staged diff for secrets…", scan_diff(diff, config)))
        elif verbose:
            console.print("  [dim]→[/dim]  [dim]Scanning staged diff for secrets…[/dim]" + " " * 3 + "[dim]—  nothing staged[/dim]")

        staged_files = get_staged_files(repo)
        if staged_files:
            result.merge(_vstep("Scanning staged file types…", scan_staged_files(staged_files, config)))
        elif verbose:
            console.print("  [dim]→[/dim]  [dim]Scanning staged file types…[/dim]" + " " * 13 + "[dim]—  nothing staged[/dim]")

        message = _extract_commit_message(git_args)
        if message:
            from git_safe_publish.scanner.secrets import scan_commit_message
            msg_result = scan_commit_message(message, "<pending>", config)
            for f in msg_result.findings:
                f.description = f"[commit message] {f.description}"
            result.merge(_vstep("Scanning commit message…", msg_result))
        elif verbose:
            console.print("  [dim]→[/dim]  [dim]Scanning commit message…[/dim]" + " " * 19 + "[dim]—  no -m flag[/dim]")

        if config.check_identity:
            result.merge(_vstep("Checking committer identity…", scan_identity(repo, config)))

        if config.check_gitignore:
            result.merge(_vstep("Auditing .gitignore coverage…", scan_gitignore(repo, config)))

        if verbose:
            console.print()

        result = _apply_allowlist(result, repo)
        print_findings(result)
        print_summary(result, scope="pre-commit check")

        if result.has_blockers and config.block_on_secrets:
            console.print("[bold red]✖  Commit blocked — resolve critical issues first.[/bold red]\n")
            sys.exit(1)

        if not result.is_clean:
            if not confirm("Issues found. Commit anyway?", default=False):
                console.print("[yellow]Commit cancelled.[/yellow]")
                sys.exit(1)

    cmd = ["git", "commit", *git_args]
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    proc = subprocess.run(cmd, cwd=repo)
    sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# git-safe-search
# ---------------------------------------------------------------------------

@click.command("git-safe-search")
@click.option("--branch", default="--all", show_default=True)
@click.option("--limit", default=None, type=int)
@click.option("--since", default=None, metavar="DATE", help="Only scan commits after this date (e.g. 2024-01-01).")
@click.option("--author", default=None, metavar="PATTERN", help="Only scan commits by matching author email.")
@click.option("--format", "output_fmt", type=_FORMAT_CHOICES, default="table", show_default=True)
@click.option("--json", "output_json", is_flag=True, default=False, hidden=True)
@click.option("--output", "output_file", default=None, help="Write report to FILE.")
@click.option("--remediate", is_flag=True, default=False)
@click.option("--exposure", is_flag=True, default=False, help="Show exposure window (first/last seen date per finding).")
@click.option("--metadata", is_flag=True, default=False, help="Also scan branch names, tags, stash, submodules, hooks.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show each commit SHA and finding count as it is scanned.")
@click.option("--quiet", is_flag=True, default=False)
@click.option("--test", "run_test", is_flag=True, default=False)
@click.version_option(__version__, prog_name="git-safe-search")
def search(branch, limit, since, author, output_fmt, output_json, output_file,
           remediate, exposure, metadata, verbose, quiet, run_test) -> None:
    """Deep-scan full commit history for secrets and sensitive data.

    Exits 0 if clean, 1 if issues found, 2 on error.
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    if not has_commits(repo):
        console.print("[yellow]No commits yet — nothing to scan.[/yellow]")
        sys.exit(0)

    fmt = "json" if output_json else output_fmt

    if fmt == "table":
        print_header("git-safe-search")
        scope_parts = [f"branch: {branch}"]
        if limit:
            scope_parts.append(f"limit: {limit}")
        if since:
            scope_parts.append(f"since: {since}")
        if author:
            scope_parts.append(f"author: {author}")
        console.print(f"[dim]Scanning history ({', '.join(scope_parts)})…[/dim]\n")

    def _progress(current, total, sha):
        if quiet:
            return
        if verbose and fmt == "table":
            console.print(f"  [dim]→[/dim]  [{current}/{total}] {sha[:12]}…", end="")
        elif fmt == "table":
            print_progress(current, total, sha)

    # Filter commits by --since and --author
    from git_safe_publish.git import get_all_commits as _get_all_commits
    commits = _get_all_commits(repo, branch=branch)
    if since:
        commits = [c for c in commits if c.date >= since]
    if author:
        import re
        commits = [c for c in commits if re.search(author, c.author_email, re.IGNORECASE)]
    if limit:
        commits = commits[:limit]

    # Run history scan on the filtered list
    from git_safe_publish.scanner.history import scan_history
    result = scan_history(
        repo, config,
        progress_callback=_progress, track_dates=exposure,
        commits=commits,
    )

    # Metadata scans
    if metadata:
        from git_safe_publish.scanner.metadata import (
            scan_branch_names, scan_tag_annotations, scan_stash,
            scan_submodules, scan_git_hooks, scan_github_actions,
        )

        def _mstep(label: str, fn, *args) -> ScanResult:
            if verbose and fmt == "table":
                console.print(f"  [dim]→[/dim]  {label:<45}", end="")
            sub = fn(*args)
            if verbose and fmt == "table":
                count = len(sub.findings)
                tag = (
                    "[green]✔  clean[/green]" if count == 0
                    else f"[red]✖  {count} finding(s)[/red]" if any(f.severity.value in ("P0", "P1") for f in sub.findings)
                    else f"[yellow]⚠  {count} finding(s)[/yellow]"
                )
                console.print(tag)
            return sub

        result.merge(_mstep("Scanning branch names…", scan_branch_names, repo, config))
        result.merge(_mstep("Scanning tag annotations…", scan_tag_annotations, repo, config))
        result.merge(_mstep("Scanning stash…", scan_stash, repo, config))
        result.merge(_mstep("Scanning submodule URLs…", scan_submodules, repo, config))
        result.merge(_mstep("Checking .git/hooks integrity…", scan_git_hooks, repo, config))
        result.merge(_mstep("Scanning GitHub Actions workflows…", scan_github_actions, repo, config))

    result = _apply_allowlist(result, repo)

    if not quiet and fmt == "table":
        print_progress_done(len(commits))
        console.print()

        if exposure and not result.is_clean:
            from git_safe_publish.scanner.history import compute_exposure_windows
            windows = compute_exposure_windows(result.findings)
            if windows:
                console.print("[bold]Exposure windows:[/bold]")
                for w in windows:
                    console.print(f"  [dim]{w.summary}[/dim]")
                console.print()

    output_result(result, fmt=fmt, scope="history scan", output_path=output_file, show_remediation=remediate)
    sys.exit(_exit_code(result, config))


# ---------------------------------------------------------------------------
# git-safe-push
# ---------------------------------------------------------------------------

@click.command(
    "git-safe-push",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("git_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--format", "output_fmt", type=_FORMAT_CHOICES, default="table", show_default=True)
@click.option("--json", "output_json", is_flag=True, default=False, hidden=True)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Print each check as it runs with a pass/fail indicator.")
@click.option("--skip-checks", is_flag=True, default=False)
@click.option("--test", "run_test", is_flag=True, default=False)
@click.version_option(__version__, prog_name="git-safe-push")
@click.pass_context
def push(ctx, git_args, output_fmt, output_json, verbose, skip_checks, run_test) -> None:
    """Drop-in replacement for `git push` with pre-push safety checks."""
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)
    fmt = "json" if output_json else output_fmt

    force = any(a in ("--force", "-f", "--force-with-lease") for a in git_args)
    target_remote = next((a for a in git_args if not a.startswith("-")), "origin")
    target_branch = next(
        (a for a in git_args if not a.startswith("-") and a != target_remote),
        None,
    )

    if not skip_checks:
        if fmt == "table":
            print_header("git-safe-push")

        result = _run_full_check(
            repo, config,
            staged_only=True,
            check_remote_flag=True,
            target_remote=target_remote,
            target_branch=target_branch,
            force=force,
            verbose=verbose,
        )

        output_result(result, fmt=fmt, scope="pre-push check")

        if fmt != "table":
            sys.exit(_exit_code(result, config))

        if result.has_blockers and config.block_on_secrets:
            console.print("[bold red]✖  Push blocked — critical issues must be resolved first.[/bold red]")
            sys.exit(1)

        if not result.is_clean:
            if not confirm("Issues found. Push anyway?", default=False):
                console.print("[yellow]Push cancelled.[/yellow]")
                sys.exit(1)

    cmd = ["git", "push", *git_args]
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    proc = subprocess.run(cmd, cwd=repo)
    sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# git-safe-publish  (interactive full flow)
# ---------------------------------------------------------------------------

@click.command("git-safe-publish")
@click.option("--remote", "target_remote", default="origin", show_default=True)
@click.option("--branch", "target_branch", default=None)
@click.option("--format", "output_fmt", type=_FORMAT_CHOICES, default="table", show_default=True)
@click.option("--json", "output_json", is_flag=True, default=False, hidden=True)
@click.option("--remediate", is_flag=True, default=False)
@click.option("--dry-run", is_flag=True, default=False)
@click.option("--force", is_flag=True, default=False)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Print each check as it runs with a pass/fail indicator.")
@click.option("--test", "run_test", is_flag=True, default=False)
@click.version_option(__version__, prog_name="git-safe-publish")
def publish(target_remote, target_branch, output_fmt, output_json, remediate, dry_run, force, verbose, run_test) -> None:
    """Full interactive safety check + push workflow."""
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)
    fmt = "json" if output_json else output_fmt

    if fmt == "table":
        print_header("git-safe-publish")

    branch = target_branch or get_current_branch(repo)

    result = _run_full_check(
        repo, config,
        staged_only=False,
        check_remote_flag=True,
        target_remote=target_remote,
        target_branch=branch,
        force=force,
        include_metadata=True,
        verbose=verbose,
    )

    output_result(result, fmt=fmt, scope="full check", show_remediation=remediate)

    if fmt != "table":
        sys.exit(_exit_code(result, config))

    if result.has_blockers and config.block_on_secrets:
        console.print("[bold red]✖  Publish blocked — resolve critical issues before pushing.[/bold red]\n")
        sys.exit(1)

    from git_safe_publish.git import get_author_email, get_author_name
    email = get_author_email(repo) or "not set"
    name = get_author_name(repo) or "not set"
    remotes_list = get_remotes(repo)
    remote_url = get_remote_url(repo, target_remote) if target_remote in remotes_list else "(none)"

    console.print(f"  Author  : [bold]{name}[/bold] <{email}>")
    console.print(f"  Remote  : [bold]{target_remote}[/bold]  {remote_url}")
    console.print(f"  Branch  : [bold]{branch}[/bold]")
    if dry_run:
        console.print("  Mode    : [yellow]dry-run[/yellow] (will not push)")
    console.print()

    if not result.is_clean:
        if not confirm(f"[yellow]{len(result.findings)} issue(s) found — push anyway?[/yellow]", default=False):
            console.print("[yellow]Publish cancelled.[/yellow]")
            sys.exit(1)
    else:
        if not confirm(f"Push [bold]{branch}[/bold] → [bold]{target_remote}[/bold]?", default=True):
            console.print("[yellow]Publish cancelled.[/yellow]")
            sys.exit(0)

    if dry_run:
        console.print("[yellow]Dry-run — skipping push.[/yellow]")
        sys.exit(0)

    push_args = [target_remote, branch]
    if force:
        push_args = ["--force-with-lease", *push_args]

    cmd = ["git", "push", *push_args]
    console.print(f"\n[dim]Running: {' '.join(cmd)}[/dim]")
    proc = subprocess.run(cmd, cwd=repo)
    if proc.returncode == 0:
        console.print("\n[bold green]✔  Published successfully.[/bold green]")
    sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# git-safe-hooks
# ---------------------------------------------------------------------------

_HOOK_TEMPLATES = {
    "pre-commit": """\
#!/bin/sh
# installed by git-safe-publish
# Scans staged changes for secrets before committing.
git-safe-check --staged
""",
    "commit-msg": """\
#!/bin/sh
# installed by git-safe-publish
# Scans the commit message for embedded secrets.
MSG=$(cat "$1")
echo "$MSG" | git-safe-check --staged --no-remote 2>/dev/null || true
""",
    "pre-push": """\
#!/bin/sh
# installed by git-safe-publish
# Runs a full check before pushing.
git-safe-check
""",
}

_CI_TEMPLATES = {
    "github": """\
# .github/workflows/git-safe-publish.yml
# Generated by: git-safe-hooks ci github
name: git-safe-publish

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read
  security-events: write  # needed for SARIF upload

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history for git-safe-search

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install git-safe-publish

      - name: Scan history for secrets
        run: git-safe-search --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
""",
    "gitlab": """\
# .gitlab-ci.yml snippet
# Generated by: git-safe-hooks ci gitlab
git-safe-publish:
  stage: test
  image: python:3.11-slim
  script:
    - pip install git-safe-publish
    - git-safe-search --format json --output gl-secret-scan.json || true
  artifacts:
    reports:
      secret_detection: gl-secret-scan.json
""",
    "pre-commit": """\
# .pre-commit-config.yaml entry
# Generated by: git-safe-hooks ci pre-commit
repos:
  - repo: local
    hooks:
      - id: git-safe-check
        name: git-safe-publish secret scan
        entry: git-safe-check --staged
        language: system
        pass_filenames: false
        stages: [commit]
""",
}


@click.group("git-safe-hooks")
def hooks() -> None:
    """Manage git-safe-publish git hooks and CI integration."""


@hooks.command("install")
@click.option("--hook", "hook_names", multiple=True,
              type=click.Choice(["pre-commit", "commit-msg", "pre-push"]),
              help="Which hook(s) to install. Defaults to all three.")
@click.option("--force", is_flag=True, default=False, help="Overwrite existing hooks.")
def hooks_install(hook_names, force) -> None:
    """Install git hooks (pre-commit, commit-msg, pre-push)."""
    repo = _get_repo()
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    to_install = list(hook_names) or list(_HOOK_TEMPLATES.keys())

    for name in to_install:
        path = hooks_dir / name
        if path.exists() and not force:
            content = path.read_text(encoding="utf-8", errors="replace")
            if "git-safe-publish" not in content:
                console.print(
                    f"[yellow]  ⚠  Skipping {name} — already exists (use --force to overwrite)[/yellow]"
                )
                continue
        path.write_text(_HOOK_TEMPLATES[name], encoding="utf-8")
        path.chmod(0o755)
        console.print(f"[green]  ✔[/green]  Installed .git/hooks/{name}")

    console.print()
    console.print("[dim]Hooks will run automatically on git commit / git push.[/dim]")


@hooks.command("uninstall")
@click.option("--hook", "hook_names", multiple=True,
              type=click.Choice(["pre-commit", "commit-msg", "pre-push"]))
def hooks_uninstall(hook_names) -> None:
    """Remove git-safe-publish managed hooks."""
    repo = _get_repo()
    hooks_dir = repo / ".git" / "hooks"
    to_remove = list(hook_names) or list(_HOOK_TEMPLATES.keys())

    for name in to_remove:
        path = hooks_dir / name
        if not path.exists():
            console.print(f"[dim]  {name} not found — skipping[/dim]")
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        if "git-safe-publish" not in content:
            console.print(f"[yellow]  ⚠  {name} was not installed by git-safe-publish — skipping[/yellow]")
            continue
        path.unlink()
        console.print(f"[green]  ✔[/green]  Removed .git/hooks/{name}")


@hooks.command("status")
def hooks_status() -> None:
    """Show which git-safe-publish hooks are installed."""
    repo = _get_repo()
    hooks_dir = repo / ".git" / "hooks"
    console.print()
    for name in _HOOK_TEMPLATES:
        path = hooks_dir / name
        if not path.exists():
            console.print(f"  [dim]{name:15}[/dim]  [red]not installed[/red]")
        else:
            content = path.read_text(encoding="utf-8", errors="replace")
            managed = "git-safe-publish" in content
            tag = "[green]installed (managed)[/green]" if managed else "[yellow]installed (unmanaged)[/yellow]"
            console.print(f"  [bold]{name:15}[/bold]  {tag}")
    console.print()


@hooks.command("ci")
@click.argument("platform", type=click.Choice(["github", "gitlab", "pre-commit"]))
@click.option("--output", "output_file", default=None, help="Write to FILE instead of stdout.")
def hooks_ci(platform, output_file) -> None:
    """Generate a CI integration snippet for the given platform."""
    template = _CI_TEMPLATES[platform]
    if output_file:
        Path(output_file).write_text(template, encoding="utf-8")
        console.print(f"[green]✔[/green] CI config written to {output_file}")
    else:
        click.echo(template)


# ---------------------------------------------------------------------------
# git-safe-fix
# ---------------------------------------------------------------------------

@click.command("git-safe-fix")
@click.option("--history", is_flag=True, default=False, help="Scan full history then generate remediation commands.")
@click.option("--branch", default="--all", show_default=True)
@click.option("--limit", default=None, type=int)
@click.option("--output", "output_file", default=None, help="Write remediation script to FILE.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show each commit as it is scanned.")
@click.option("--test", "run_test", is_flag=True, default=False)
@click.version_option(__version__, prog_name="git-safe-fix")
def fix(history, branch, limit, output_file, verbose, run_test) -> None:
    """Generate guided remediation commands for history findings.

    Scans staged changes (or full history with --history), then produces
    exact `git filter-repo` commands to remove secrets.
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    print_header("git-safe-fix")

    if history:
        if not has_commits(repo):
            console.print("[yellow]No commits yet.[/yellow]")
            sys.exit(0)
        console.print("[dim]Scanning full history…[/dim]\n")

        def _prog(cur, tot, sha):
            if verbose:
                console.print(f"  [dim]→[/dim]  [{cur}/{tot}] {sha[:12]}…")
            else:
                print_progress(cur, tot, sha)

        result = scan_history(repo, config, branch=branch, limit=limit,
                              progress_callback=_prog, track_dates=True)
        print_progress_done(limit or 0)
        console.print()
    else:
        diff = get_staged_diff(repo)
        result = ScanResult()
        if diff:
            result.merge(scan_diff(diff, config))

    result = _apply_allowlist(result, repo)

    if result.is_clean:
        console.print("[bold green]✔  No findings — nothing to fix.[/bold green]")
        sys.exit(0)

    print_findings(result)
    print_summary(result, scope="fix scan")

    # Generate remediation script
    lines = ["#!/bin/sh", "# Remediation script generated by git-safe-fix", "# Review carefully before running!\n"]

    # Group unique filenames with secrets
    files_with_secrets: dict = {}
    for f in result.findings:
        if f.filename and not f.filename.startswith("<"):
            files_with_secrets.setdefault(f.filename, []).append(f.check_name)

    if files_with_secrets:
        lines.append("# --- Remove files containing secrets from entire history ---")
        for filepath, checks in files_with_secrets.items():
            lines.append(f"# Checks: {', '.join(set(checks))}")
            lines.append(f"git filter-repo --path {filepath} --invert-paths")
            lines.append("")

    # Suggest replace-text for specific secret values
    lines.append("# --- Or redact specific secret values in history ---")
    lines.append("# Create a replacements file, then run:")
    lines.append("# git filter-repo --replace-text replacements.txt")
    lines.append("# Format of replacements.txt: LITERAL:old_value==>REDACTED")
    lines.append("")

    # Exposure window summary
    from git_safe_publish.scanner.history import compute_exposure_windows
    windows = compute_exposure_windows(result.findings)
    if windows:
        lines.append("# --- Exposure windows ---")
        for w in windows:
            lines.append(f"# {w.summary}")
        lines.append("")

    lines.append("# After rewriting history:")
    lines.append("# git push --force-with-lease origin <branch>")
    lines.append("# Notify all collaborators to re-clone or reset their forks.")

    script = "\n".join(lines)

    if output_file:
        Path(output_file).write_text(script, encoding="utf-8")
        console.print(f"\n[green]✔[/green] Remediation script written to [bold]{output_file}[/bold]")
    else:
        console.print("\n[bold]Remediation script:[/bold]\n")
        for line in script.splitlines():
            style = "dim" if line.startswith("#") else ""
            console.print(f"  [{style}]{line}[/{style}]" if style else f"  {line}")

    sys.exit(1 if result.has_blockers else 0)


# ---------------------------------------------------------------------------
# git-safe-scan  (arbitrary files / dirs, no git repo required)
# ---------------------------------------------------------------------------

@click.command("git-safe-scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--format", "output_fmt", type=_FORMAT_CHOICES, default="table", show_default=True)
@click.option("--json", "output_json", is_flag=True, default=False, hidden=True)
@click.option("--output", "output_file", default=None)
@click.option("--severity", "severity_threshold", default="P2", show_default=True,
              type=click.Choice(["P0", "P1", "P2", "P3"]))
@click.option("--ignore", "ignore_globs", multiple=True, metavar="GLOB", help="Glob patterns to skip.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show each file as it is scanned with a pass/fail indicator.")
@click.option("--remediate", is_flag=True, default=False)
@click.option("--test", "run_test", is_flag=True, default=False)
@click.version_option(__version__, prog_name="git-safe-scan")
def scan(paths, output_fmt, output_json, output_file, severity_threshold, ignore_globs, verbose, remediate, run_test) -> None:
    """Scan arbitrary files or directories for secrets — no git repo required.

    Examples:
        git-safe-scan ./config-backup/
        git-safe-scan settings.py .env --format json
        git-safe-scan /tmp/export/ --severity P1 --output report.sarif --format sarif
    """
    if run_test:
        sys.exit(_run_tests())

    from git_safe_publish.config import Config, DEFAULTS
    import fnmatch

    config = Config({**DEFAULTS, "severity_threshold": severity_threshold,
                     "ignore_paths": list(ignore_globs)})
    fmt = "json" if output_json else output_fmt

    if fmt == "table":
        print_header("git-safe-scan")

    result = ScanResult()

    _BINARY_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".pdf", ".zip", ".gz", ".tar", ".whl", ".egg",
        ".pyc", ".pyd", ".so", ".dylib", ".dll", ".exe",
        ".db", ".sqlite", ".sqlite3",
    }

    all_files: list[Path] = []
    for raw_path in paths:
        p = Path(raw_path)
        if p.is_file():
            all_files.append(p)
        elif p.is_dir():
            for child in p.rglob("*"):
                if child.is_file():
                    all_files.append(child)

    scanned = 0
    for file_path in all_files:
        rel = str(file_path)
        if config.is_path_ignored(rel):
            continue
        if any(fnmatch.fnmatch(file_path.name, g) for g in ignore_globs):
            continue
        if file_path.suffix.lower() in _BINARY_EXTS:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_result = scan_file_content(content, rel, config)
        if verbose and fmt == "table":
            count = len(file_result.findings)
            label = str(file_path)[-50:].ljust(52)
            tag = (
                "[green]✔  clean[/green]" if count == 0
                else f"[red]✖  {count} finding(s)[/red]" if any(f.severity.value in ("P0", "P1") for f in file_result.findings)
                else f"[yellow]⚠  {count} finding(s)[/yellow]"
            )
            console.print(f"  [dim]→[/dim]  {label}{tag}")
        result.merge(file_result)
        scanned += 1

    if fmt == "table":
        console.print(f"[dim]Scanned {scanned} file(s).[/dim]\n")

    output_result(result, fmt=fmt, scope=f"scan ({scanned} files)",
                  output_path=output_file, show_remediation=remediate)
    sys.exit(0 if result.is_clean else 1)
