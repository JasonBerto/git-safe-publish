"""CLI entry points for git-safe-publish.

Four commands:
  git-safe-check    — scan staged/tracked content, report issues, exit 0/1/2
  git-safe-search   — deep-scan full commit history
  git-safe-push     — drop-in for `git push` with pre-push safety checks
  git-safe-publish  — interactive full check + push flow
"""

from __future__ import annotations

import subprocess
import sys
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
    print_findings,
    print_header,
    print_json,
    print_progress,
    print_progress_done,
    print_remediation_detail,
    print_summary,
)
from git_safe_publish.scanner.files import scan_staged_files, scan_tracked_files
from git_safe_publish.scanner.gitignore import scan_gitignore, suggest_gitignore_additions
from git_safe_publish.scanner.history import scan_history
from git_safe_publish.scanner.identity import scan_identity
from git_safe_publish.scanner.remote import scan_remote
from git_safe_publish.scanner.secrets import scan_diff


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _find_tests_dir() -> Optional[Path]:
    """Locate the tests/ directory.

    Priority:
      1. Two levels above this file (works in editable / source installs).
      2. tests/ at the root of the current git repository.
    """
    # src/git_safe_publish/cli.py → ../../tests
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
    """Run the test suite via pytest and return its exit code."""
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
    """Return exit code: 0 = clean, 1 = issues found (and blocking), 2 = tool error."""
    if result.is_clean:
        return 0
    threshold = {"P0": Severity.P0, "P1": Severity.P1, "P2": Severity.P2, "P3": Severity.P3}.get(
        config.severity_threshold, Severity.P0
    )
    if any(f.severity <= threshold for f in result.findings):
        return 1
    return 0


def _run_full_check(
    repo: Path,
    config,
    staged_only: bool = False,
    check_remote_flag: bool = True,
    target_remote: str = "origin",
    target_branch: Optional[str] = None,
    force: bool = False,
) -> ScanResult:
    """Run all enabled checks and return a merged ScanResult."""
    result = ScanResult()

    # 1. Secret scan on staged diff
    diff = get_staged_diff(repo)
    if diff:
        result.merge(scan_diff(diff, config))

    # 2. Sensitive file detection
    staged_files = get_staged_files(repo)
    if staged_files:
        result.merge(scan_staged_files(staged_files, config))

    if not staged_only:
        tracked = get_tracked_files(repo)
        result.merge(scan_tracked_files(tracked, config))

    # 3. .gitignore audit
    if config.check_gitignore:
        result.merge(scan_gitignore(repo, config))

    # 4. Identity check
    if config.check_identity:
        result.merge(scan_identity(repo, config))

    # 5. Remote / branch safety
    if check_remote_flag and config.check_remote and get_remotes(repo):
        result.merge(scan_remote(repo, config, target_remote, target_branch, force))

    return result


# ---------------------------------------------------------------------------
# git-safe-check
# ---------------------------------------------------------------------------

@click.command("git-safe-check")
@click.option("--staged", is_flag=True, default=False, help="Check staged changes only (skip tracked file scan).")
@click.option("--remote", "target_remote", default="origin", show_default=True, help="Remote to validate against.")
@click.option("--branch", "target_branch", default=None, help="Branch to validate (default: current branch).")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output results as JSON.")
@click.option("--no-remote", is_flag=True, default=False, help="Skip remote / branch checks.")
@click.option("--remediate", is_flag=True, default=False, help="Show full remediation steps.")
@click.option("--init-config", is_flag=True, default=False, help="Write a default .git-safe-publish.yml and exit.")
@click.option("--test", "run_test", is_flag=True, default=False, help="Run the test suite and exit.")
@click.version_option(__version__, prog_name="git-safe-check")
def check(
    staged: bool,
    target_remote: str,
    target_branch: Optional[str],
    output_json: bool,
    no_remote: bool,
    remediate: bool,
    init_config: bool,
    run_test: bool,
) -> None:
    """Scan staged and tracked content for secrets and safety issues.

    Exits 0 if clean, 1 if issues found, 2 on error.
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    if init_config:
        cfg_path = repo / ".git-safe-publish.yml"
        write_default_config(cfg_path)
        console.print(f"[green]✔[/green] Config written to {cfg_path}")
        sys.exit(0)

    if not output_json:
        print_header("git-safe-check")

    result = _run_full_check(
        repo, config,
        staged_only=staged,
        check_remote_flag=not no_remote,
        target_remote=target_remote,
        target_branch=target_branch,
    )

    if output_json:
        print_json(result)
    else:
        print_findings(result)
        print_summary(result, scope="check")
        if remediate and not result.is_clean:
            print_remediation_detail(result)

    sys.exit(_exit_code(result, config))


# ---------------------------------------------------------------------------
# git-safe-commit
# ---------------------------------------------------------------------------

def _extract_commit_message(git_args: Tuple[str, ...]) -> Optional[str]:
    """Extract the -m / --message value from raw git commit args, if present."""
    args = list(git_args)
    for flag in ("-m", "--message"):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                return args[idx + 1]
        # Handle -m"value" or --message=value forms
        prefix = flag + ("=" if flag.startswith("--") else "")
        for arg in args:
            if arg.startswith(prefix) and len(arg) > len(prefix):
                return arg[len(prefix):]
    return None


@click.command(
    "git-safe-commit",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("git_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--skip-checks", is_flag=True, default=False, help="Skip safety checks and commit directly.")
@click.option("--test", "run_test", is_flag=True, default=False, help="Run the test suite and exit.")
@click.version_option(__version__, prog_name="git-safe-commit")
@click.pass_context
def commit(
    ctx: click.Context,
    git_args: Tuple[str, ...],
    skip_checks: bool,
    run_test: bool,
) -> None:
    """Drop-in replacement for `git commit` with pre-commit safety checks.

    Scans staged changes for secrets, sensitive file types, and identity
    issues before committing. Also scans the commit message (-m) for secrets.

    All arguments are passed directly to `git commit`.

    Examples:
        git-safe-commit -m "feat: add login page"
        git-safe-commit --amend --no-edit
        git-safe-commit -m "wip" --allow-empty
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    if not skip_checks:
        print_header("git-safe-commit")

        result = ScanResult()

        # 1. Scan staged diff for secrets
        diff = get_staged_diff(repo)
        if diff:
            result.merge(scan_diff(diff, config))

        # 2. Scan staged file types
        staged_files = get_staged_files(repo)
        if staged_files:
            result.merge(scan_staged_files(staged_files, config))

        # 3. Scan the commit message for embedded secrets
        message = _extract_commit_message(git_args)
        if message:
            from git_safe_publish.scanner.secrets import scan_commit_message
            msg_result = scan_commit_message(message, commit_sha="<pending>", config=config)
            if not msg_result.is_clean:
                for f in msg_result.findings:
                    f.description = f"[commit message] {f.description}"
            result.merge(msg_result)

        # 4. Identity check
        if config.check_identity:
            result.merge(scan_identity(repo, config))

        # 5. .gitignore audit (P2 — inform but don't block commits)
        if config.check_gitignore:
            result.merge(scan_gitignore(repo, config))

        print_findings(result)
        print_summary(result, scope="pre-commit check")

        if result.has_blockers and config.block_on_secrets:
            console.print("[bold red]✖  Commit blocked — resolve critical issues first.[/bold red]\n")
            sys.exit(1)

        if not result.is_clean:
            if not confirm("Issues found. Commit anyway?", default=False):
                console.print("[yellow]Commit cancelled.[/yellow]")
                sys.exit(1)

    # Execute the actual git commit
    cmd = ["git", "commit", *git_args]
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    proc = subprocess.run(cmd, cwd=repo)
    sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# git-safe-search
# ---------------------------------------------------------------------------

@click.command("git-safe-search")
@click.option("--branch", default="--all", show_default=True, help='Branch to scan ("--all" for all refs).')
@click.option("--limit", default=None, type=int, help="Limit scan to the N most recent commits.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output results as JSON.")
@click.option("--remediate", is_flag=True, default=False, help="Show full remediation steps.")
@click.option("--quiet", is_flag=True, default=False, help="Suppress progress output.")
@click.option("--test", "run_test", is_flag=True, default=False, help="Run the test suite and exit.")
@click.version_option(__version__, prog_name="git-safe-search")
def search(
    branch: str,
    limit: Optional[int],
    output_json: bool,
    remediate: bool,
    quiet: bool,
    run_test: bool,
) -> None:
    """Deep-scan full commit history for secrets and sensitive data.

    Scans every commit's diff and message for secret patterns.
    Exits 0 if clean, 1 if issues found, 2 on error.
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    if not has_commits(repo):
        console.print("[yellow]No commits yet — nothing to scan.[/yellow]")
        sys.exit(0)

    if not output_json:
        print_header("git-safe-search")
        scope = f"branch: {branch}" + (f", limit: {limit}" if limit else "")
        console.print(f"[dim]Scanning history ({scope})…[/dim]\n")

    def _progress(current: int, total: int, sha: str) -> None:
        if not quiet and not output_json:
            print_progress(current, total, sha)

    result = scan_history(repo, config, branch=branch, limit=limit, progress_callback=_progress)

    if not quiet and not output_json:
        from git_safe_publish.git import get_all_commits
        total = len(get_all_commits(repo, branch=branch))
        scanned = min(limit, total) if limit else total
        print_progress_done(scanned)
        console.print()

    if output_json:
        print_json(result)
    else:
        print_findings(result)
        print_summary(result, scope="history scan")
        if remediate and not result.is_clean:
            print_remediation_detail(result)

    sys.exit(_exit_code(result, config))


# ---------------------------------------------------------------------------
# git-safe-push
# ---------------------------------------------------------------------------

@click.command(
    "git-safe-push",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("git_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--json", "output_json", is_flag=True, default=False, help="Output check results as JSON.")
@click.option("--skip-checks", is_flag=True, default=False, help="Skip safety checks and push directly.")
@click.option("--test", "run_test", is_flag=True, default=False, help="Run the test suite and exit.")
@click.version_option(__version__, prog_name="git-safe-push")
@click.pass_context
def push(ctx: click.Context, git_args: Tuple[str, ...], output_json: bool, skip_checks: bool, run_test: bool) -> None:
    """Drop-in replacement for `git push` with pre-push safety checks.

    All arguments after the options are passed directly to `git push`.

    Examples:
        git-safe-push
        git-safe-push origin main
        git-safe-push --force-with-lease origin feature/my-branch
    """
    if run_test:
        sys.exit(_run_tests())
    repo = _get_repo()
    config = _load(repo)

    force = any(a in ("--force", "-f", "--force-with-lease") for a in git_args)
    target_remote = next((a for a in git_args if not a.startswith("-")), "origin")
    target_branch = next(
        (a for a in git_args if not a.startswith("-") and a != target_remote),
        None,
    )

    if not skip_checks:
        if not output_json:
            print_header("git-safe-push")

        result = _run_full_check(
            repo, config,
            staged_only=True,
            check_remote_flag=True,
            target_remote=target_remote,
            target_branch=target_branch,
            force=force,
        )

        if output_json:
            print_json(result)
            sys.exit(_exit_code(result, config))

        print_findings(result)
        print_summary(result, scope="pre-push check")

        if result.has_blockers and config.block_on_secrets:
            console.print("[bold red]✖  Push blocked — critical issues must be resolved first.[/bold red]")
            console.print()
            sys.exit(1)

        if not result.is_clean:
            if not confirm("Issues found. Push anyway?", default=False):
                console.print("[yellow]Push cancelled.[/yellow]")
                sys.exit(1)

    # Execute the actual git push
    cmd = ["git", "push", *git_args]
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    proc = subprocess.run(cmd, cwd=repo)
    sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# git-safe-publish  (interactive full flow)
# ---------------------------------------------------------------------------

@click.command("git-safe-publish")
@click.option("--remote", "target_remote", default="origin", show_default=True)
@click.option("--branch", "target_branch", default=None, help="Target branch (default: current branch).")
@click.option("--json", "output_json", is_flag=True, default=False)
@click.option("--remediate", is_flag=True, default=False, help="Show full remediation steps.")
@click.option("--dry-run", is_flag=True, default=False, help="Run checks but do not push.")
@click.option("--force", is_flag=True, default=False, help="Allow force push after confirmation.")
@click.option("--test", "run_test", is_flag=True, default=False, help="Run the test suite and exit.")
@click.version_option(__version__, prog_name="git-safe-publish")
def publish(
    target_remote: str,
    target_branch: Optional[str],
    output_json: bool,
    remediate: bool,
    dry_run: bool,
    force: bool,
    run_test: bool,
) -> None:
    """Full interactive safety check + push workflow.

    Runs all checks, presents a report, confirms author identity,
    then pushes if the user approves.
    """
    if run_test:
        sys.exit(_run_tests())

    repo = _get_repo()
    config = _load(repo)

    if not output_json:
        print_header("git-safe-publish")

    branch = target_branch or get_current_branch(repo)

    # ---- Run all checks ---------------------------------------------------
    result = _run_full_check(
        repo, config,
        staged_only=False,
        check_remote_flag=True,
        target_remote=target_remote,
        target_branch=branch,
        force=force,
    )

    if output_json:
        print_json(result)
        sys.exit(_exit_code(result, config))

    print_findings(result, show_remediation=True)
    print_summary(result, scope="full check")

    if remediate and not result.is_clean:
        print_remediation_detail(result)

    # ---- Blocker gate -----------------------------------------------------
    if result.has_blockers and config.block_on_secrets:
        console.print("[bold red]✖  Publish blocked — resolve critical issues before pushing.[/bold red]\n")
        sys.exit(1)

    # ---- Confirm identity -------------------------------------------------
    from git_safe_publish.git import get_author_email, get_author_name
    email = get_author_email(repo) or "not set"
    name = get_author_name(repo) or "not set"
    remotes_list = get_remotes(repo)
    remote_url = get_remote_url(repo, target_remote) if target_remote in remotes_list else "(none)"

    console.print(f"  Author  : [bold]{name}[/bold] <{email}>")
    console.print(f"  Remote  : [bold]{target_remote}[/bold]  {remote_url}")
    console.print(f"  Branch  : [bold]{branch}[/bold]")
    if dry_run:
        console.print(f"  Mode    : [yellow]dry-run[/yellow] (will not push)")
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

    # ---- Execute push -----------------------------------------------------
    push_args = [target_remote, branch]
    if force:
        push_args = ["--force-with-lease", *push_args]

    cmd = ["git", "push", *push_args]
    console.print(f"\n[dim]Running: {' '.join(cmd)}[/dim]")
    proc = subprocess.run(cmd, cwd=repo)
    if proc.returncode == 0:
        console.print("\n[bold green]✔  Published successfully.[/bold green]")
    sys.exit(proc.returncode)
