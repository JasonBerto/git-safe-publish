"""Rich terminal output for git-safe-publish."""

from __future__ import annotations

import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from git_safe_publish.models import Finding, ScanResult, Severity

console = Console(stderr=True)
out = Console()  # stdout for --json / piped output


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_SEV_STYLE: dict[Severity, str] = {
    Severity.P0: "bold red",
    Severity.P1: "red",
    Severity.P2: "yellow",
    Severity.P3: "blue",
}

_SEV_BADGE: dict[Severity, str] = {
    Severity.P0: "[bold red] CRITICAL [/bold red]",
    Severity.P1: "[red]   HIGH    [/red]",
    Severity.P2: "[yellow]  MEDIUM  [/yellow]",
    Severity.P3: "[blue]   LOW    [/blue]",
}


# ---------------------------------------------------------------------------
# Header / footer
# ---------------------------------------------------------------------------

def print_header(title: str = "git-safe-publish") -> None:
    console.print()
    console.print(Panel(
        f"[bold white]{title}[/bold white]  [dim]— scanning for secrets & safety issues[/dim]",
        border_style="bright_blue",
        padding=(0, 2),
    ))
    console.print()


def print_clean(scope: str = "scan") -> None:
    console.print(
        Panel(
            f"[bold green]✔  No issues found[/bold green]  [dim]({scope})[/dim]",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print()


def print_summary(result: ScanResult, scope: str = "scan") -> None:
    """Print a one-line summary of findings by severity."""
    if result.is_clean:
        print_clean(scope)
        return

    by_sev = result.by_severity
    parts = []
    for sev in [Severity.P0, Severity.P1, Severity.P2, Severity.P3]:
        count = len(by_sev[sev])
        if count:
            style = _SEV_STYLE[sev]
            parts.append(f"[{style}]{count} {sev.label}[/{style}]")

    summary_text = "  ".join(parts)
    total = len(result.findings)
    console.print(
        Panel(
            f"[bold red]✖  {total} issue{'s' if total != 1 else ''} found[/bold red]   {summary_text}",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

def print_findings(result: ScanResult, show_remediation: bool = True) -> None:
    if result.is_clean:
        return

    by_sev = result.by_severity

    for sev in [Severity.P0, Severity.P1, Severity.P2, Severity.P3]:
        findings = by_sev[sev]
        if not findings:
            continue

        table = Table(
            box=box.ROUNDED,
            border_style=_SEV_STYLE[sev],
            header_style=f"bold {_SEV_STYLE[sev]}",
            show_lines=True,
            expand=True,
        )
        table.add_column("Check", style="bold", no_wrap=True, min_width=24)
        table.add_column("File / Location", style="dim", min_width=20)
        table.add_column("Details", ratio=2)

        for finding in findings:
            location = finding.filename
            if finding.line_number:
                location += f":{finding.line_number}"
            if finding.commit_sha:
                location += f"\n[dim]commit {finding.commit_sha[:8]}[/dim]"

            details = finding.description
            if finding.line_content:
                details += f"\n[dim]{finding.line_content[:120]}[/dim]"
            if show_remediation and finding.remediation:
                details += f"\n[green dim]→ {finding.remediation.splitlines()[0]}[/green dim]"

            table.add_row(finding.check_name, location, details)

        console.print(
            Panel(
                table,
                title=f"{_SEV_BADGE[sev]}  {sev.label} ({len(findings)})",
                border_style=_SEV_STYLE[sev],
                padding=(0, 1),
            )
        )
        console.print()


def print_remediation_detail(result: ScanResult) -> None:
    """Print full remediation steps for all findings."""
    if result.is_clean:
        return

    console.print("[bold]Remediation steps:[/bold]")
    console.print()
    seen = set()
    for finding in result.findings:
        key = (finding.check_name, finding.remediation)
        if key in seen or not finding.remediation:
            continue
        seen.add(key)
        console.print(f"  [bold]{finding.check_name}[/bold]")
        for line in finding.remediation.splitlines():
            console.print(f"    {line}")
        console.print()


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

def print_progress(current: int, total: int, sha: str) -> None:
    console.print(
        f"  [dim]Scanning commit {current}/{total}  {sha[:8]}…[/dim]",
        end="\r",
    )


def print_progress_done(total: int) -> None:
    console.print(f"  [dim]Scanned {total} commits.{' ' * 30}[/dim]")


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def print_json(result: ScanResult) -> None:
    import json
    data = {
        "clean": result.is_clean,
        "has_blockers": result.has_blockers,
        "total": len(result.findings),
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "check_name": f.check_name,
                "description": f.description,
                "filename": f.filename,
                "line_number": f.line_number,
                "line_content": f.line_content,
                "commit_sha": f.commit_sha,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    out.print_json(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Interactive confirmation prompt
# ---------------------------------------------------------------------------

def confirm(message: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(message + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
    if not answer:
        return default
    return answer in ("y", "yes")
