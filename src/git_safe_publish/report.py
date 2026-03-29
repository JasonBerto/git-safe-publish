"""Rich terminal output for git-safe-publish."""

from __future__ import annotations

import sys
from pathlib import Path
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


# ---------------------------------------------------------------------------
# Pattern listing
# ---------------------------------------------------------------------------

def print_patterns_table() -> None:
    """Print all built-in secret patterns in a rich table."""
    from git_safe_publish.patterns import PATTERNS
    from rich.table import Table
    from rich import box

    table = Table(
        title="Built-in Secret Patterns",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_blue",
        show_lines=False,
        expand=True,
    )
    table.add_column("Name", style="bold", min_width=28)
    table.add_column("Sev", justify="center", min_width=4)
    table.add_column("Category", min_width=20)
    table.add_column("Description")

    for p in sorted(PATTERNS, key=lambda x: (x.severity, x.category)):
        sev_style = {"P0": "bold red", "P1": "red", "P2": "yellow", "P3": "blue"}.get(p.severity, "")
        table.add_row(
            p.name,
            f"[{sev_style}]{p.severity}[/{sev_style}]",
            p.category,
            p.description,
        )
    console.print(table)
    console.print(f"\n[dim]{len(PATTERNS)} patterns total[/dim]\n")


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

def format_as_sarif(result, tool_version: str = "0.3.0") -> dict:
    """Return a SARIF 2.1.0 dict for the given ScanResult."""
    from git_safe_publish.patterns import PATTERNS

    rules = []
    seen_rule_ids: set = set()
    for finding in result.findings:
        if finding.check_name not in seen_rule_ids:
            seen_rule_ids.add(finding.check_name)
            pat = next((p for p in PATTERNS if p.name == finding.check_name), None)
            rules.append({
                "id": finding.check_name,
                "name": finding.check_name.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": pat.description if pat else finding.description},
                "help": {"text": finding.remediation or "See git-safe-publish documentation."},
                "properties": {
                    "tags": [finding.category],
                    "security-severity": {"P0": "9.0", "P1": "7.0", "P2": "5.0", "P3": "3.0"}.get(
                        finding.severity.value, "5.0"
                    ),
                },
            })

    sarif_results = []
    for finding in result.findings:
        location: dict = {"message": {"text": finding.filename or "<unknown>"}}
        if finding.filename:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.filename, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(finding.line_number, 1)},
                },
                "message": {"text": finding.filename},
            }
        sarif_results.append({
            "ruleId": finding.check_name,
            "level": {"P0": "error", "P1": "error", "P2": "warning", "P3": "note"}.get(
                finding.severity.value, "warning"
            ),
            "message": {
                "text": (
                    f"{finding.description}\n{finding.line_content}"
                    if finding.line_content else finding.description
                )
            },
            "locations": [location],
            "partialFingerprints": {
                "commitSha": finding.commit_sha,
            } if finding.commit_sha else {},
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "git-safe-publish",
                    "version": tool_version,
                    "informationUri": "https://github.com/your-org/git-safe-publish",
                    "rules": rules,
                }
            },
            "results": sarif_results,
        }],
    }


def print_sarif(result, output_path: Optional[str] = None) -> None:
    import json
    data = format_as_sarif(result)
    text = json.dumps(data, indent=2)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        console.print(f"[green]✔[/green] SARIF written to {output_path}")
    else:
        out.print(text)


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def format_as_markdown(result, scope: str = "") -> str:
    from git_safe_publish.models import Severity as Sev

    lines = ["## git-safe-publish report"]
    if scope:
        lines.append(f"*Scope: {scope}*\n")

    if result.is_clean:
        lines.append("\n✅ **No issues found.**\n")
        return "\n".join(lines)

    sev_emoji = {Sev.P0: "🚨", Sev.P1: "⚠️", Sev.P2: "⚡", Sev.P3: "ℹ️"}
    by_sev = result.by_severity

    for sev in [Sev.P0, Sev.P1, Sev.P2, Sev.P3]:
        findings = by_sev[sev]
        if not findings:
            continue
        lines.append(f"\n### {sev_emoji[sev]} {sev.label} ({len(findings)})\n")
        lines.append("| Check | File | Line | Description |")
        lines.append("|---|---|---|---|")
        for f in findings:
            loc = f"{f.filename}:{f.line_number}" if f.line_number else f.filename
            desc = f.description.replace("|", "\\|")
            lines.append(f"| `{f.check_name}` | `{loc}` | {f.line_number or ''} | {desc} |")

    total = len(result.findings)
    lines.append(f"\n---\n*{total} issue{'s' if total != 1 else ''} found by git-safe-publish*")
    return "\n".join(lines)


def print_markdown(result, scope: str = "", output_path: Optional[str] = None) -> None:
    text = format_as_markdown(result, scope)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        console.print(f"[green]✔[/green] Markdown report written to {output_path}")
    else:
        out.print(text)


# ---------------------------------------------------------------------------
# Output dispatcher
# ---------------------------------------------------------------------------

def output_result(
    result,
    fmt: str = "table",
    scope: str = "",
    output_path: Optional[str] = None,
    show_remediation: bool = False,
) -> None:
    """Dispatch output based on --format flag."""
    fmt = fmt.lower()
    if fmt == "json":
        if output_path:
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
            Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            console.print(f"[green]✔[/green] JSON report written to {output_path}")
        else:
            print_json(result)
    elif fmt == "sarif":
        print_sarif(result, output_path)
    elif fmt == "markdown":
        print_markdown(result, scope, output_path)
    else:
        print_findings(result, show_remediation=show_remediation)
        print_summary(result, scope=scope)
        if show_remediation and not result.is_clean:
            print_remediation_detail(result)

