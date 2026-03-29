"""Shared data models used across all scanners."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    P0 = "P0"  # Critical — block publish
    P1 = "P1"  # High     — strongly warn
    P2 = "P2"  # Medium   — warn
    P3 = "P3"  # Low      — note

    @property
    def label(self) -> str:
        return {
            Severity.P0: "CRITICAL",
            Severity.P1: "HIGH",
            Severity.P2: "MEDIUM",
            Severity.P3: "LOW",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.P0: "bold red",
            Severity.P1: "red",
            Severity.P2: "yellow",
            Severity.P3: "blue",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.P0: "🚨",
            Severity.P1: "⚠️ ",
            Severity.P2: "⚡",
            Severity.P3: "ℹ️ ",
        }[self]

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.P0, Severity.P1, Severity.P2, Severity.P3]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    severity: Severity
    category: str
    check_name: str
    description: str
    filename: str = ""
    line_number: int = 0
    line_content: str = ""  # redacted, shown to user
    commit_sha: str = ""
    commit_message: str = ""
    remediation: str = ""

    def is_blocker(self) -> bool:
        return self.severity == Severity.P0


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.findings

    @property
    def has_blockers(self) -> bool:
        return any(f.is_blocker() for f in self.findings)

    @property
    def blocker_count(self) -> int:
        return sum(1 for f in self.findings if f.is_blocker())

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def merge(self, other: ScanResult) -> None:
        self.findings.extend(other.findings)

    def filtered(self, min_severity: Optional[Severity] = None) -> ScanResult:
        if min_severity is None:
            return self
        return ScanResult([f for f in self.findings if f.severity <= min_severity])
