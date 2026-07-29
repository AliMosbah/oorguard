"""Finding data model — the universal output unit for all security checks.

Every check module returns a list of Finding objects. Findings are sorted by
severity, grouped by category in reports, and serialized for JSON/HTML export.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.IntEnum):
    """Severity levels ordered from most to least critical.

    Using IntEnum so findings can be sorted by numeric value — lower number
    means higher severity, ensuring Critical sorts before Info.
    """

    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4

    @property
    def label(self) -> str:
        """Human-readable label for terminal/report display."""
        return self.name.capitalize()

    @property
    def color(self) -> str:
        """Rich markup color for terminal rendering."""
        return {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "dark_orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def emoji(self) -> str:
        """Emoji prefix for compact display."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Parse a severity string (case-insensitive) into a Severity enum."""
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(
                f"Unknown severity '{value}'. "
                f"Valid: {', '.join(s.name.lower() for s in cls)}"
            )


@dataclass(slots=True)
class Finding:
    """A single security finding produced by a check module.

    Attributes:
        severity: How critical this finding is.
        category: Grouping label (e.g. 'Environment', 'Inertia', 'Dependencies').
        title: Short one-line summary of the issue.
        description: Detailed explanation of why this matters.
        recommendation: Actionable fix or mitigation advice.
        file: Optional file path where the issue was found.
        line: Optional line number within the file.
    """

    severity: Severity
    category: str
    title: str
    description: str
    recommendation: str
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON export."""
        data = asdict(self)
        data["severity"] = self.severity.label
        return data

    @property
    def location(self) -> str:
        """Format file:line for display, or empty string if no location."""
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        return ""


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (critical first), then by category, then title."""
    return sorted(findings, key=lambda f: (f.severity.value, f.category, f.title))


def group_findings_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group sorted findings by their category."""
    groups: dict[str, list[Finding]] = {}
    for finding in sort_findings(findings):
        groups.setdefault(finding.category, []).append(finding)
    return groups


def count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings per severity level."""
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    return counts
