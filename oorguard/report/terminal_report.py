"""Rich terminal report renderer.

Renders findings as a polished, color-coded terminal report using the Rich
library — with severity badges, package inventory table, category grouping, and summary panels.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from oorguard.core.finding import (
    Finding,
    Severity,
    group_findings_by_category,
    count_by_severity,
)
from oorguard.core.packages import PackageInfo


def render_terminal_report(
    findings: list[Finding],
    console: Console | None = None,
    min_severity: Severity = Severity.INFO,
    packages: list[PackageInfo] | None = None,
) -> None:
    """Render findings to the terminal with Rich formatting.

    Args:
        findings: All collected findings (already sorted).
        console: Rich Console instance (created if not provided).
        min_severity: Only show findings at or above this severity.
        packages: Optional list of installed packages to render at top of report.
    """
    if console is None:
        console = Console()

    # Filter by minimum severity
    filtered = [f for f in findings if f.severity.value <= min_severity.value]

    console.print()

    # --- Header ---
    header = Text()
    header.append("🛡️  ", style="bold")
    header.append("OorGuard", style="bold cyan")
    header.append(" — Laravel Security Scanner", style="dim")

    console.print(Panel(header, border_style="cyan", padding=(0, 2)))

    # --- Package Inventory Table (First item in report) ---
    if packages:
        _render_packages(console, packages)

    if not filtered:
        console.print(
            Panel(
                "[green bold]✅ No security findings at the selected severity level.[/]",
                border_style="green",
            )
        )
        return

    # --- Summary Panel ---
    counts = count_by_severity(filtered)
    _render_summary(console, counts, len(filtered))

    # --- Findings by Category ---
    grouped = group_findings_by_category(filtered)
    for category, cat_findings in grouped.items():
        _render_category(console, category, cat_findings)

    # --- Footer ---
    total_critical_high = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    if total_critical_high > 0:
        console.print(
            Panel(
                f"[red bold]⚠  {total_critical_high} Critical/High issue(s) found. "
                f"Exit code will be non-zero.[/]",
                border_style="red",
            )
        )
    else:
        console.print(
            Panel(
                "[green]✅ No Critical or High severity issues. Exit code: 0[/]",
                border_style="green",
            )
        )

    console.print()


def _render_packages(console: Console, packages: list[PackageInfo]) -> None:
    """Render table of installed packages and available versions."""
    table = Table(
        title="📦 Installed Packages & Available Versions",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold white",
        border_style="cyan",
        padding=(0, 1),
        expand=True,
    )

    table.add_column("Package", style="bold white", ratio=2)
    table.add_column("Type", style="dim", width=16)
    table.add_column("Installed", style="cyan", width=12)
    table.add_column("Required", style="dim", width=12)
    table.add_column("Latest Available", width=16)
    table.add_column("Status", width=14, justify="center")

    for pkg in packages:
        status_text = (
            Text(" Outdated ", style="bold black on yellow")
            if pkg.status == "Outdated"
            else Text(" Up-to-date ", style="bold black on green")
        )
        latest_style = "yellow bold" if pkg.status == "Outdated" else "green"
        latest_display = pkg.latest_version or pkg.installed_version or "—"

        table.add_row(
            pkg.name,
            pkg.type,
            pkg.installed_version or "—",
            pkg.required_version or "—",
            Text(latest_display, style=latest_style),
            status_text,
        )

    console.print(table)
    console.print()


def _render_summary(console: Console, counts: dict[Severity, int], total: int) -> None:
    """Render the summary panel with severity counts."""
    parts: list[str] = []

    for severity in Severity:
        count = counts[severity]
        if count > 0:
            parts.append(f"[{severity.color}]{severity.emoji} {severity.label}: {count}[/]")
        else:
            parts.append(f"[dim]{severity.emoji} {severity.label}: 0[/]")

    summary_text = "   ".join(parts)
    summary_text += f"\n\n[bold]Total findings: {total}[/]"

    console.print(Panel(
        summary_text,
        title="[bold]Scan Summary[/]",
        border_style="blue",
        padding=(1, 2),
    ))


def _render_category(console: Console, category: str, findings: list[Finding]) -> None:
    """Render a category section with its findings in a table."""
    table = Table(
        title=f"📂 {category}",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold white",
        border_style="dim",
        padding=(0, 1),
        expand=True,
    )

    table.add_column("Severity", width=10, justify="center", no_wrap=True)
    table.add_column("Title", ratio=2)
    table.add_column("Location", ratio=1, style="dim")
    table.add_column("Details", ratio=3)
    table.add_column("Recommendation", ratio=3, style="green")

    for finding in findings:
        severity_badge = Text(
            f" {finding.severity.label} ",
            style=f"{finding.severity.color} reverse",
        )

        location = finding.location or "—"

        desc = finding.description
        if len(desc) > 200:
            desc = desc[:197] + "..."

        rec = finding.recommendation
        if len(rec) > 200:
            rec = rec[:197] + "..."

        table.add_row(
            severity_badge,
            Text(finding.title, style="bold"),
            location,
            desc,
            rec,
        )

    console.print(table)
    console.print()
