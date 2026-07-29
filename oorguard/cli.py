"""OorGuard CLI — main entry point.

Provides three modes:
1. Interactive wizard: just run `oorguard` — shows ASCII art, lets you pick
   checks and enter the project path interactively.
2. Direct scan: `oorguard scan <path> [OPTIONS]`
3. Utility commands: `oorguard list-checks`, `oorguard version`
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

import oorguard
from oorguard.core.config import load_config, OorGuardConfig
from oorguard.core.context import ScanContext
from oorguard.core.engine import ScanEngine
from oorguard.core.finding import Severity, count_by_severity
from oorguard.core.registry import get_all_checks, get_categories
from oorguard.core.packages import get_installed_packages

# Force-import checks package to trigger @register_check decorators
import oorguard.checks  # noqa: F401

from oorguard.report.terminal_report import render_terminal_report
from oorguard.report.json_report import render_json_report
from oorguard.report.html_report import render_html_report


console = Console()


# ────────────────────────────────────────────────────────
#  ASCII Art Banner
# ────────────────────────────────────────────────────────

BANNER = r"""[bold cyan]
   ___   ___  ____   ____ _   _   _    ____  ____
  / _ \ / _ \|  _ \ / ___| | | | / \  |  _ \|  _ \
 | | | | | | | |_) | |  _| | | |/ _ \ | |_) | | | |
 | |_| | |_| |  _ <| |_| | |_| / ___ \|  _ <| |_| |
  \___/ \___/|_| \_\\____|\___/_/   \_\_| \_\____/
[/bold cyan]
[dim]  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
[bold white]   🛡️  Laravel Security Scanner[/bold white]  [dim]v{version}[/dim]
[dim]  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim]
"""

MINI_BANNER = r"""[bold cyan]
  ╔═══════════════════════════════════════════╗
  ║        🛡️  OorGuard v{version}              ║
  ║     Laravel Security Scanner             ║
  ╚═══════════════════════════════════════════╝
[/bold cyan]"""


def show_banner(mini: bool = False) -> None:
    """Print the OorGuard ASCII art banner."""
    if mini:
        console.print(MINI_BANNER.format(version=oorguard.__version__))
    else:
        console.print(BANNER.format(version=oorguard.__version__))


# ────────────────────────────────────────────────────────
#  Category display config (emoji + description)
# ────────────────────────────────────────────────────────

_CATEGORY_META: dict[str, tuple[str, str]] = {
    "Environment":     ("⚙️ ", "Environment & .env configuration checks"),
    "File Exposure":   ("📂", "Exposed files & path security"),
    "Dependencies":    ("📦", "Composer & npm vulnerability audit"),
    "Laravel Core":    ("🔒", "Mass assignment, CORS, CSRF, debug tools"),
    "Code Patterns":   ("🔍", "Dangerous PHP code patterns (SQL injection, eval, etc.)"),
    "Secrets":         ("🔑", "Hardcoded secrets & API keys"),
    "Inertia":         ("⚡", "Inertia.js prop exposure & Sanctum"),
    "React/Frontend":  ("⚛️ ", "React/JS security (XSS, eval, CSP)"),
    "SSR":             ("🖥️ ", "Server-Side Rendering security"),
    "Live Exposure":   ("🌐", "Live HTTP endpoint exposure probes"),
    "Livewire":        ("🔥", "Livewire component security"),
}


# ────────────────────────────────────────────────────────
#  CLI Group
# ────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """🛡️  OorGuard — Advanced Laravel Security Scanner.

    Run without a subcommand for interactive mode, or use:

    \b
      oorguard scan <path>     Scan a Laravel project
      oorguard list-checks     Show all available checks
      oorguard version         Show version
    """
    if ctx.invoked_subcommand is None:
        # No subcommand = interactive mode
        _interactive_wizard()


# ────────────────────────────────────────────────────────
#  Interactive Wizard
# ────────────────────────────────────────────────────────

def _interactive_wizard() -> None:
    """Launch the interactive scanning wizard."""
    show_banner()

    console.print("  [bold green]Welcome to OorGuard![/bold green] Let's scan your Laravel project.\n")

    # Step 1: Select check categories
    categories = get_categories()
    if not categories:
        console.print("[red]No checks registered. Something went wrong.[/red]")
        sys.exit(2)

    console.print("  [bold]Step 1:[/bold] [cyan]Select security check categories[/cyan]\n")

    # Build category table
    table = Table(
        box=box.ROUNDED,
        border_style="dim",
        show_header=True,
        header_style="bold white",
        padding=(0, 1),
    )
    table.add_column("#", style="bold cyan", width=4, justify="center")
    table.add_column("Category", style="bold", width=20)
    table.add_column("Description", ratio=1, style="dim")
    table.add_column("Checks", width=8, justify="center")

    all_checks = get_all_checks()
    for i, cat in enumerate(categories, 1):
        emoji, desc = _CATEGORY_META.get(cat, ("📋", cat))
        check_count = len([c for c in all_checks if c.category == cat])
        table.add_row(str(i), f"{emoji} {cat}", desc, str(check_count))

    console.print(table)
    console.print()

    # Ask for selection
    console.print("  [dim]Enter category numbers separated by commas, or[/dim] [bold]'all'[/bold] [dim]for everything.[/dim]")
    selection = Prompt.ask(
        "  [bold cyan]▶ Categories[/bold cyan]",
        default="all",
        console=console,
    )

    selected_categories: set[str] = set()
    excluded_categories: set[str] = set()

    if selection.strip().lower() == "all":
        selected_categories = set(categories)
    else:
        try:
            indices = [int(s.strip()) for s in selection.split(",") if s.strip()]
            for idx in indices:
                if 1 <= idx <= len(categories):
                    selected_categories.add(categories[idx - 1])
                else:
                    console.print(f"  [yellow]⚠ Invalid number: {idx} (skipped)[/yellow]")
        except ValueError:
            console.print("  [yellow]⚠ Could not parse selection. Using all categories.[/yellow]")
            selected_categories = set(categories)

    if not selected_categories:
        selected_categories = set(categories)

    excluded_categories = set(categories) - selected_categories

    # Show selected
    selected_names = ", ".join(f"[cyan]{c}[/cyan]" for c in sorted(selected_categories))
    console.print(f"\n  ✅ Selected: {selected_names}\n")

    # Step 2: Project path
    console.print("  [bold]Step 2:[/bold] [cyan]Enter the Laravel project path[/cyan]\n")
    project_path = Prompt.ask(
        "  [bold cyan]▶ Project path[/bold cyan]",
        default=".",
        console=console,
    )

    # Validate path
    resolved = Path(project_path).resolve()
    if not resolved.is_dir():
        console.print(f"\n  [red bold]✗ Path does not exist:[/red bold] {resolved}")
        sys.exit(2)

    console.print(f"  📁 Scanning: [bold yellow]{resolved}[/bold yellow]\n")

    # Step 3: Output format
    console.print("  [bold]Step 3:[/bold] [cyan]Choose output format[/cyan]\n")

    format_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    format_table.add_column(width=4, justify="center")
    format_table.add_column()
    format_table.add_row("[bold cyan]1[/]", "📺 Terminal (rich colored output)")
    format_table.add_row("[bold cyan]2[/]", "📄 JSON (structured, for CI/CD)")
    format_table.add_row("[bold cyan]3[/]", "🌐 HTML (dark-themed report)")
    console.print(format_table)

    format_choice = Prompt.ask(
        "\n  [bold cyan]▶ Format[/bold cyan]",
        default="1",
        choices=["1", "2", "3"],
        console=console,
    )

    format_map = {"1": "terminal", "2": "json", "3": "html"}
    output_format = format_map[format_choice]

    output_path: str | None = None
    open_browser = False

    if output_format in ("json", "html"):
        ext = ".json" if output_format == "json" else ".html"
        default_name = f"oorguard-report{ext}"
        output_path = Prompt.ask(
            f"  [bold cyan]▶ Output file[/bold cyan]",
            default=default_name,
            console=console,
        )
        if output_format == "html":
            open_browser = Confirm.ask(
                "  [bold cyan]▶ Open in browser after scan?[/bold cyan]",
                default=True,
                console=console,
            )

    # Step 4: Optional live scan URL
    console.print()
    do_live = Confirm.ask(
        "  [bold cyan]▶ Run live exposure checks? (HTTP probes)[/bold cyan]",
        default=False,
        console=console,
    )

    base_url: str | None = None
    if do_live:
        base_url = Prompt.ask(
            "  [bold cyan]▶ Base URL[/bold cyan]",
            default="https://example.com",
            console=console,
        )

    # Step 5: Severity filter
    console.print()
    min_severity = Prompt.ask(
        "  [bold cyan]▶ Minimum severity[/bold cyan]",
        default="info",
        choices=["critical", "high", "medium", "low", "info"],
        console=console,
    )

    console.print()

    # ── Confirmation ──
    console.print(Panel(
        f"  📁 [bold]Path:[/bold]       {resolved}\n"
        f"  📊 [bold]Categories:[/bold] {len(selected_categories)}/{len(categories)}\n"
        f"  📺 [bold]Format:[/bold]     {output_format}\n"
        f"  🔍 [bold]Severity:[/bold]   ≥ {min_severity}\n"
        f"  🌐 [bold]Live scan:[/bold]  {'Yes → ' + (base_url or '') if do_live else 'No'}",
        title="[bold]Scan Configuration[/bold]",
        border_style="cyan",
        padding=(1, 2),
    ))

    if not Confirm.ask("\n  [bold green]▶ Start scan?[/bold green]", default=True, console=console):
        console.print("  [dim]Scan cancelled.[/dim]")
        sys.exit(0)

    console.print()

    # ── Execute Scan ──
    _execute_scan(
        path=str(resolved),
        url=base_url,
        output_format=output_format,
        output=output_path,
        open_browser=open_browser,
        min_severity=min_severity,
        exclude_categories=excluded_categories,
        config_path=None,
        verbose=False,
    )


# ────────────────────────────────────────────────────────
#  Scan Command (direct CLI)
# ────────────────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--url", type=str, default=None, help="Base URL for optional live exposure checks.")
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "html"], case_sensitive=False),
    default="terminal",
    help="Output format (default: terminal).",
)
@click.option("--output", type=click.Path(), default=None, help="File path to write JSON/HTML report.")
@click.option("--open", "open_browser", is_flag=True, help="Open HTML report in browser after generation.")
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default="info",
    help="Only show findings at or above this severity level.",
)
@click.option(
    "--exclude-category",
    multiple=True,
    help="Skip a check category (repeatable).",
)
@click.option("--no-live", is_flag=True, help="Explicitly disable all network calls.")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Path to .oorguard.yml config.")
@click.option("-v", "--verbose", is_flag=True, help="Show per-check progress detail.")
def scan(
    path: str,
    url: str | None,
    output_format: str,
    output: str | None,
    open_browser: bool,
    min_severity: str,
    exclude_category: tuple[str, ...],
    no_live: bool,
    config_path: str | None,
    verbose: bool,
) -> None:
    """Scan a Laravel project for security vulnerabilities.

    PATH is the root directory of the Laravel project to scan.
    """
    show_banner(mini=True)

    if no_live:
        url = None

    _execute_scan(
        path=path,
        url=url,
        output_format=output_format,
        output=output,
        open_browser=open_browser,
        min_severity=min_severity,
        exclude_categories=set(exclude_category),
        config_path=config_path,
        verbose=verbose,
        no_live=no_live,
    )


# ────────────────────────────────────────────────────────
#  Core scan execution (shared by interactive + direct)
# ────────────────────────────────────────────────────────

def _execute_scan(
    path: str,
    url: str | None,
    output_format: str,
    output: str | None,
    open_browser: bool,
    min_severity: str,
    exclude_categories: set[str],
    config_path: str | None,
    verbose: bool,
    no_live: bool = False,
) -> None:
    """Execute the scan engine and produce output."""
    start_time = time.monotonic()
    severity_threshold = Severity.from_string(min_severity)

    # Load config
    config = load_config(config_path=config_path, project_path=path)
    config.merge_cli_overrides(
        min_severity=min_severity,
        exclude_categories=list(exclude_categories),
    )

    if no_live:
        config.disabled_checks.add("live_exposure_scan")

    # Create context
    try:
        ctx = ScanContext(
            project_path=path,
            config=config,
            base_url=url,
            verbose=verbose,
        )
    except FileNotFoundError as exc:
        console.print(f"  [red bold]✗ Error:[/red bold] {exc}")
        sys.exit(2)

    # Count active checks
    checks = get_all_checks()
    active_checks = [
        c for c in checks
        if c.name not in config.disabled_checks
        and c.category not in config.exclude_categories
    ]

    console.print(f"  [dim]Scanning [bold]{path}[/bold] with {len(active_checks)} checks...[/dim]\n")

    # Run with progress
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Running {len(active_checks)} security checks...", total=None)

        def on_progress(check_name: str, status: str, elapsed: float) -> None:
            if verbose:
                icon = "✅" if status == "done" else "⚡" if status == "running" else "❌"
                progress.update(task, description=f"{icon} {check_name} ({status})")

        engine = ScanEngine(ctx=ctx, on_progress=on_progress)
        findings = engine.run()
        packages = get_installed_packages(ctx, fetch_latest=not no_live)

    elapsed = time.monotonic() - start_time
    console.print(f"  [dim]✅ Scan completed in {elapsed:.1f}s — {len(findings)} finding(s), {len(packages)} package(s)[/dim]\n")

    # Output
    if output_format == "terminal":
        render_terminal_report(findings, console=console, min_severity=severity_threshold, packages=packages)
    elif output_format == "json":
        out_path = output or "oorguard-report.json"
        result = render_json_report(findings, output_path=out_path, project_path=path, min_severity=severity_threshold, packages=packages)
        console.print(f"  [green]✅ JSON report written to:[/green] {result}")
    elif output_format == "html":
        out_path = output or "oorguard-report.html"
        result = render_html_report(
            findings, output_path=out_path, project_path=path,
            min_severity=severity_threshold, open_browser=open_browser, packages=packages,
        )
        console.print(f"  [green]✅ HTML report written to:[/green] {result}")
        if open_browser:
            console.print("  [dim]Opening in browser...[/dim]")

    # Also write file if --output specified with terminal format
    if output and output_format == "terminal":
        if output.endswith(".json"):
            render_json_report(findings, output_path=output, project_path=path, min_severity=severity_threshold, packages=packages)
            console.print(f"\n  [green]✅ JSON report also written to:[/green] {output}")
        elif output.endswith(".html") or output.endswith(".htm"):
            render_html_report(
                findings, output_path=output, project_path=path,
                min_severity=severity_threshold, open_browser=open_browser, packages=packages,
            )
            console.print(f"\n  [green]✅ HTML report also written to:[/green] {output}")

    # Exit code
    counts = count_by_severity(findings)
    critical_high = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    if critical_high > 0:
        sys.exit(1)
    sys.exit(0)


# ────────────────────────────────────────────────────────
#  List Checks Command
# ────────────────────────────────────────────────────────

@cli.command("list-checks")
def list_checks() -> None:
    """List all available security checks with their category and description."""
    show_banner(mini=True)

    checks = get_all_checks()
    if not checks:
        console.print("  [yellow]No checks registered.[/yellow]")
        return

    table = Table(
        title="Available Security Checks",
        box=box.ROUNDED,
        show_lines=True,
        border_style="cyan",
        title_style="bold white",
    )

    table.add_column("Category", style="cyan bold", width=18)
    table.add_column("Check Name", style="bold", width=30)
    table.add_column("Description", ratio=1)

    sorted_checks = sorted(checks, key=lambda c: (c.category, c.name))

    for check in sorted_checks:
        emoji, _ = _CATEGORY_META.get(check.category, ("📋", ""))
        desc = check.description
        if len(desc) > 120:
            desc = desc[:117] + "..."
        table.add_row(f"{emoji} {check.category}", check.name, desc)

    console.print(table)
    console.print(f"\n  [dim]Total: {len(checks)} checks across {len(get_categories())} categories[/dim]\n")


# ────────────────────────────────────────────────────────
#  Version Command
# ────────────────────────────────────────────────────────

@cli.command()
def version() -> None:
    """Show OorGuard version."""
    show_banner()


# ────────────────────────────────────────────────────────
#  Entry point
# ────────────────────────────────────────────────────────

def main() -> None:
    """Main entry point for direct script execution."""
    cli()


if __name__ == "__main__":
    main()
