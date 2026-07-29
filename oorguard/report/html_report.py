"""HTML report exporter.

Generates a static HTML report using Jinja2 templates. The report can be
opened in the default browser via webbrowser.open().
"""

from __future__ import annotations

import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from oorguard.core.finding import Finding, Severity, count_by_severity, group_findings_by_category
from oorguard.core.packages import PackageInfo


def render_html_report(
    findings: list[Finding],
    output_path: str | Path,
    project_path: str = "",
    min_severity: Severity = Severity.INFO,
    open_browser: bool = False,
    packages: list[PackageInfo] | None = None,
) -> Path:
    """Export findings to a styled HTML report.

    Args:
        findings: All collected findings.
        output_path: File path to write the HTML report.
        project_path: The scanned project path (for header).
        min_severity: Only include findings at or above this level.
        open_browser: Whether to open the report in the default browser.
        packages: Optional list of installed packages.

    Returns:
        Path to the written HTML file.
    """
    filtered = [f for f in findings if f.severity.value <= min_severity.value]
    counts = count_by_severity(filtered)
    grouped = group_findings_by_category(filtered)
    pkg_dicts = [p.to_dict() for p in (packages or [])]

    # Locate templates directory
    templates_dir = Path(__file__).parent.parent.parent / "templates"
    if not templates_dir.exists():
        # Fallback: render inline if template dir not found
        return _render_inline_html(filtered, counts, grouped, output_path, project_path, open_browser, pkg_dicts)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.jinja")

    html = template.render(
        tool_name="OorGuard",
        version="1.0.0",
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        project_path=str(project_path),
        total_findings=len(filtered),
        counts={s.label.lower(): c for s, c in counts.items()},
        has_critical_or_high=counts[Severity.CRITICAL] + counts[Severity.HIGH] > 0,
        grouped_findings={
            cat: [f.to_dict() for f in cat_findings]
            for cat, cat_findings in grouped.items()
        },
        severities=["Critical", "High", "Medium", "Low", "Info"],
        packages=pkg_dicts,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    if open_browser:
        webbrowser.open(f"file://{output.resolve()}")

    return output


def _render_inline_html(
    findings: list[Finding],
    counts: dict[Severity, int],
    grouped: dict[str, list[Finding]],
    output_path: str | Path,
    project_path: str,
    open_browser: bool,
    packages: list[dict],
) -> Path:
    """Fallback: render HTML inline without Jinja2 template."""
    severity_colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6",
        "Info": "#6b7280",
    }

    packages_html = ""
    if packages:
        packages_html = f"""
        <div class="category">
            <h2>📦 Installed Packages & Available Versions <span class="cat-count">{len(packages)}</span></h2>
            <div style="overflow-x:auto;">
                <table style="width:100%;border-collapse:collapse;background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:2rem;">
                    <thead>
                        <tr style="background:rgba(255,255,255,0.03);color:#f1f5f9;text-align:left;">
                            <th style="padding:0.75rem 1rem;">Package</th>
                            <th style="padding:0.75rem 1rem;">Type</th>
                            <th style="padding:0.75rem 1rem;">Installed</th>
                            <th style="padding:0.75rem 1rem;">Required</th>
                            <th style="padding:0.75rem 1rem;">Latest Available</th>
                            <th style="padding:0.75rem 1rem;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for p in packages:
            status_badge = (
                '<span class="badge" style="background:#f97316;color:#000;">Outdated</span>'
                if p.get("status") == "Outdated"
                else '<span class="badge" style="background:#4ade80;color:#000;">Up-to-date</span>'
            )
            packages_html += f"""
                        <tr style="border-bottom:1px solid #334155;">
                            <td style="padding:0.75rem 1rem;font-weight:600;">{p.get('name')}</td>
                            <td style="padding:0.75rem 1rem;color:#94a3b8;">{p.get('type')}</td>
                            <td style="padding:0.75rem 1rem;"><code style="color:#38bdf8;">{p.get('installed_version') or '—'}</code></td>
                            <td style="padding:0.75rem 1rem;"><code style="color:#94a3b8;">{p.get('required_version') or '—'}</code></td>
                            <td style="padding:0.75rem 1rem;"><code style="color:#38bdf8;">{p.get('latest_version') or p.get('installed_version') or '—'}</code></td>
                            <td style="padding:0.75rem 1rem;">{status_badge}</td>
                        </tr>
            """
        packages_html += """
                    </tbody>
                </table>
            </div>
        </div>
        """

    findings_html = ""
    for category, cat_findings in grouped.items():
        findings_html += f'<div class="category"><h2>{category}</h2>'
        for f in cat_findings:
            fd = f.to_dict()
            color = severity_colors.get(fd["severity"], "#6b7280")
            location = f.location or ""
            loc_html = f'<span class="location">{location}</span>' if location else ""

            findings_html += f'''
            <div class="finding">
                <div class="finding-header">
                    <span class="badge" style="background:{color}">{fd["severity"]}</span>
                    <span class="title">{fd["title"]}</span>
                    {loc_html}
                </div>
                <p class="desc">{fd["description"]}</p>
                <p class="rec">💡 {fd["recommendation"]}</p>
            </div>'''
        findings_html += '</div>'

    summary_html = ""
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = counts.get(Severity.from_string(sev), 0)
        color = severity_colors[sev]
        summary_html += f'<span class="summary-item" style="border-color:{color}"><strong style="color:{color}">{count}</strong> {sev}</span>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OorGuard Security Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:2rem}}
.container{{max-width:1100px;margin:0 auto}}
header{{text-align:center;margin-bottom:2rem;padding:2rem;background:linear-gradient(135deg,#1e293b,#334155);border-radius:12px;border:1px solid #475569}}
header h1{{font-size:2rem;color:#38bdf8}} header .meta{{color:#94a3b8;font-size:0.85rem;margin-top:0.5rem}}
.summary{{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin-bottom:2rem}}
.summary-item{{padding:0.75rem 1.5rem;background:#1e293b;border-radius:8px;border-left:4px solid;font-size:0.95rem}}
.category h2{{color:#38bdf8;margin:1.5rem 0 0.75rem;padding-bottom:0.5rem;border-bottom:1px solid #334155}}
.finding{{background:#1e293b;border-radius:8px;padding:1rem 1.25rem;margin-bottom:0.75rem;border:1px solid #334155}}
.finding-header{{display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;flex-wrap:wrap}}
.badge{{padding:0.15rem 0.6rem;border-radius:4px;font-size:0.75rem;font-weight:700;color:#fff;text-transform:uppercase}}
.title{{font-weight:600;color:#f1f5f9}}
.location{{color:#94a3b8;font-size:0.8rem;font-family:monospace}}
.desc{{color:#cbd5e1;font-size:0.9rem;margin-bottom:0.5rem;white-space:pre-line}}
.rec{{color:#4ade80;font-size:0.85rem;white-space:pre-line}}
footer{{text-align:center;margin-top:2rem;padding:1rem;color:#64748b;font-size:0.8rem}}
</style>
</head>
<body>
<div class="container">
<header>
<h1>🛡️ OorGuard Security Report</h1>
<p class="meta">Project: {project_path} | Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")} | Total: {len(findings)} findings</p>
</header>
{packages_html}
<div class="summary">{summary_html}</div>
{findings_html}
<footer>Generated by OorGuard v1.0.0 — Laravel Security Scanner</footer>
</div>
</body>
</html>"""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    if open_browser:
        webbrowser.open(f"file://{output.resolve()}")

    return output
