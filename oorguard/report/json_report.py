"""JSON report exporter.

Serializes findings and package inventory to a structured JSON file with metadata,
summary counts, and grouped findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from oorguard.core.finding import Finding, Severity, count_by_severity, group_findings_by_category
from oorguard.core.packages import PackageInfo


def render_json_report(
    findings: list[Finding],
    output_path: str | Path,
    project_path: str = "",
    min_severity: Severity = Severity.INFO,
    packages: list[PackageInfo] | None = None,
) -> Path:
    """Export findings and packages to a JSON file.

    Args:
        findings: All collected findings.
        output_path: File path to write the JSON report.
        project_path: The scanned project path (for metadata).
        min_severity: Only include findings at or above this level.
        packages: List of installed packages.

    Returns:
        Path to the written JSON file.
    """
    filtered = [f for f in findings if f.severity.value <= min_severity.value]
    counts = count_by_severity(filtered)
    grouped = group_findings_by_category(filtered)

    report = {
        "meta": {
            "tool": "OorGuard",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project_path": str(project_path),
            "total_findings": len(filtered),
            "total_packages": len(packages) if packages else 0,
            "min_severity": min_severity.label,
        },
        "packages": [p.to_dict() for p in (packages or [])],
        "summary": {
            severity.label.lower(): count
            for severity, count in counts.items()
        },
        "has_critical_or_high": counts[Severity.CRITICAL] + counts[Severity.HIGH] > 0,
        "findings_by_category": {
            category: [f.to_dict() for f in cat_findings]
            for category, cat_findings in grouped.items()
        },
        "all_findings": [f.to_dict() for f in filtered],
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    return output
