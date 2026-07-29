"""Dependency Auditing checks.

Runs `composer audit` and `npm audit` as subprocesses, parses their JSON output,
and maps advisories to Finding objects. Gracefully handles missing binaries or
lock files — never crashes the scan.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


def _severity_from_composer(level: str) -> Severity:
    """Map Composer advisory severity to our Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(level.lower(), Severity.MEDIUM)


def _severity_from_npm(level: str) -> Severity:
    """Map npm audit severity to our Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(level.lower(), Severity.MEDIUM)


@register_check(
    category="Dependencies",
    name="composer_audit",
    description="Runs `composer audit` to check PHP dependencies for known vulnerabilities.",
)
def check_composer_audit(ctx: ScanContext) -> list[Finding]:
    """Run composer audit and parse results."""
    findings: list[Finding] = []
    lock_path = ctx.project_path / "composer.lock"

    if not lock_path.exists():
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="No composer.lock found — skipping PHP dependency audit",
            description="composer.lock is missing, so PHP dependencies cannot be audited.",
            recommendation="Run 'composer install' to generate a lock file, then re-scan.",
        ))
        return findings

    composer_bin = shutil.which("composer")
    if not composer_bin:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="Composer binary not found — skipping PHP dependency audit",
            description=(
                "The 'composer' command is not available in PATH. "
                "PHP dependency vulnerability scanning requires Composer."
            ),
            recommendation=(
                "Install Composer (https://getcomposer.org/download/) or run manually:\n"
                "  composer audit --format=json"
            ),
        ))
        return findings

    try:
        result = subprocess.run(
            [composer_bin, "audit", "--format=json", "--no-interaction"],
            capture_output=True,
            text=True,
            cwd=str(ctx.project_path),
            timeout=120,
        )

        # composer audit returns non-zero when advisories exist
        output = result.stdout.strip()
        if not output:
            return findings

        data = json.loads(output)
        advisories = data.get("advisories", {})

        if not advisories:
            findings.append(Finding(
                severity=Severity.INFO,
                category="Dependencies",
                title="No PHP dependency vulnerabilities found",
                description="composer audit reported no known advisories.",
                recommendation="Keep dependencies updated regularly.",
            ))
            return findings

        for package_name, package_advisories in advisories.items():
            for advisory in package_advisories:
                title = advisory.get("title", "Unknown vulnerability")
                cve = advisory.get("cve", "")
                link = advisory.get("link", "")
                affected = advisory.get("affectedVersions", "")
                severity_str = advisory.get("severity", "medium")

                desc_parts = [f"Package: {package_name}"]
                if affected:
                    desc_parts.append(f"Affected versions: {affected}")
                if cve:
                    desc_parts.append(f"CVE: {cve}")
                if link:
                    desc_parts.append(f"Advisory: {link}")

                findings.append(Finding(
                    severity=_severity_from_composer(severity_str),
                    category="Dependencies",
                    title=f"[Composer] {package_name}: {title}",
                    description="\n".join(desc_parts),
                    recommendation=f"Update '{package_name}' to a patched version: composer update {package_name}",
                    file="composer.lock",
                ))

    except subprocess.TimeoutExpired:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="Composer audit timed out",
            description="The 'composer audit' command took longer than 120 seconds.",
            recommendation="Run 'composer audit' manually to check for vulnerabilities.",
        ))
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="Composer audit output could not be parsed",
            description=f"Error: {exc}",
            recommendation="Run 'composer audit --format=json' manually.",
        ))

    return findings


@register_check(
    category="Dependencies",
    name="npm_audit",
    description="Runs `npm audit` to check JavaScript dependencies for known vulnerabilities.",
)
def check_npm_audit(ctx: ScanContext) -> list[Finding]:
    """Run npm audit and parse results."""
    findings: list[Finding] = []
    lock_path = ctx.project_path / "package-lock.json"

    if not lock_path.exists():
        # Also check for yarn.lock
        if (ctx.project_path / "yarn.lock").exists():
            findings.append(Finding(
                severity=Severity.INFO,
                category="Dependencies",
                title="yarn.lock detected — npm audit skipped",
                description=(
                    "This project uses Yarn. Run 'yarn audit' manually to "
                    "check JS dependencies."
                ),
                recommendation="Run: yarn audit --json",
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO,
                category="Dependencies",
                title="No package-lock.json found — skipping JS dependency audit",
                description="No JS lock file found.",
                recommendation="Run 'npm install' to generate a lock file, then re-scan.",
            ))
        return findings

    npm_bin = shutil.which("npm")
    if not npm_bin:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="npm binary not found — skipping JS dependency audit",
            description="The 'npm' command is not available in PATH.",
            recommendation=(
                "Install Node.js/npm or run manually:\n  npm audit --json"
            ),
        ))
        return findings

    try:
        result = subprocess.run(
            [npm_bin, "audit", "--json"],
            capture_output=True,
            text=True,
            cwd=str(ctx.project_path),
            timeout=120,
        )

        output = result.stdout.strip()
        if not output:
            return findings

        data = json.loads(output)
        vulnerabilities = data.get("vulnerabilities", {})

        if not vulnerabilities:
            findings.append(Finding(
                severity=Severity.INFO,
                category="Dependencies",
                title="No JS dependency vulnerabilities found",
                description="npm audit reported no known vulnerabilities.",
                recommendation="Keep dependencies updated regularly.",
            ))
            return findings

        for pkg_name, vuln_info in vulnerabilities.items():
            severity_str = vuln_info.get("severity", "moderate")
            via = vuln_info.get("via", [])

            # Collect advisory details from 'via' entries
            descriptions: list[str] = []
            for v in via:
                if isinstance(v, dict):
                    title = v.get("title", "")
                    url = v.get("url", "")
                    if title:
                        descriptions.append(title)
                    if url:
                        descriptions.append(f"Advisory: {url}")
                elif isinstance(v, str):
                    descriptions.append(f"Via: {v}")

            range_str = vuln_info.get("range", "")
            fix_available = vuln_info.get("fixAvailable", False)

            desc = f"Package: {pkg_name}"
            if range_str:
                desc += f"\nAffected: {range_str}"
            if descriptions:
                desc += "\n" + "\n".join(descriptions)

            rec = f"Run: npm audit fix"
            if not fix_available:
                rec = f"No automatic fix available. Run: npm audit for details and consider manual update."

            findings.append(Finding(
                severity=_severity_from_npm(severity_str),
                category="Dependencies",
                title=f"[npm] {pkg_name}: vulnerability detected",
                description=desc,
                recommendation=rec,
                file="package-lock.json",
            ))

    except subprocess.TimeoutExpired:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="npm audit timed out",
            description="The 'npm audit' command took longer than 120 seconds.",
            recommendation="Run 'npm audit' manually.",
        ))
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Dependencies",
            title="npm audit output could not be parsed",
            description=f"Error: {exc}",
            recommendation="Run 'npm audit --json' manually.",
        ))

    return findings
