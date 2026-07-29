"""File & Path Exposure checks.

Detects exposed .git directories, missing .htaccess, unsafe storage symlinks,
and Vite dev server misconfigurations that could leak data in production.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


@register_check(
    category="File Exposure",
    name="git_in_public",
    description="Detects .git directory inside public/ — full repo history downloadable over HTTP.",
)
def check_git_in_public(ctx: ScanContext) -> list[Finding]:
    """Flag .git directory exposed under public/."""
    findings: list[Finding] = []
    git_path = ctx.project_path / "public" / ".git"

    if git_path.exists():
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="File Exposure",
            title=".git directory exposed in public/",
            description=(
                "The .git directory is accessible under public/. An attacker "
                "can download the entire repository history — including source "
                "code, secrets in past commits, and internal documentation — "
                "via HTTP requests to /.git/."
            ),
            recommendation=(
                "Remove the .git directory from public/. If using Apache, add "
                "a rule to deny access: RedirectMatch 404 /\\.git. For Nginx: "
                "location ~ /\\.git { deny all; }"
            ),
            file="public/.git",
        ))

    return findings


@register_check(
    category="File Exposure",
    name="missing_htaccess",
    description="Checks for missing public/.htaccess (breaks routing on Apache/shared hosting).",
)
def check_htaccess(ctx: ScanContext) -> list[Finding]:
    """Detect missing .htaccess in public/."""
    findings: list[Finding] = []
    htaccess_path = ctx.project_path / "public" / ".htaccess"

    if not htaccess_path.exists():
        findings.append(Finding(
            severity=Severity.LOW,
            category="File Exposure",
            title="public/.htaccess is missing",
            description=(
                "The default .htaccess file is missing from public/. On Apache "
                "or shared hosting, this file is required for proper URL routing "
                "and security headers. Without it, all requests may go to "
                "index.php without proper rewriting."
            ),
            recommendation=(
                "Restore the default Laravel .htaccess file. If you're using Nginx, "
                "this is expected — but ensure your Nginx config handles rewrites."
            ),
            file="public/.htaccess",
        ))

    return findings


@register_check(
    category="File Exposure",
    name="storage_symlink",
    description="Checks public/storage symlink target for safety.",
)
def check_storage_symlink(ctx: ScanContext) -> list[Finding]:
    """Detect public/storage symlink pointing outside expected path."""
    findings: list[Finding] = []
    storage_link = ctx.project_path / "public" / "storage"

    if storage_link.is_symlink():
        target = os.readlink(storage_link)
        resolved = Path(target) if Path(target).is_absolute() else (storage_link.parent / target).resolve()

        # Expected target: storage/app/public (relative to project root)
        expected = ctx.project_path / "storage" / "app" / "public"

        if resolved != expected and not str(resolved).startswith(str(ctx.project_path / "storage")):
            findings.append(Finding(
                severity=Severity.HIGH,
                category="File Exposure",
                title="public/storage symlink points to unexpected target",
                description=(
                    f"The public/storage symlink resolves to '{resolved}', which "
                    f"is outside the expected storage/app/public directory. This "
                    "could expose sensitive files (logs, framework data) over HTTP."
                ),
                recommendation=(
                    "Re-create the symlink: php artisan storage:link. "
                    "Ensure it points to storage/app/public."
                ),
                file="public/storage",
            ))
    elif storage_link.exists() and not storage_link.is_symlink():
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="File Exposure",
            title="public/storage is a real directory, not a symlink",
            description=(
                "public/storage exists as a physical directory rather than a "
                "symlink to storage/app/public. Uploaded files may not be "
                "served correctly, and cleanup becomes harder."
            ),
            recommendation=(
                "Remove the directory and recreate as a symlink: "
                "php artisan storage:link"
            ),
            file="public/storage",
        ))

    return findings


@register_check(
    category="File Exposure",
    name="vite_dev_server_exposure",
    description="Detects Vite dev server configured to bind 0.0.0.0 in production config.",
)
def check_vite_dev_exposure(ctx: ScanContext) -> list[Finding]:
    """Flag Vite dev server bound to 0.0.0.0 (network-accessible)."""
    findings: list[Finding] = []
    vite_config_path = ctx.project_path / "vite.config.js"
    vite_config_ts_path = ctx.project_path / "vite.config.ts"

    config_path = None
    if vite_config_path.exists():
        config_path = vite_config_path
    elif vite_config_ts_path.exists():
        config_path = vite_config_ts_path

    if config_path is None:
        return findings

    content = ctx.read_file(config_path)
    if content is None:
        return findings

    # Look for server.host: '0.0.0.0' or server: { host: '0.0.0.0' }
    host_patterns = [
        re.compile(r"""host\s*:\s*['"]0\.0\.0\.0['"]"""),
        re.compile(r"""host\s*:\s*true"""),
    ]

    for pattern in host_patterns:
        match = pattern.search(content)
        if match:
            # Find the line number
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="File Exposure",
                title="Vite dev server configured to bind 0.0.0.0",
                description=(
                    "The Vite config sets server.host to '0.0.0.0' or true, "
                    "making the dev server accessible to any device on the "
                    "network. If the dev server accidentally runs in production "
                    "or on a public server, internal dev assets and HMR are exposed."
                ),
                recommendation=(
                    "Bind to localhost for development: server.host: 'localhost'. "
                    "If network access is needed for testing, use a conditional: "
                    "host: process.env.VITE_HOST || 'localhost'."
                ),
                file=ctx.relative_path(config_path),
                line=line_num,
            ))
            break

    return findings
