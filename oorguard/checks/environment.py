"""Environment & Configuration checks.

Detects insecure .env settings, exposed secrets in VITE_* variables,
missing APP_KEY, debug mode in production, and EOL Laravel versions.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check

# Laravel versions and their approximate EOL dates (YYYY-MM-DD).
# Only LTS and recent versions tracked. Used for informational flagging only.
_LARAVEL_EOL: dict[str, str] = {
    "6": "2022-09-06",
    "7": "2021-03-03",
    "8": "2023-01-24",
    "9": "2024-02-06",
    "10": "2025-02-04",
    "11": "2026-03-12",
    "12": "2027-03-10",
}

# Patterns that suggest a value is a secret rather than a generic config value
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(key|secret|token|password|pwd|credential|auth)", re.IGNORECASE),
]

# VITE_* values that look like actual secrets (not just flags or URLs)
_VITE_SECRET_INDICATORS: list[re.Pattern[str]] = [
    re.compile(r"sk[-_]", re.IGNORECASE),        # Stripe secret keys
    re.compile(r"AKIA[0-9A-Z]{16}"),              # AWS access key IDs
    re.compile(r"^[A-Za-z0-9/+=]{32,}$"),         # Generic long base64 tokens
]


@register_check(
    category="Environment",
    name="env_file_existence",
    description="Checks that .env file exists and has secure file permissions.",
)
def check_env_file(ctx: ScanContext) -> list[Finding]:
    """Verify .env exists and isn't world-readable."""
    findings: list[Finding] = []
    env_path = ctx.project_path / ".env"

    if not env_path.exists():
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Environment",
            title=".env file is missing",
            description=(
                "No .env file found at the project root. Laravel requires "
                "environment configuration to function properly and securely."
            ),
            recommendation="Create a .env file from .env.example and configure it.",
            file=".env",
        ))
        return findings

    # Check file permissions (Unix only)
    try:
        mode = env_path.stat().st_mode
        if mode & stat.S_IROTH or mode & stat.S_IWOTH:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Environment",
                title=".env file is world-readable",
                description=(
                    f".env has permissions {oct(mode)[-3:]}. Other users on "
                    "the system can read your secrets."
                ),
                recommendation="Run: chmod 600 .env",
                file=".env",
            ))
    except OSError:
        pass

    return findings


@register_check(
    category="Environment",
    name="env_debug_mode",
    description="Flags APP_DEBUG=true in what looks like a production environment.",
)
def check_debug_mode(ctx: ScanContext) -> list[Finding]:
    """Detect debug mode enabled in production."""
    findings: list[Finding] = []
    env_values = ctx.get_env_values()

    app_debug = env_values.get("APP_DEBUG", "").lower()
    app_env = env_values.get("APP_ENV", "").lower()

    if app_debug == "true" and app_env in ("production", "prod", "staging"):
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="Environment",
            title="APP_DEBUG is enabled in production",
            description=(
                f"APP_DEBUG=true with APP_ENV={app_env}. Debug mode exposes "
                "full stack traces, database queries, environment variables, "
                "and internal paths to any visitor encountering an error."
            ),
            recommendation="Set APP_DEBUG=false in .env for production/staging.",
            file=".env",
        ))
    elif app_debug == "true":
        findings.append(Finding(
            severity=Severity.INFO,
            category="Environment",
            title="APP_DEBUG is enabled",
            description=(
                f"APP_DEBUG=true with APP_ENV={app_env or '(not set)'}. "
                "Acceptable for local development, but ensure this is disabled "
                "before deploying."
            ),
            recommendation="Set APP_DEBUG=false before deploying to production.",
            file=".env",
        ))

    return findings


@register_check(
    category="Environment",
    name="env_app_key",
    description="Checks for missing or empty APP_KEY.",
)
def check_app_key(ctx: ScanContext) -> list[Finding]:
    """Detect missing or empty application encryption key."""
    findings: list[Finding] = []
    env_values = ctx.get_env_values()

    app_key = env_values.get("APP_KEY", "").strip()

    if not app_key:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="Environment",
            title="APP_KEY is empty or missing",
            description=(
                "The application encryption key is not set. Without it, "
                "encrypted values (cookies, sessions, passwords) are insecure "
                "and predictable."
            ),
            recommendation="Run: php artisan key:generate",
            file=".env",
        ))

    return findings


@register_check(
    category="Environment",
    name="env_session_security",
    description="Checks SESSION_SECURE_COOKIE and SESSION_ENCRYPT settings.",
)
def check_session_security(ctx: ScanContext) -> list[Finding]:
    """Flag insecure session configuration."""
    findings: list[Finding] = []
    env_values = ctx.get_env_values()
    app_env = env_values.get("APP_ENV", "").lower()

    # Only flag in production-like environments
    if app_env not in ("production", "prod", "staging"):
        return findings

    secure_cookie = env_values.get("SESSION_SECURE_COOKIE", "").lower()
    if secure_cookie == "false" or (not secure_cookie and app_env == "production"):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Environment",
            title="SESSION_SECURE_COOKIE is not enabled",
            description=(
                "Session cookies are not restricted to HTTPS connections. "
                "On HTTP connections, cookies can be intercepted via MITM attacks."
            ),
            recommendation="Set SESSION_SECURE_COOKIE=true in .env for production.",
            file=".env",
        ))

    return findings


@register_check(
    category="Environment",
    name="env_example_secrets",
    description="Detects .env.example leaking real secret values instead of placeholders.",
)
def check_env_example(ctx: ScanContext) -> list[Finding]:
    """Detect real secrets leaked in .env.example."""
    findings: list[Finding] = []
    example_values = ctx.get_env_values(".env.example")
    real_values = ctx.get_env_values(".env")

    if not example_values:
        return findings

    for key, example_val in example_values.items():
        # Skip empty/placeholder values
        if not example_val or example_val in (
            "null", "your-key-here", "your-secret", "xxx",
            "changeme", "placeholder", "secret", "",
        ):
            continue

        # Check if the key name looks like it holds a secret
        is_secret_key = any(p.search(key) for p in _SECRET_PATTERNS)
        if not is_secret_key:
            continue

        # If the example value matches the real .env value, it's likely a real secret
        real_val = real_values.get(key, "")
        if example_val == real_val and len(example_val) > 8:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Environment",
                title=f".env.example leaks real secret for {key}",
                description=(
                    f"The key '{key}' in .env.example contains a value that "
                    "matches the actual .env. This file is typically committed "
                    "to version control, exposing your secret."
                ),
                recommendation=(
                    f"Replace the value of {key} in .env.example with a placeholder "
                    "like 'your-{key.lower()}-here'."
                ),
                file=".env.example",
            ))

    return findings


@register_check(
    category="Environment",
    name="env_vite_secrets",
    description="Flags VITE_* environment variables that look like they hold secrets.",
)
def check_vite_secrets(ctx: ScanContext) -> list[Finding]:
    """Detect secrets exposed via VITE_* variables (inlined into client JS by Vite)."""
    findings: list[Finding] = []
    env_values = ctx.get_env_values()

    for key, value in env_values.items():
        if not key.startswith("VITE_"):
            continue
        if not value or len(value) < 8:
            continue

        # Check if the key name suggests a secret
        is_secret_name = any(p.search(key) for p in _SECRET_PATTERNS)

        # Check if the value looks like a secret
        is_secret_value = any(p.search(value) for p in _VITE_SECRET_INDICATORS)

        if is_secret_name or is_secret_value:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="Environment",
                title=f"VITE_* variable '{key}' appears to hold a secret",
                description=(
                    f"The variable '{key}' is prefixed with VITE_, which means "
                    "Vite will inline its value directly into the client-side "
                    "JavaScript bundle at build time. Every visitor to your site "
                    "can extract this value from the browser's JS."
                ),
                recommendation=(
                    f"Remove the VITE_ prefix from '{key}' if it's a server-side "
                    "secret. Access it via a backend API endpoint instead."
                ),
                file=".env",
            ))

    return findings


@register_check(
    category="Environment",
    name="env_laravel_version",
    description="Checks Laravel version against known EOL dates (informational).",
)
def check_laravel_version(ctx: ScanContext) -> list[Finding]:
    """Flag EOL or outdated Laravel versions (informational only, no fake CVEs)."""
    findings: list[Finding] = []
    version = ctx.get_laravel_version()

    if not version:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Environment",
            title="Could not determine Laravel version",
            description=(
                "No composer.lock found or laravel/framework not present. "
                "Version-based checks cannot be performed."
            ),
            recommendation="Ensure composer.lock is committed to your project.",
        ))
        return findings

    major = version.split(".")[0]

    if major in _LARAVEL_EOL:
        from datetime import date

        eol_date = date.fromisoformat(_LARAVEL_EOL[major])
        today = date.today()

        if today > eol_date:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Environment",
                title=f"Laravel {version} has reached end of life",
                description=(
                    f"Laravel {major}.x security support ended on {eol_date}. "
                    "Your application will not receive security patches."
                ),
                recommendation=(
                    f"Upgrade to a supported Laravel version. "
                    f"See https://laravel.com/docs/releases for the support policy."
                ),
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO,
                category="Environment",
                title=f"Laravel {version} is within support window",
                description=(
                    f"Laravel {major}.x is supported until {eol_date}."
                ),
                recommendation="No action needed. Keep an eye on the EOL date.",
            ))

    return findings
