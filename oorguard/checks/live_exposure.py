"""Optional Live Exposure check (opt-in via --url flag).

Makes read-only HTTP GET requests to common sensitive paths and flags any
that return HTTP 200 with plausible content. Only runs when the user
explicitly provides a --url. Rate-limited with delays between requests.
"""

from __future__ import annotations

import time
from urllib.parse import urljoin

import requests

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


# Paths to check, with descriptions and expected severity if exposed
_SENSITIVE_PATHS: list[tuple[str, str, Severity]] = [
    (
        "/.env",
        "Environment file exposed — contains database credentials, API keys, APP_KEY",
        Severity.CRITICAL,
    ),
    (
        "/.git/config",
        "Git config exposed — confirms .git directory is accessible, enabling full repo download",
        Severity.CRITICAL,
    ),
    (
        "/.git/HEAD",
        "Git HEAD exposed — confirms .git directory is web-accessible",
        Severity.CRITICAL,
    ),
    (
        "/telescope",
        "Laravel Telescope dashboard accessible — exposes requests, exceptions, queries, jobs",
        Severity.HIGH,
    ),
    (
        "/horizon",
        "Laravel Horizon dashboard accessible — exposes queue jobs and server metrics",
        Severity.HIGH,
    ),
    (
        "/_debugbar/open",
        "Laravel Debugbar endpoint accessible — exposes queries, config, session data",
        Severity.HIGH,
    ),
    (
        "/storage/logs/laravel.log",
        "Laravel log file accessible — may contain stack traces, credentials, user data",
        Severity.HIGH,
    ),
    (
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "PHPUnit eval endpoint accessible — potential remote code execution",
        Severity.CRITICAL,
    ),
    (
        "/.env.backup",
        "Environment backup file exposed — may contain production credentials",
        Severity.CRITICAL,
    ),
    (
        "/.env.production",
        "Production environment file exposed",
        Severity.CRITICAL,
    ),
    (
        "/storage/framework/sessions",
        "Session storage directory accessible — may expose session data",
        Severity.HIGH,
    ),
    (
        "/phpinfo.php",
        "phpinfo() page accessible — exposes PHP config, extensions, server paths",
        Severity.MEDIUM,
    ),
]

# Delay between requests (seconds)
_REQUEST_DELAY: float = 0.5

# Request timeout (seconds)
_REQUEST_TIMEOUT: int = 10


@register_check(
    category="Live Exposure",
    name="live_exposure_scan",
    description="HTTP probes for exposed sensitive paths (opt-in via --url).",
)
def check_live_exposure(ctx: ScanContext) -> list[Finding]:
    """Probe sensitive paths via HTTP GET requests."""
    findings: list[Finding] = []

    if not ctx.base_url:
        return findings

    base_url = ctx.base_url.rstrip("/")

    findings.append(Finding(
        severity=Severity.INFO,
        category="Live Exposure",
        title=f"Live exposure scan targeting: {base_url}",
        description=(
            f"Scanning {len(_SENSITIVE_PATHS)} sensitive paths against {base_url}. "
            "Only read-only GET requests are sent."
        ),
        recommendation="Review any exposed paths found below.",
    ))

    headers = {
        "User-Agent": "OorGuard Security Scanner/1.0 (authorized scan)",
    }

    for path, description, severity in _SENSITIVE_PATHS:
        url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=True,
            )

            if response.status_code == 200:
                content_length = len(response.content)
                content_type = response.headers.get("Content-Type", "")

                # Validate it's a plausible response (not a custom 404 page)
                if _is_plausible_exposure(path, response):
                    findings.append(Finding(
                        severity=severity,
                        category="Live Exposure",
                        title=f"Exposed: {path}",
                        description=(
                            f"{description}\n"
                            f"URL: {url}\n"
                            f"Status: {response.status_code}\n"
                            f"Content-Type: {content_type}\n"
                            f"Content-Length: {content_length} bytes"
                        ),
                        recommendation=(
                            f"Block access to {path} immediately:\n"
                            f"  Nginx: location ~ {path.replace('.', '\\\\.')} {{ deny all; }}\n"
                            f"  Apache: RedirectMatch 404 {path.replace('.', '\\\\.')}"
                        ),
                    ))

        except requests.exceptions.SSLError:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="Live Exposure",
                title="SSL/TLS error during live scan",
                description=f"SSL error when connecting to {url}. Certificate may be invalid.",
                recommendation="Check your SSL certificate configuration.",
            ))
        except requests.exceptions.ConnectionError:
            findings.append(Finding(
                severity=Severity.INFO,
                category="Live Exposure",
                title="Connection failed during live scan",
                description=f"Could not connect to {url}.",
                recommendation="Verify the URL is correct and the server is running.",
            ))
        except requests.exceptions.Timeout:
            pass  # Skip silently on timeout
        except requests.exceptions.RequestException:
            pass  # Skip other request errors silently

        # Rate limiting delay
        time.sleep(_REQUEST_DELAY)

    return findings


def _is_plausible_exposure(path: str, response: requests.Response) -> bool:
    """Heuristic to distinguish real exposure from custom error pages.

    Custom 404 pages often return 200 status but contain generic HTML.
    Real exposures have distinctive content for each path.
    """
    content = response.text[:2000].lower()
    content_type = response.headers.get("Content-Type", "").lower()

    # .env files should contain key=value pairs
    if path.startswith("/.env"):
        return "app_key" in content or "db_password" in content or "app_name" in content

    # .git/config should contain [core] or [remote]
    if ".git/config" in path:
        return "[core]" in content or "[remote" in content

    # .git/HEAD should contain ref: refs/
    if ".git/HEAD" in path:
        return content.strip().startswith("ref:") or len(content.strip()) == 40

    # Telescope/Horizon should return HTML with their specific markers
    if "/telescope" in path:
        return "telescope" in content and ("text/html" in content_type or "<html" in content)

    if "/horizon" in path:
        return "horizon" in content and ("text/html" in content_type or "<html" in content)

    # Debugbar returns JSON
    if "_debugbar" in path:
        return "application/json" in content_type

    # Log files contain timestamps and stack traces
    if "laravel.log" in path:
        return "stack trace" in content or "[20" in content or "Exception" in content

    # PHPUnit eval-stdin.php is very specific
    if "eval-stdin" in path:
        return "text/html" not in content_type or len(response.content) < 100

    # phpinfo returns specific markers
    if "phpinfo" in path:
        return "php version" in content or "phpinfo()" in content

    # Session directory listing
    if "sessions" in path:
        return "index of" in content

    # Default: if it responds with meaningful content, flag it
    return len(response.content) > 50 and "404" not in content[:500]
