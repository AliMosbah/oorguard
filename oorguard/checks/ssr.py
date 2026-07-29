"""SSR (Inertia SSR / Node) Security checks.

Detects SSR setup, flags publicly bound SSR servers, and provides
informational notes about DoS risks with server-side rendering.
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


@register_check(
    category="SSR",
    name="ssr_configuration",
    description="Detects SSR setup and checks for security misconfigurations.",
)
def check_ssr_config(ctx: ScanContext) -> list[Finding]:
    """Analyze SSR configuration for security issues."""
    findings: list[Finding] = []

    # Detect SSR setup
    has_ssr = False
    ssr_entry: str | None = None

    # Check for ssr.js or ssr.tsx entry file
    ssr_paths = [
        "resources/js/ssr.js",
        "resources/js/ssr.ts",
        "resources/js/ssr.tsx",
        "resources/js/ssr.jsx",
    ]
    for ssr_path in ssr_paths:
        if ctx.file_exists(ssr_path):
            has_ssr = True
            ssr_entry = ssr_path
            break

    # Check package.json for inertia:start-ssr script
    pkg_json = ctx.get_package_json()
    if pkg_json:
        scripts = pkg_json.get("scripts", {})
        if any("ssr" in v.lower() or "inertia:start-ssr" in k for k, v in scripts.items()):
            has_ssr = True

    if not has_ssr:
        return findings

    findings.append(Finding(
        severity=Severity.INFO,
        category="SSR",
        title="SSR (Server-Side Rendering) setup detected",
        description=(
            f"Inertia SSR entry found{f' at {ssr_entry}' if ssr_entry else ''}. "
            "SSR renders React/Vue components on the server, which has "
            "performance benefits but also security implications."
        ),
        recommendation="Review SSR configuration for the security notes below.",
        file=ssr_entry,
    ))

    # --- Check SSR server binding ---
    # Look in vite.config.js/ts for ssr.host or server configuration
    for config_name in ("vite.config.js", "vite.config.ts"):
        content = ctx.read_file(config_name)
        if content is None:
            continue

        # Check for SSR server bound to 0.0.0.0
        host_pattern = re.compile(
            r"""ssr\s*:\s*\{[^}]*host\s*:\s*['"]0\.0\.0\.0['"]""",
            re.DOTALL,
        )
        match = host_pattern.search(content)
        if match:
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                category="SSR",
                title="SSR server bound to 0.0.0.0 (publicly accessible)",
                description=(
                    f"The SSR server in {config_name} is configured to bind to "
                    "0.0.0.0, making it accessible from any network interface. "
                    "The SSR server should only be reachable by the Laravel "
                    "backend (localhost), never directly by end users."
                ),
                recommendation=(
                    "Bind SSR to localhost only:\n"
                    "  ssr: { host: '127.0.0.1' }\n"
                    "And ensure firewall rules block external access to the SSR port."
                ),
                file=config_name,
                line=line_num,
            ))

    # Check if SSR entry file exposes a custom port on 0.0.0.0
    if ssr_entry:
        ssr_content = ctx.read_file(ssr_entry)
        if ssr_content:
            listen_pattern = re.compile(
                r"""\.listen\s*\(\s*(\d+)\s*,\s*['"]0\.0\.0\.0['"]""",
            )
            match = listen_pattern.search(ssr_content)
            if match:
                port = match.group(1)
                line_num = ssr_content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="SSR",
                    title=f"SSR Node server listening on 0.0.0.0:{port}",
                    description=(
                        f"The SSR entry file binds to 0.0.0.0:{port}, making the "
                        "Node rendering server accessible from the network. "
                        "External access to the SSR server can leak rendered "
                        "page content and enable DoS attacks."
                    ),
                    recommendation=(
                        "Bind to 127.0.0.1 only:\n"
                        f"  .listen({port}, '127.0.0.1')"
                    ),
                    file=ssr_entry,
                    line=line_num,
                ))

    # --- DoS risk informational note ---
    findings.append(Finding(
        severity=Severity.INFO,
        category="SSR",
        title="SSR DoS risk: rate limiting recommended",
        description=(
            "SSR renders React/Vue components server-side on every request. "
            "Each render consumes CPU and memory in the Node process. Without "
            "rate limiting, an attacker can overwhelm the SSR server with "
            "rapid requests, causing denial of service for all users."
        ),
        recommendation=(
            "Implement rate limiting upstream (nginx, Laravel throttle middleware) "
            "before requests reach the SSR server. Consider payload size limits "
            "and monitoring SSR server memory/CPU usage."
        ),
    ))

    return findings
