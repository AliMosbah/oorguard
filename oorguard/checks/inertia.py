"""Inertia.js Security checks.

Detects cases where full Eloquent models are shared as Inertia props without
field filtering, exposing sensitive user data (passwords, tokens) to the
frontend. Also checks Sanctum SPA stateful domain configuration.
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


@register_check(
    category="Inertia",
    name="inertia_shared_props",
    description="Flags HandleInertiaRequests sharing full Eloquent models without field filtering.",
)
def check_inertia_shared_props(ctx: ScanContext) -> list[Finding]:
    """Detect full model sharing in HandleInertiaRequests middleware."""
    findings: list[Finding] = []

    # Find HandleInertiaRequests middleware
    middleware_files = ctx.get_files_in("app/Http/Middleware", ".php")
    for file_path in middleware_files:
        if "HandleInertiaRequests" not in file_path.name:
            continue

        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        # Look for share() method returning $request->user() without ->only()
        # Patterns: 'auth' => $request->user(), or 'user' => $request->user()
        user_share_pattern = re.compile(
            r"""['"](?:auth|user)['"].*?=>\s*\$request->user\(\)(?!\s*->\s*(?:only|toArray|makeHidden|Resource|resource))""",
            re.DOTALL,
        )

        for match in user_share_pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1

            # Check if the model class has $hidden defined
            has_safety = False
            matched_text = match.group(0)

            # Check for inline ->only() or Resource class
            if "->only(" in matched_text or "Resource" in matched_text:
                has_safety = True

            if not has_safety:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="Inertia",
                    title="Full user model shared as Inertia prop",
                    description=(
                        f"HandleInertiaRequests in {rel_path} shares $request->user() "
                        "directly as an Inertia prop without ->only() or a Resource "
                        "class. This sends all model attributes (potentially including "
                        "password hash, remember_token, API tokens) to the frontend "
                        "JavaScript — visible in page source and Inertia props."
                    ),
                    recommendation=(
                        "Use ->only() to whitelist fields:\n"
                        "  'auth' => $request->user()?->only('id', 'name', 'email'),\n"
                        "Or use an API Resource:\n"
                        "  'auth' => $request->user() ? new UserResource($request->user()) : null,"
                    ),
                    file=rel_path,
                    line=line_num,
                ))

        # Generic model sharing patterns: ->with(['key' => Model::all()])
        model_all_pattern = re.compile(
            r"""['"][a-zA-Z]+['"]\s*=>\s*[A-Z][a-zA-Z]*::(all|get|find|where)\(""",
        )
        for match in model_all_pattern.finditer(content):
            # Check if it's inside the share method
            method_start = content.rfind("function share(", 0, match.start())
            if method_start == -1:
                continue

            line_num = content[:match.start()].count("\n") + 1
            matched_text = match.group(0)

            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="Inertia",
                title="Eloquent query result shared directly as Inertia prop",
                description=(
                    f"In {rel_path}, a query result is shared directly in the "
                    f"share() method: '{matched_text[:60]}...'. Raw Eloquent "
                    "results may include sensitive attributes."
                ),
                recommendation=(
                    "Use API Resources or ->select() to control which fields "
                    "are sent to the frontend."
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="Inertia",
    name="inertia_render_props",
    description="Flags controllers passing raw Eloquent models to Inertia::render().",
)
def check_inertia_render(ctx: ScanContext) -> list[Finding]:
    """Detect raw model passing in Inertia::render() calls."""
    findings: list[Finding] = []

    controller_files = ctx.get_files_in("app/Http/Controllers", ".php")
    if not controller_files:
        controller_files = ctx.get_files_in("app/Http", ".php")

    # Pattern: Inertia::render('Page', ['key' => $model]) where $model is not wrapped
    render_pattern = re.compile(
        r"""Inertia::render\s*\(\s*['"][^'"]+['"]\s*,\s*\[(.*?)\]\s*\)""",
        re.DOTALL,
    )

    # Also match the inertia() helper
    helper_pattern = re.compile(
        r"""inertia\s*\(\s*['"][^'"]+['"]\s*,\s*\[(.*?)\]\s*\)""",
        re.DOTALL,
    )

    model_prop_pattern = re.compile(
        r"""['"][a-zA-Z]+['"]\s*=>\s*\$[a-zA-Z]+(?:\s*$|\s*,|\s*\])""",
        re.MULTILINE,
    )

    for file_path in controller_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        for pattern in (render_pattern, helper_pattern):
            for match in pattern.finditer(content):
                props_block = match.group(1)
                line_num = content[:match.start()].count("\n") + 1

                # Check each prop for raw variable passing
                for prop_match in model_prop_pattern.finditer(props_block):
                    prop_text = prop_match.group(0).strip()

                    # Skip if it's clearly using a Resource or ->only()
                    if "Resource" in content[match.start():match.end() + 100]:
                        continue
                    if "->only(" in content[match.start():match.end() + 100]:
                        continue

                    # This is a heuristic — flag it as informational
                    findings.append(Finding(
                        severity=Severity.LOW,
                        category="Inertia",
                        title="Variable passed directly to Inertia::render()",
                        description=(
                            f"In {rel_path} at line {line_num}, a variable is "
                            f"passed directly as an Inertia prop: '{prop_text[:50]}'. "
                            "If this is an Eloquent model, all attributes "
                            "(including hidden ones) may be serialized to the page."
                        ),
                        recommendation=(
                            "Use API Resources for complex models:\n"
                            "  'user' => new UserResource($user),\n"
                            "Or filter fields:\n"
                            "  'user' => $user->only('id', 'name'),"
                        ),
                        file=rel_path,
                        line=line_num,
                    ))

    return findings


@register_check(
    category="Inertia",
    name="sanctum_stateful_domains",
    description="Checks Sanctum SPA stateful domains for overly broad configuration.",
)
def check_sanctum_config(ctx: ScanContext) -> list[Finding]:
    """Flag overly broad Sanctum stateful domain configuration."""
    findings: list[Finding] = []

    sanctum_path = ctx.project_path / "config" / "sanctum.php"
    if not sanctum_path.exists():
        return findings

    content = ctx.read_file(sanctum_path)
    if content is None:
        return findings

    rel_path = ctx.relative_path(sanctum_path)

    # Look for wildcard or overly broad stateful domains
    stateful_pattern = re.compile(
        r"""['"]stateful['"]\s*=>\s*.*?\[(.*?)\]""",
        re.DOTALL,
    )

    match = stateful_pattern.search(content)
    if match:
        domains_block = match.group(1)
        line_num = content[:match.start()].count("\n") + 1

        # Flag wildcards
        if "'*'" in domains_block or '"*"' in domains_block:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="Inertia",
                title="Sanctum stateful domains set to wildcard",
                description=(
                    "Sanctum's stateful domains include '*', allowing any "
                    "domain to make authenticated SPA requests. This bypasses "
                    "CSRF protection for API routes."
                ),
                recommendation=(
                    "Restrict stateful domains to your actual frontend domain:\n"
                    "  'stateful' => ['yourdomain.com', 'localhost:3000'],"
                ),
                file=rel_path,
                line=line_num,
            ))

        # Flag env('SANCTUM_STATEFUL_DOMAINS') without validation
        if "env(" in domains_block:
            findings.append(Finding(
                severity=Severity.INFO,
                category="Inertia",
                title="Sanctum stateful domains loaded from environment",
                description=(
                    "Stateful domains are loaded from an environment variable. "
                    "Ensure the value is restrictive and doesn't include wildcards."
                ),
                recommendation=(
                    "Verify your SANCTUM_STATEFUL_DOMAINS .env value is set to "
                    "specific domains, not wildcards."
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings
