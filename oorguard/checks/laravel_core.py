"""Laravel Core Security checks.

Detects mass assignment vulnerabilities, insecure CORS configurations,
broad CSRF exceptions, and exposed debug tooling (Telescope, Horizon, Debugbar).
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


@register_check(
    category="Laravel Core",
    name="mass_assignment",
    description="Detects $guarded = [] or $fillable = ['*'] in Eloquent models.",
)
def check_mass_assignment(ctx: ScanContext) -> list[Finding]:
    """Flag models with disabled mass assignment protection."""
    findings: list[Finding] = []

    # Scan all PHP files under app/Models (or app/ for older structures)
    model_files = ctx.get_files_in("app/Models", ".php")
    if not model_files:
        model_files = ctx.get_files_in("app", ".php")

    guarded_empty = re.compile(r"""\$guarded\s*=\s*\[\s*\]""")
    fillable_wildcard = re.compile(r"""\$fillable\s*=\s*\[\s*['"]?\*['"]?\s*\]""")

    for file_path in model_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        # Check for extends Model to confirm it's an Eloquent model
        if "extends Model" not in content and "extends Authenticatable" not in content:
            continue

        rel_path = ctx.relative_path(file_path)

        for match in guarded_empty.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Laravel Core",
                title=f"Mass assignment unguarded: $guarded = []",
                description=(
                    f"Model at {rel_path} sets $guarded to an empty array, "
                    "disabling all mass assignment protection. Any attribute "
                    "can be set via create()/update() — including admin flags, "
                    "roles, and internal IDs."
                ),
                recommendation=(
                    "Use $fillable to whitelist allowed attributes, or add "
                    "sensitive columns to $guarded: protected $guarded = ['id', 'is_admin'];"
                ),
                file=rel_path,
                line=line_num,
            ))

        for match in fillable_wildcard.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Laravel Core",
                title=f"Mass assignment wildcard: $fillable = ['*']",
                description=(
                    f"Model at {rel_path} sets $fillable to ['*'], allowing "
                    "every attribute to be mass assigned. This is equivalent "
                    "to disabling mass assignment protection entirely."
                ),
                recommendation=(
                    "Explicitly list only the attributes that should be mass "
                    "assignable in $fillable."
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="Laravel Core",
    name="cors_wildcard",
    description="Flags wildcard CORS origins combined with supports_credentials.",
)
def check_cors_config(ctx: ScanContext) -> list[Finding]:
    """Detect dangerous CORS configurations."""
    findings: list[Finding] = []

    cors_path = ctx.project_path / "config" / "cors.php"
    if not cors_path.exists():
        return findings

    content = ctx.read_file(cors_path)
    if content is None:
        return findings

    rel_path = ctx.relative_path(cors_path)

    # Check for wildcard origins
    has_wildcard = bool(re.search(r"""['"]allowed_origins['"]\s*=>\s*\[\s*['"]?\*['"]?\s*\]""", content))
    has_wildcard = has_wildcard or bool(re.search(r"""['"]allowedOrigins['"]\s*=>\s*\[\s*['"]?\*['"]?\s*\]""", content))

    # Check for supports_credentials: true
    has_credentials = bool(re.search(r"""['"]supports_credentials['"]\s*=>\s*true""", content))
    has_credentials = has_credentials or bool(re.search(r"""['"]supportsCredentials['"]\s*=>\s*true""", content))

    if has_wildcard and has_credentials:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="Laravel Core",
            title="CORS: wildcard origins with credentials enabled",
            description=(
                "The CORS config allows all origins ('*') while also enabling "
                "supports_credentials. This combination lets any website make "
                "authenticated cross-origin requests to your API, potentially "
                "stealing session data or performing actions on behalf of users."
            ),
            recommendation=(
                "Either restrict allowed_origins to specific trusted domains, "
                "or disable supports_credentials if credentials aren't needed."
            ),
            file=rel_path,
        ))
    elif has_wildcard:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Laravel Core",
            title="CORS: wildcard allowed_origins",
            description=(
                "CORS allows requests from any origin ('*'). While less dangerous "
                "without credentials, it widens the attack surface."
            ),
            recommendation="Restrict allowed_origins to your actual frontend domain(s).",
            file=rel_path,
        ))

    return findings


@register_check(
    category="Laravel Core",
    name="csrf_exceptions",
    description="Detects broad CSRF exceptions in middleware or bootstrap config.",
)
def check_csrf_exceptions(ctx: ScanContext) -> list[Finding]:
    """Flag overly broad CSRF token exceptions."""
    findings: list[Finding] = []

    # Laravel <= 10: VerifyCsrfToken middleware
    csrf_patterns_in_middleware = [
        re.compile(r"""\$except\s*=\s*\[\s*['"]?\*['"]?\s*\]"""),
        re.compile(r"""\$except\s*=\s*\[\s*['"]/?\*['"]\s*\]"""),
    ]

    middleware_files = ctx.get_files_in("app/Http/Middleware", ".php")
    for file_path in middleware_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue
        if "VerifyCsrfToken" not in content:
            continue

        rel_path = ctx.relative_path(file_path)
        for pattern in csrf_patterns_in_middleware:
            match = pattern.search(content)
            if match:
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="Laravel Core",
                    title="CSRF protection disabled with wildcard exception",
                    description=(
                        f"VerifyCsrfToken in {rel_path} excludes '*' from CSRF "
                        "verification, effectively disabling CSRF protection "
                        "for all POST/PUT/DELETE routes."
                    ),
                    recommendation="Remove the wildcard. Only exclude specific webhook endpoints.",
                    file=rel_path,
                    line=line_num,
                ))

    # Laravel 11+: bootstrap/app.php
    bootstrap_path = ctx.project_path / "bootstrap" / "app.php"
    if bootstrap_path.exists():
        content = ctx.read_file(bootstrap_path)
        if content:
            csrf_except_pattern = re.compile(
                r"""validateCsrfTokens\s*\(\s*except\s*:\s*\[(.*?)\]""",
                re.DOTALL,
            )
            match = csrf_except_pattern.search(content)
            if match:
                exceptions = match.group(1).strip()
                if "'*'" in exceptions or '"*"' in exceptions or "/*" in exceptions:
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category="Laravel Core",
                        title="CSRF protection disabled with wildcard exception (Laravel 11+)",
                        description=(
                            "bootstrap/app.php disables CSRF for all routes via "
                            "a wildcard in validateCsrfTokens(except: [...])."
                        ),
                        recommendation="Remove the wildcard. Only exclude specific webhook URLs.",
                        file="bootstrap/app.php",
                        line=line_num,
                    ))

    # Check Blade templates for <form method="post"> without @csrf
    blade_files = ctx.get_files(".blade.php")
    form_pattern = re.compile(
        r"""<form[^>]*method\s*=\s*['"]post['"][^>]*>""",
        re.IGNORECASE,
    )
    csrf_directive = re.compile(r"""@csrf""")

    for file_path in blade_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        lines = content.splitlines()
        rel_path = ctx.relative_path(file_path)

        for i, line in enumerate(lines, 1):
            if form_pattern.search(line):
                # Check next ~5 lines for @csrf
                block = "\n".join(lines[i - 1: i + 5])
                if not csrf_directive.search(block):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category="Laravel Core",
                        title="Blade form missing @csrf directive",
                        description=(
                            f"A POST form in {rel_path} at line {i} does not "
                            "include @csrf. Without it, the form is vulnerable "
                            "to Cross-Site Request Forgery attacks."
                        ),
                        recommendation="Add @csrf inside the <form> tag.",
                        file=rel_path,
                        line=i,
                    ))

    return findings


@register_check(
    category="Laravel Core",
    name="debug_tools_exposure",
    description="Detects Telescope, Horizon, or Debugbar without access restrictions.",
)
def check_debug_tools(ctx: ScanContext) -> list[Finding]:
    """Flag debug/admin tools that lack access control."""
    findings: list[Finding] = []

    composer_json = ctx.get_composer_json()
    if not composer_json:
        return findings

    require = composer_json.get("require", {})
    require_dev = composer_json.get("require-dev", {})
    all_packages = {**require, **require_dev}

    # --- Telescope ---
    if "laravel/telescope" in all_packages:
        telescope_provider = ctx.project_path / "app" / "Providers" / "TelescopeServiceProvider.php"
        has_gate = False

        if telescope_provider.exists():
            content = ctx.read_file(telescope_provider)
            if content and ("Gate::define" in content or "gate" in content.lower()):
                has_gate = True

        if not has_gate:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Laravel Core",
                title="Laravel Telescope installed without access restriction",
                description=(
                    "Telescope is installed but no Gate::define restricting access "
                    "was found in TelescopeServiceProvider. In production, anyone "
                    "visiting /telescope can see requests, exceptions, queries, "
                    "mail, and more."
                ),
                recommendation=(
                    "Add a gate in TelescopeServiceProvider::gate():\n"
                    "  Gate::define('viewTelescope', function ($user) {\n"
                    "      return in_array($user->email, ['admin@example.com']);\n"
                    "  });"
                ),
            ))

    # --- Horizon ---
    if "laravel/horizon" in all_packages:
        horizon_provider = ctx.project_path / "app" / "Providers" / "HorizonServiceProvider.php"
        has_gate = False

        if horizon_provider.exists():
            content = ctx.read_file(horizon_provider)
            if content and ("Gate::define" in content or "gate" in content.lower()):
                has_gate = True

        if not has_gate:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Laravel Core",
                title="Laravel Horizon installed without access restriction",
                description=(
                    "Horizon is installed but no Gate restricting access was found. "
                    "The /horizon dashboard exposes queue jobs, metrics, and can "
                    "be used to retry/delete jobs."
                ),
                recommendation=(
                    "Add a gate in HorizonServiceProvider::gate():\n"
                    "  Gate::define('viewHorizon', function ($user) {\n"
                    "      return in_array($user->email, ['admin@example.com']);\n"
                    "  });"
                ),
            ))

    # --- Debugbar ---
    if "barryvdh/laravel-debugbar" in require:
        # In require (not require-dev) — should be dev-only
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Laravel Core",
            title="Debugbar in production dependencies",
            description=(
                "barryvdh/laravel-debugbar is in 'require' (production deps) "
                "instead of 'require-dev'. The debug bar exposes queries, "
                "routes, config, and session data to anyone in the browser."
            ),
            recommendation=(
                "Move to require-dev:\n"
                "  composer remove barryvdh/laravel-debugbar\n"
                "  composer require --dev barryvdh/laravel-debugbar"
            ),
            file="composer.json",
        ))
    elif "barryvdh/laravel-debugbar" in require_dev:
        # Check if it's explicitly disabled in production config
        env_values = ctx.get_env_values()
        debugbar_enabled = env_values.get("DEBUGBAR_ENABLED", "").lower()
        app_env = env_values.get("APP_ENV", "").lower()

        if app_env in ("production", "prod") and debugbar_enabled != "false":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="Laravel Core",
                title="Debugbar not explicitly disabled for production",
                description=(
                    "barryvdh/laravel-debugbar is installed (dev) but "
                    "DEBUGBAR_ENABLED is not set to false in .env. If the "
                    "package is accidentally loaded in production, the debug "
                    "bar will be visible."
                ),
                recommendation="Add DEBUGBAR_ENABLED=false to your production .env.",
                file=".env",
            ))

    return findings
