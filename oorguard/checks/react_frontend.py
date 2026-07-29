"""React / Frontend Security checks.

Detects dangerouslySetInnerHTML without sanitization, eval()/new Function()
in JS/JSX/TSX, and missing Content-Security-Policy configuration.
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


@register_check(
    category="React/Frontend",
    name="dangerous_inner_html",
    description="Detects dangerouslySetInnerHTML without evidence of a sanitizer (DOMPurify).",
)
def check_dangerous_inner_html(ctx: ScanContext) -> list[Finding]:
    """Flag dangerouslySetInnerHTML usage without sanitization."""
    findings: list[Finding] = []

    frontend_files = ctx.get_files(".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte")
    danger_pattern = re.compile(r"""dangerouslySetInnerHTML""")
    sanitizer_pattern = re.compile(
        r"""(?:DOMPurify|dompurify|sanitize|createDOMPurify|xss|sanitizeHtml|sanitize-html)""",
        re.IGNORECASE,
    )

    for file_path in frontend_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        for match in danger_pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1

            # Check if a sanitizer is imported/used in the same file
            has_sanitizer = bool(sanitizer_pattern.search(content))

            if not has_sanitizer:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="React/Frontend",
                    title="dangerouslySetInnerHTML without sanitization",
                    description=(
                        f"dangerouslySetInnerHTML is used in {rel_path} at line "
                        f"{line_num} without evidence of a sanitizer like DOMPurify. "
                        "This renders raw HTML directly into the DOM, enabling "
                        "Cross-Site Scripting (XSS) if the content includes "
                        "user-supplied data."
                    ),
                    recommendation=(
                        "Sanitize HTML before rendering:\n"
                        "  import DOMPurify from 'dompurify';\n"
                        "  <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}} />"
                    ),
                    file=rel_path,
                    line=line_num,
                ))
            else:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category="React/Frontend",
                    title="dangerouslySetInnerHTML with sanitizer present",
                    description=(
                        f"dangerouslySetInnerHTML is used in {rel_path} at line "
                        f"{line_num}. A sanitizer (DOMPurify or similar) appears "
                        "to be imported in this file."
                    ),
                    recommendation=(
                        "Verify that the sanitizer is applied to the exact "
                        "value passed to dangerouslySetInnerHTML."
                    ),
                    file=rel_path,
                    line=line_num,
                ))

    return findings


@register_check(
    category="React/Frontend",
    name="js_eval",
    description="Detects eval() and new Function() usage in JavaScript/TypeScript files.",
)
def check_js_eval(ctx: ScanContext) -> list[Finding]:
    """Flag eval() and new Function() in frontend code."""
    findings: list[Finding] = []

    frontend_files = ctx.get_files(".js", ".jsx", ".ts", ".tsx")
    eval_pattern = re.compile(r"""\beval\s*\(""")
    new_function_pattern = re.compile(r"""\bnew\s+Function\s*\(""")

    for file_path in frontend_files:
        # Skip minified/bundled files
        if "dist/" in str(file_path) or "build/" in str(file_path) or ".min." in file_path.name:
            continue

        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        for match in eval_pattern.finditer(content):
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_content = content[line_start:match.end()]
            if line_content.lstrip().startswith("//") or line_content.lstrip().startswith("*"):
                continue

            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                category="React/Frontend",
                title="eval() usage in JavaScript",
                description=(
                    f"eval() is used in {rel_path} at line {line_num}. "
                    "eval() executes arbitrary code and is a common XSS vector. "
                    "If any part of the evaluated string is user-controlled, "
                    "it's a critical vulnerability."
                ),
                recommendation=(
                    "Remove eval(). Use JSON.parse() for data, template literals "
                    "for string construction, or a proper expression parser."
                ),
                file=rel_path,
                line=line_num,
            ))

        for match in new_function_pattern.finditer(content):
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_content = content[line_start:match.end()]
            if line_content.lstrip().startswith("//") or line_content.lstrip().startswith("*"):
                continue

            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                category="React/Frontend",
                title="new Function() usage in JavaScript",
                description=(
                    f"new Function() is used in {rel_path} at line {line_num}. "
                    "Like eval(), new Function() compiles and executes arbitrary "
                    "code strings, enabling code injection attacks."
                ),
                recommendation=(
                    "Avoid new Function(). Use structured logic (maps, switch "
                    "statements) instead of dynamically generating code."
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="React/Frontend",
    name="csp_check",
    description="Checks for Content-Security-Policy header configuration.",
)
def check_csp(ctx: ScanContext) -> list[Finding]:
    """Flag missing CSP configuration (informational)."""
    findings: list[Finding] = []

    # Check for common CSP middleware/package indicators
    csp_indicators = [
        # Laravel packages
        "spatie/laravel-csp",
        "bepsvpt/secure-headers",
        # Manual middleware
        "Content-Security-Policy",
        "content-security-policy",
    ]

    # Check composer.json
    composer = ctx.get_composer_json()
    has_csp_package = False
    if composer:
        all_deps = {**composer.get("require", {}), **composer.get("require-dev", {})}
        for pkg in ("spatie/laravel-csp", "bepsvpt/secure-headers"):
            if pkg in all_deps:
                has_csp_package = True
                break

    if has_csp_package:
        findings.append(Finding(
            severity=Severity.INFO,
            category="React/Frontend",
            title="CSP package detected",
            description="A Content-Security-Policy package is installed.",
            recommendation="Verify the CSP policy is properly configured and not too permissive.",
        ))
        return findings

    # Check for manual CSP in middleware files
    has_manual_csp = False
    php_files = ctx.get_files_in("app/Http/Middleware", ".php")
    for file_path in php_files:
        content = ctx.read_file(file_path)
        if content and "Content-Security-Policy" in content:
            has_manual_csp = True
            break

    # Check .htaccess for CSP header
    htaccess = ctx.read_file("public/.htaccess")
    if htaccess and "Content-Security-Policy" in htaccess:
        has_manual_csp = True

    if not has_manual_csp:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="React/Frontend",
            title="No Content-Security-Policy configuration detected",
            description=(
                "No CSP header configuration was found (no CSP package installed, "
                "no middleware setting the header, no .htaccess rule). CSP is a "
                "critical defense-in-depth layer against XSS — it restricts "
                "which scripts, styles, and resources can load on your pages."
            ),
            recommendation=(
                "Add CSP headers. Recommended: install spatie/laravel-csp:\n"
                "  composer require spatie/laravel-csp\n"
                "Or add a middleware that sets the header manually."
            ),
        ))

    return findings
