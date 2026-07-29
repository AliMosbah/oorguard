"""Dangerous Code Patterns check.

Regex-based static analysis scanning app/ and resources/views/ for dangerous
PHP patterns: raw SQL injection vectors, eval(), unserialize() on input,
dynamic include/require, and unescaped Blade output {!! !!}.
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


@register_check(
    category="Code Patterns",
    name="dangerous_code_patterns",
    description="Detects raw SQL injection, eval(), unserialize(), dynamic includes, and unescaped Blade output.",
)
def check_dangerous_patterns(ctx: ScanContext) -> list[Finding]:
    """Scan PHP files for dangerous code patterns."""
    findings: list[Finding] = []

    php_files = ctx.get_files_in("app", ".php")
    blade_files = ctx.get_files(".blade.php")

    # --- Raw SQL with variable concatenation ---
    raw_sql_patterns = [
        (
            re.compile(r"""(whereRaw|selectRaw|orderByRaw|groupByRaw|havingRaw)\s*\(\s*['"].*?\$""", re.DOTALL),
            "Raw SQL query with variable interpolation",
            "A raw query method uses a PHP variable directly in the SQL string, "
            "which can lead to SQL injection if the variable contains user input.",
            "Use parameter bindings: whereRaw('column = ?', [$value])",
        ),
        (
            re.compile(r"""DB::raw\s*\(\s*['"].*?\$""", re.DOTALL),
            "DB::raw() with variable interpolation",
            "DB::raw() is used with a PHP variable in the SQL string. "
            "This bypasses Eloquent's parameter binding and can lead to SQL injection.",
            "Use bindings: DB::raw('COALESCE(column, ?) as result', [$default])",
        ),
        (
            re.compile(r"""DB::statement\s*\(\s*['"].*?\$""", re.DOTALL),
            "DB::statement() with variable interpolation",
            "DB::statement() executes raw SQL with a PHP variable interpolated "
            "into the query string, creating a SQL injection vector.",
            "Use the second parameter for bindings: DB::statement('...', [$value])",
        ),
        (
            re.compile(r"""DB::(select|insert|update|delete)\s*\(\s*['"].*?\.\s*\$""", re.DOTALL),
            "Raw DB query with string concatenation",
            "A raw database call concatenates a variable into the SQL string "
            "using the dot operator, bypassing parameter binding.",
            "Use parameterized queries: DB::select('... WHERE id = ?', [$id])",
        ),
    ]

    for file_path in php_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        for pattern, title, desc, rec in raw_sql_patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="Code Patterns",
                    title=title,
                    description=f"{desc}\nFound in: {rel_path}",
                    recommendation=rec,
                    file=rel_path,
                    line=line_num,
                ))

    # --- eval() ---
    eval_pattern = re.compile(r"""\beval\s*\(""")
    for file_path in php_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)
        for match in eval_pattern.finditer(content):
            # Skip if in a comment
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_content = content[line_start:match.end()]
            if line_content.lstrip().startswith("//") or line_content.lstrip().startswith("*"):
                continue

            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="Code Patterns",
                title="eval() usage detected",
                description=(
                    f"eval() executes arbitrary PHP code at runtime. If any part "
                    f"of the evaluated string is user-controlled, this is a Remote "
                    f"Code Execution (RCE) vulnerability.\nFound in: {rel_path}"
                ),
                recommendation=(
                    "Remove eval() entirely. Use proper alternatives: "
                    "match/switch statements, strategy pattern, or dedicated parsers."
                ),
                file=rel_path,
                line=line_num,
            ))

    # --- unserialize() on request/input data ---
    unserialize_pattern = re.compile(
        r"""unserialize\s*\(\s*\$(?:request|_GET|_POST|_REQUEST|_COOKIE|input)""",
    )
    for file_path in php_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)
        for match in unserialize_pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="Code Patterns",
                title="unserialize() on user input — PHP Object Injection",
                description=(
                    f"unserialize() is called on request/input data in {rel_path}. "
                    "An attacker can craft serialized objects to trigger "
                    "destructors, __wakeup(), or __toString() magic methods, "
                    "potentially achieving RCE."
                ),
                recommendation=(
                    "Never unserialize user input. Use json_decode() for data "
                    "interchange. If serialization is required, use allowed_classes "
                    "parameter: unserialize($data, ['allowed_classes' => false])"
                ),
                file=rel_path,
                line=line_num,
            ))

    # --- Dynamic include/require ---
    include_pattern = re.compile(
        r"""\b(include|include_once|require|require_once)\s*[\(]?\s*\$""",
    )
    for file_path in php_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)
        for match in include_pattern.finditer(content):
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_content = content[line_start:match.end()]
            if line_content.lstrip().startswith("//") or line_content.lstrip().startswith("*"):
                continue

            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Code Patterns",
                title="Dynamic include/require with variable path",
                description=(
                    f"A {match.group(1)} statement uses a variable for the file "
                    f"path in {rel_path}. If the variable is user-controlled, "
                    "this enables Local File Inclusion (LFI) or Remote File "
                    "Inclusion (RFI) attacks."
                ),
                recommendation=(
                    "Use a whitelist of allowed paths: match($type) { ... }. "
                    "Never include files based on user input directly."
                ),
                file=rel_path,
                line=line_num,
            ))

    # --- Blade {!! !!} unescaped output ---
    blade_unescaped = re.compile(r"""\{!!\s*.*?\s*!!\}""")
    for file_path in blade_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)
        for match in blade_unescaped.finditer(content):
            inner = match.group(0)
            line_num = content[:match.start()].count("\n") + 1

            # Skip common safe usages
            safe_patterns = [
                "csrf_field", "csrf_token", "method_field",
                "__(",  # translations
                "Vite::", "vite(",
                "app.css", "app.js",
            ]
            if any(s in inner for s in safe_patterns):
                continue

            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="Code Patterns",
                title="Unescaped Blade output {!! !!}",
                description=(
                    f"Unescaped output in {rel_path} at line {line_num}: {inner[:80]}. "
                    "If the variable contains user-supplied data, this is a "
                    "Cross-Site Scripting (XSS) vulnerability."
                ),
                recommendation=(
                    "Use escaped output {{ }} unless the content is guaranteed "
                    "safe (e.g., rendered by a trusted WYSIWYG with server-side "
                    "sanitization via HTMLPurifier)."
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings
