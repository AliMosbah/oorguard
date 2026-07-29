"""Secrets Scanner — project-wide detection of hardcoded secrets.

Scans all project files (excluding vendor/, node_modules/, .git/) for
common secret patterns: AWS keys, Stripe keys, Google API keys, generic
password/token assignments, and secrets in frontend JS/JSX/TSX files.
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


# Patterns for known secret formats.
# Each tuple: (compiled regex, description, severity)
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str, str, Severity]] = [
    (
        re.compile(r"""AKIA[0-9A-Z]{16}"""),
        "AWS Access Key ID",
        "AWS access key IDs start with 'AKIA' followed by 16 alphanumeric characters.",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"""(?:aws)?_?secret_?(?:access)?_?key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]""", re.IGNORECASE),
        "AWS Secret Access Key",
        "A 40-character AWS secret key was found hardcoded.",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"""sk_live_[A-Za-z0-9]{20,}"""),
        "Stripe Live Secret Key",
        "Stripe live secret keys (sk_live_*) grant full API access to your Stripe account.",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"""rk_live_[A-Za-z0-9]{20,}"""),
        "Stripe Restricted Live Key",
        "A Stripe restricted live key was found hardcoded.",
        Severity.HIGH,
    ),
    (
        re.compile(r"""sk_test_[A-Za-z0-9]{20,}"""),
        "Stripe Test Secret Key",
        "Stripe test keys should still not be committed to source control.",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"""AIza[0-9A-Za-z_-]{35}"""),
        "Google API Key",
        "Google API keys (AIza*) can be used to access various Google services.",
        Severity.HIGH,
    ),
    (
        re.compile(r"""ghp_[A-Za-z0-9]{36}"""),
        "GitHub Personal Access Token",
        "GitHub PATs grant repository and API access to your GitHub account.",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"""gho_[A-Za-z0-9]{36}"""),
        "GitHub OAuth Access Token",
        "GitHub OAuth tokens grant API access.",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"""(?:slack)(?:_|-)?(?:token|key|secret|webhook)\s*[=:]\s*['"]xox[bpsa]-[A-Za-z0-9-]+['"]""", re.IGNORECASE),
        "Slack Token",
        "Slack API tokens provide access to your Slack workspace.",
        Severity.HIGH,
    ),
    (
        re.compile(r"""(?:twilio)(?:_|-)?(?:auth)(?:_|-)?(?:token)\s*[=:]\s*['"][a-f0-9]{32}['"]""", re.IGNORECASE),
        "Twilio Auth Token",
        "Twilio auth tokens grant API access to send messages and make calls.",
        Severity.HIGH,
    ),
    (
        re.compile(r"""(?:sendgrid|sg)(?:_|-)?(?:api)?(?:_|-)?(?:key)\s*[=:]\s*['"]SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+['"]""", re.IGNORECASE),
        "SendGrid API Key",
        "SendGrid API keys can send emails on your behalf.",
        Severity.HIGH,
    ),
    (
        re.compile(r"""(?:mailgun)(?:_|-)?(?:api)?(?:_|-)?(?:key)\s*[=:]\s*['"]key-[A-Za-z0-9]{32}['"]""", re.IGNORECASE),
        "Mailgun API Key",
        "Mailgun API keys can send emails and access your account.",
        Severity.HIGH,
    ),
]

# Generic secret assignment patterns (matches key = "value" where key suggests a secret)
_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|secret|api_key|apikey|api_secret|auth_token|access_token|private_key|encryption_key)\s*[=:]\s*['"]([^'"]{8,})['"]""",
    re.IGNORECASE,
)

# Values to ignore (placeholders, common defaults)
_IGNORE_VALUES: frozenset[str] = frozenset({
    "your-key-here", "changeme", "secret", "password", "null", "undefined",
    "xxxxxxxx", "your-secret-here", "your_api_key", "placeholder",
    "test", "testing", "example", "sample", "demo", "dummy",
    "env(", "config(", "process.env.", "import.meta.env.",
})

# File extensions to scan
_SCAN_EXTENSIONS: tuple[str, ...] = (
    ".php", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".yaml", ".yml", ".json", ".xml", ".ini", ".conf",
    ".py", ".rb", ".env.production", ".env.staging",
)

# Files to skip entirely
_SKIP_FILES: frozenset[str] = frozenset({
    "package-lock.json", "composer.lock", "yarn.lock",
    "pnpm-lock.yaml", ".env", ".env.example",
})


@register_check(
    category="Secrets",
    name="secrets_scanner",
    description="Scans project files for hardcoded secrets: AWS keys, Stripe keys, API tokens, passwords.",
)
def check_secrets(ctx: ScanContext) -> list[Finding]:
    """Scan all project files for hardcoded secrets."""
    findings: list[Finding] = []

    for file_path in ctx.all_files:
        # Skip binary-looking files and lock files
        if file_path.name in _SKIP_FILES:
            continue
        if not any(file_path.name.endswith(ext) for ext in _SCAN_EXTENSIONS):
            continue

        content = ctx.read_file(file_path)
        if content is None:
            continue

        # Skip very large files (likely generated/minified)
        if len(content) > 500_000:
            continue

        rel_path = ctx.relative_path(file_path)
        is_frontend = file_path.suffix in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte")

        # Check named patterns
        for pattern, name, desc, severity in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1

                extra = ""
                if is_frontend:
                    extra = (
                        " This secret is in a frontend file and will be exposed "
                        "to every browser visitor."
                    )

                findings.append(Finding(
                    severity=severity if not is_frontend else Severity.CRITICAL,
                    category="Secrets",
                    title=f"Hardcoded {name} detected",
                    description=f"{desc}{extra}\nFound in: {rel_path}",
                    recommendation=(
                        f"Move this secret to .env and access it via env() in PHP "
                        f"or process.env in Node.js. Never commit secrets to source control."
                    ),
                    file=rel_path,
                    line=line_num,
                ))

        # Check generic password/secret assignments
        for match in _GENERIC_SECRET_ASSIGNMENT.finditer(content):
            value = match.group(1).strip()

            # Skip if value looks like a placeholder or env() reference
            if any(ignore in value.lower() for ignore in _IGNORE_VALUES):
                continue
            # Skip if value is too short or all same character
            if len(set(value)) < 4:
                continue

            line_num = content[:match.start()].count("\n") + 1

            # Check if it's inside a comment
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_content = content[line_start:match.start()].strip()
            if line_content.startswith("//") or line_content.startswith("*") or line_content.startswith("#"):
                continue

            findings.append(Finding(
                severity=Severity.HIGH if is_frontend else Severity.MEDIUM,
                category="Secrets",
                title="Hardcoded secret/password assignment",
                description=(
                    f"A value that looks like a secret is hardcoded in {rel_path}. "
                    f"Key pattern matched: '{match.group(0)[:60]}...'"
                ),
                recommendation=(
                    "Move secrets to .env and reference via env('KEY'). "
                    "For frontend code, use a backend API to proxy sensitive calls."
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings
