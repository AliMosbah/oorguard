"""Livewire Security checks.

Detects Livewire-specific vulnerabilities: exposed sensitive properties,
missing #[Locked] attributes, public methods callable from frontend without
authorization, unsafe file uploads, and unprotected search/filter properties.
"""

from __future__ import annotations

import re
from pathlib import Path

from oorguard.core.context import ScanContext
from oorguard.core.finding import Finding, Severity
from oorguard.core.registry import register_check


# Properties that should almost always be protected with #[Locked]
_SENSITIVE_PROPERTY_NAMES: set[str] = {
    "user_id", "userId", "role", "roles", "is_admin", "isAdmin",
    "permissions", "email", "password", "token", "api_key", "apiKey",
    "secret", "price", "total", "amount", "discount", "order_id",
    "orderId", "payment", "balance", "credit", "account_id", "accountId",
}

# Methods that suggest authorization-sensitive actions
_SENSITIVE_METHOD_NAMES: set[str] = {
    "delete", "destroy", "remove", "approve", "reject", "ban",
    "suspend", "promote", "demote", "changeRole", "setAdmin",
    "updateRole", "resetPassword", "forceDelete", "restore",
    "publish", "unpublish", "activate", "deactivate", "impersonate",
    "transfer", "refund", "payout",
}


@register_check(
    category="Livewire",
    name="livewire_public_properties",
    description="Flags Livewire components exposing sensitive data via public properties without #[Locked].",
)
def check_public_properties(ctx: ScanContext) -> list[Finding]:
    """Detect sensitive public properties in Livewire components.

    All public properties in a Livewire component are visible to the frontend
    AND can be modified by the client via wire:model or direct JS manipulation.
    Sensitive properties must use #[Locked] to prevent client-side tampering.
    """
    findings: list[Finding] = []

    livewire_files = _find_livewire_components(ctx)

    # Pattern: public $propertyName (with optional type hint)
    public_prop_pattern = re.compile(
        r"""^\s*public\s+(?:\??\w+\s+)?\$(\w+)""",
        re.MULTILINE,
    )
    locked_pattern = re.compile(r"""#\[Locked\]""")

    for file_path in livewire_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)
        lines = content.splitlines()

        for match in public_prop_pattern.finditer(content):
            prop_name = match.group(1)
            line_num = content[:match.start()].count("\n") + 1

            # Check if property name looks sensitive
            if prop_name.lower() not in {s.lower() for s in _SENSITIVE_PROPERTY_NAMES}:
                continue

            # Check if #[Locked] is on the line above
            if line_num >= 2:
                prev_line = lines[line_num - 2].strip()
                if "#[Locked]" in prev_line:
                    continue

            # Check for #[Locked] anywhere near this property (within 3 lines above)
            start_check = max(0, line_num - 4)
            context_block = "\n".join(lines[start_check:line_num])
            if locked_pattern.search(context_block):
                continue

            findings.append(Finding(
                severity=Severity.HIGH,
                category="Livewire",
                title=f"Sensitive property '${prop_name}' without #[Locked]",
                description=(
                    f"Livewire component {rel_path} exposes '${prop_name}' as a "
                    f"public property without the #[Locked] attribute. Any public "
                    f"property in Livewire can be modified from the frontend via "
                    f"JavaScript or wire:model, allowing users to tamper with "
                    f"values like user IDs, prices, or roles."
                ),
                recommendation=(
                    f"Add #[Locked] above the property to prevent client-side modification:\n"
                    f"  #[Locked]\n"
                    f"  public ${prop_name};"
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="Livewire",
    name="livewire_unprotected_methods",
    description="Flags public methods in Livewire components that perform sensitive actions without authorization.",
)
def check_unprotected_methods(ctx: ScanContext) -> list[Finding]:
    """Detect public methods callable from frontend without authorization checks.

    Every public method in a Livewire component can be called directly from
    the browser. Methods that perform destructive or privileged actions must
    include authorization checks (Gate, Policy, or manual checks).
    """
    findings: list[Finding] = []

    livewire_files = _find_livewire_components(ctx)

    # Pattern: public function methodName(
    public_method_pattern = re.compile(
        r"""^\s*public\s+function\s+(\w+)\s*\(""",
        re.MULTILINE,
    )

    # Authorization patterns to look for in method body
    auth_patterns = [
        re.compile(r"""(?:\$this->)?authorize\s*\("""),
        re.compile(r"""Gate::(?:allows|denies|check|authorize)\s*\("""),
        re.compile(r"""can\s*\("""),
        re.compile(r"""cannot\s*\("""),
        re.compile(r"""abort_if\s*\("""),
        re.compile(r"""abort_unless\s*\("""),
        re.compile(r"""current_user_can"""),
        re.compile(r"""policy\s*\("""),
        re.compile(r"""\$this->authorize"""),
    ]

    for file_path in livewire_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        for match in public_method_pattern.finditer(content):
            method_name = match.group(1)
            line_num = content[:match.start()].count("\n") + 1

            # Skip Livewire lifecycle methods
            if method_name in (
                "mount", "render", "hydrate", "dehydrate", "boot",
                "updated", "updating", "created", "rules", "messages",
                "validationAttributes", "resetValidation", "getListeners",
                "__construct", "placeholder",
            ) or method_name.startswith("updated") or method_name.startswith("updating"):
                continue

            # Check if method name suggests a sensitive action
            is_sensitive = method_name.lower() in {s.lower() for s in _SENSITIVE_METHOD_NAMES}
            if not is_sensitive:
                continue

            # Extract method body (approximate: from method declaration to next method or closing brace)
            method_start = match.start()
            next_method = public_method_pattern.search(content, match.end())
            method_end = next_method.start() if next_method else len(content)
            method_body = content[method_start:method_end]

            # Check for authorization patterns
            has_auth = any(p.search(method_body) for p in auth_patterns)

            if not has_auth:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="Livewire",
                    title=f"Sensitive method '{method_name}()' without authorization",
                    description=(
                        f"Livewire component {rel_path} has a public method "
                        f"'{method_name}()' that appears to perform a sensitive "
                        f"action but doesn't include authorization checks. "
                        f"Any public method in a Livewire component can be called "
                        f"directly from the browser by any authenticated user."
                    ),
                    recommendation=(
                        f"Add authorization before the action:\n"
                        f"  public function {method_name}()\n"
                        f"  {{\n"
                        f"      $this->authorize('{method_name}', $this->model);\n"
                        f"      // ... action logic\n"
                        f"  }}"
                    ),
                    file=rel_path,
                    line=line_num,
                ))

    return findings


@register_check(
    category="Livewire",
    name="livewire_file_uploads",
    description="Checks Livewire file upload handling for missing validation.",
)
def check_file_uploads(ctx: ScanContext) -> list[Finding]:
    """Detect Livewire file uploads without proper validation.

    Livewire's WithFileUploads trait allows file uploads. Without proper
    validation (mime types, size limits), attackers can upload malicious
    files (PHP shells, oversized files for DoS).
    """
    findings: list[Finding] = []

    livewire_files = _find_livewire_components(ctx)

    upload_trait = re.compile(r"""use\s+WithFileUploads""")
    validation_pattern = re.compile(
        r"""['"](?:file|image|mimes|mimetypes|max|dimensions)""",
    )
    rules_pattern = re.compile(r"""(?:rules|validate)\s*\(""")

    for file_path in livewire_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        if not upload_trait.search(content):
            continue

        rel_path = ctx.relative_path(file_path)

        # Check if there's file validation
        has_file_validation = validation_pattern.search(content)
        has_rules = rules_pattern.search(content)

        if not has_file_validation:
            line_match = upload_trait.search(content)
            line_num = content[:line_match.start()].count("\n") + 1 if line_match else 1

            findings.append(Finding(
                severity=Severity.HIGH,
                category="Livewire",
                title="File upload without type/size validation",
                description=(
                    f"Livewire component {rel_path} uses WithFileUploads but "
                    f"no file validation rules (mimes, max size, image) were "
                    f"detected. Without validation, users can upload:\n"
                    f"• Executable files (PHP shells, .exe)\n"
                    f"• Oversized files (DoS via disk/memory exhaustion)\n"
                    f"• Files with misleading extensions"
                ),
                recommendation=(
                    "Add validation rules for file properties:\n"
                    "  public function rules() {\n"
                    "      return ['photo' => 'required|image|mimes:jpg,png,webp|max:2048'];\n"
                    "  }\n"
                    "Or validate inline:\n"
                    "  $this->validate(['photo' => 'image|max:2048']);"
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="Livewire",
    name="livewire_sql_injection",
    description="Detects Livewire search/filter properties used directly in raw queries.",
)
def check_livewire_sql_injection(ctx: ScanContext) -> list[Finding]:
    """Detect SQL injection via Livewire properties in raw queries.

    Livewire properties bound via wire:model are user-controlled. Using them
    directly in raw SQL queries (whereRaw, DB::raw) is a SQL injection vector.
    """
    findings: list[Finding] = []

    livewire_files = _find_livewire_components(ctx)

    # Common Livewire search/filter property names
    search_props = re.compile(
        r"""public\s+(?:string\s+)?\$(?:search|query|filter|keyword|term|q)\b""",
    )

    raw_query_with_prop = re.compile(
        r"""(?:whereRaw|selectRaw|orderByRaw|groupByRaw|havingRaw|DB::raw)\s*\(\s*['"].*?\$(?:this->)?(?:search|query|filter|keyword|term|q)""",
        re.DOTALL,
    )

    for file_path in livewire_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        if not search_props.search(content):
            continue

        rel_path = ctx.relative_path(file_path)

        for match in raw_query_with_prop.finditer(content):
            line_num = content[:match.start()].count("\n") + 1

            findings.append(Finding(
                severity=Severity.CRITICAL,
                category="Livewire",
                title="SQL injection via Livewire search property",
                description=(
                    f"Livewire component {rel_path} uses a search/filter property "
                    f"directly in a raw SQL query. Livewire properties are "
                    f"user-controlled via wire:model — using them in raw SQL "
                    f"without parameter binding is a SQL injection vulnerability."
                ),
                recommendation=(
                    "Use parameter bindings:\n"
                    "  ->whereRaw('column LIKE ?', ['%' . $this->search . '%'])\n"
                    "Or better yet, use Eloquent:\n"
                    "  ->where('column', 'like', '%' . $this->search . '%')"
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="Livewire",
    name="livewire_model_binding",
    description="Flags wire:model.live on sensitive form fields in Blade views.",
)
def check_wire_model_exposure(ctx: ScanContext) -> list[Finding]:
    """Detect wire:model on sensitive fields that should use .blur or .defer.

    wire:model.live sends every keystroke to the server in real-time.
    For sensitive fields (passwords, credit cards), this creates unnecessary
    network traffic containing sensitive data. Use .blur or .submit instead.
    """
    findings: list[Finding] = []

    blade_files = ctx.get_files(".blade.php")

    # wire:model.live on password/sensitive fields
    sensitive_wire_pattern = re.compile(
        r"""wire:model\.live\s*=\s*['"](\w*(?:password|secret|token|credit|card|cvv|ssn|pin)\w*)['"]""",
        re.IGNORECASE,
    )

    for file_path in blade_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)

        for match in sensitive_wire_pattern.finditer(content):
            prop_name = match.group(1)
            line_num = content[:match.start()].count("\n") + 1

            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="Livewire",
                title=f"wire:model.live on sensitive field '{prop_name}'",
                description=(
                    f"In {rel_path}, wire:model.live is used on a sensitive "
                    f"field '{prop_name}'. This sends every keystroke to the "
                    f"server in real-time, meaning partial sensitive data "
                    f"(passwords, credit card numbers) is transmitted with "
                    f"every character typed."
                ),
                recommendation=(
                    f"Use wire:model.blur (sends on focus loss) or "
                    f"wire:model (deferred, sends on action) for sensitive fields:\n"
                    f"  wire:model.blur=\"{prop_name}\""
                ),
                file=rel_path,
                line=line_num,
            ))

    return findings


@register_check(
    category="Livewire",
    name="livewire_rate_limiting",
    description="Checks for rate limiting on Livewire action methods.",
)
def check_rate_limiting(ctx: ScanContext) -> list[Finding]:
    """Flag Livewire components without rate limiting on action methods.

    Livewire actions can be called rapidly from the browser. Without rate
    limiting, attackers can abuse actions like email sending, form submissions,
    or API calls. This is informational — not all components need rate limiting.
    """
    findings: list[Finding] = []

    livewire_files = _find_livewire_components(ctx)

    # Methods that typically need rate limiting
    rate_sensitive_methods = {
        "submit", "send", "sendEmail", "sendNotification", "register",
        "login", "resetPassword", "verify", "resend", "charge", "pay",
        "export", "import", "generate", "process",
    }

    public_method_pattern = re.compile(
        r"""^\s*public\s+function\s+(\w+)\s*\(""",
        re.MULTILINE,
    )

    rate_limit_patterns = [
        re.compile(r"""RateLimiter"""),
        re.compile(r"""throttle"""),
        re.compile(r"""RateLimit"""),
        re.compile(r"""rate_limit"""),
        re.compile(r"""sleep\s*\("""),
    ]

    for file_path in livewire_files:
        content = ctx.read_file(file_path)
        if content is None:
            continue

        rel_path = ctx.relative_path(file_path)
        has_rate_limit = any(p.search(content) for p in rate_limit_patterns)

        if has_rate_limit:
            continue

        for match in public_method_pattern.finditer(content):
            method_name = match.group(1)

            if method_name.lower() in {s.lower() for s in rate_sensitive_methods}:
                line_num = content[:match.start()].count("\n") + 1

                findings.append(Finding(
                    severity=Severity.LOW,
                    category="Livewire",
                    title=f"Action '{method_name}()' without rate limiting",
                    description=(
                        f"Livewire component {rel_path} has an action method "
                        f"'{method_name}()' that may benefit from rate limiting. "
                        f"Without it, users can trigger this action rapidly, "
                        f"potentially causing email spam, resource exhaustion, "
                        f"or brute-force attacks."
                    ),
                    recommendation=(
                        "Add rate limiting:\n"
                        "  use Illuminate\\Support\\Facades\\RateLimiter;\n\n"
                        f"  public function {method_name}()\n"
                        "  {\n"
                        "      $executed = RateLimiter::attempt(\n"
                        f"          'action:' . auth()->id(), 5, function () {{\n"
                        "              // ... action logic\n"
                        "          }\n"
                        "      );\n"
                        "      if (!$executed) {\n"
                        "          session()->flash('error', 'Too many attempts.');\n"
                        "      }\n"
                        "  }"
                    ),
                    file=rel_path,
                    line=line_num,
                ))

    return findings


def _find_livewire_components(ctx: ScanContext) -> list[Path]:
    """Find all Livewire component PHP files in the project.

    Livewire components are typically in:
    - app/Livewire/ (Laravel 11+)
    - app/Http/Livewire/ (older convention)

    Also detects any PHP file that extends Component from Livewire.
    """
    livewire_dirs = ["app/Livewire", "app/Http/Livewire"]
    files: list[Path] = []

    for lw_dir in livewire_dirs:
        dir_files = ctx.get_files_in(lw_dir, ".php")
        files.extend(dir_files)

    if files:
        return files

    # Fallback: scan all PHP files for Livewire Component usage
    all_php = ctx.get_files_in("app", ".php")
    livewire_pattern = re.compile(
        r"""(?:extends\s+Component|use\s+Livewire\\|use\s+.*\\Component)"""
    )

    return [
        f for f in all_php
        if (content := ctx.read_file(f)) and livewire_pattern.search(content)
    ]
