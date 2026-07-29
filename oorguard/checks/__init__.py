"""Security checks package — all check modules auto-register via the decorator.

Importing this package triggers the import of every check module, which in turn
registers each check in the global registry via @register_check.
"""

from oorguard.checks import (
    environment,
    file_exposure,
    dependency_audit,
    laravel_core,
    code_patterns,
    secrets_scanner,
    inertia,
    react_frontend,
    ssr,
    live_exposure,
    livewire,
)

__all__ = [
    "environment",
    "file_exposure",
    "dependency_audit",
    "laravel_core",
    "code_patterns",
    "secrets_scanner",
    "inertia",
    "react_frontend",
    "ssr",
    "live_exposure",
    "livewire",
]
