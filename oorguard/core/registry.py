"""Plugin-style check registry for OorGuard.

Each check module uses the @register_check decorator to register itself.
The engine queries this registry at scan time to discover and run all checks.

Usage in a check module:

    from oorguard.core.registry import register_check
    from oorguard.core.context import ScanContext
    from oorguard.core.finding import Finding

    @register_check(category="Environment", name="env_debug_check")
    def run(ctx: ScanContext) -> list[Finding]:
        ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Any

from oorguard.core.finding import Finding


# Type alias for a check function
CheckFunction = Callable[..., list[Finding]]


@dataclass(frozen=True, slots=True)
class CheckInfo:
    """Metadata for a registered check.

    Attributes:
        name: Unique identifier for the check.
        category: Grouping label (e.g. 'Environment', 'Dependencies').
        description: One-line description of what the check detects.
        func: The callable that runs the check.
    """

    name: str
    category: str
    description: str
    func: CheckFunction


# Global registry — populated at import time via @register_check
_registry: list[CheckInfo] = []


def register_check(
    category: str,
    name: str,
    description: str = "",
) -> Callable[[CheckFunction], CheckFunction]:
    """Decorator to register a check function in the global registry.

    Args:
        category: Category label for grouping in reports.
        name: Unique check name (used in config to disable).
        description: Human-readable summary for `list-checks` output.

    Returns:
        The original function, unmodified.
    """

    def decorator(func: CheckFunction) -> CheckFunction:
        _registry.append(
            CheckInfo(
                name=name,
                category=category,
                description=description or func.__doc__ or "",
                func=func,
            )
        )
        return func

    return decorator


def get_all_checks() -> list[CheckInfo]:
    """Return all registered checks."""
    return list(_registry)


def get_checks_by_category(category: str) -> list[CheckInfo]:
    """Return checks filtered to a specific category."""
    return [c for c in _registry if c.category == category]


def get_check_by_name(name: str) -> CheckInfo | None:
    """Return a single check by name, or None if not found."""
    for check in _registry:
        if check.name == name:
            return check
    return None


def get_categories() -> list[str]:
    """Return a sorted list of unique category names."""
    return sorted({c.category for c in _registry})
