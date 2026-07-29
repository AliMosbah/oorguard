"""Core engine, data models, and configuration for OorGuard."""

from oorguard.core.finding import Finding, Severity
from oorguard.core.context import ScanContext
from oorguard.core.registry import register_check, get_all_checks
from oorguard.core.packages import PackageInfo, get_installed_packages

__all__ = [
    "Finding",
    "Severity",
    "ScanContext",
    "register_check",
    "get_all_checks",
    "PackageInfo",
    "get_installed_packages",
]
