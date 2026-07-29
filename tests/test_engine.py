"""Unit tests for the scan engine and packages module."""

from oorguard.core.context import ScanContext
from oorguard.core.engine import ScanEngine
from oorguard.core.packages import get_installed_packages


def test_scan_engine(scan_ctx: ScanContext):
    engine = ScanEngine(ctx=scan_ctx)
    findings = engine.run()
    assert isinstance(findings, list)
    assert len(findings) > 0


def test_get_installed_packages(scan_ctx: ScanContext):
    packages = get_installed_packages(scan_ctx, fetch_latest=False)
    assert isinstance(packages, list)
