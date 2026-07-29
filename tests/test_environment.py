"""Unit tests for environment security checks."""

from oorguard.checks import environment
from oorguard.core.context import ScanContext
from oorguard.core.finding import Severity


def test_check_debug_mode(scan_ctx: ScanContext):
    findings = environment.check_debug_mode(scan_ctx)
    critical_debug = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_debug) > 0
    assert "APP_DEBUG is enabled in production" in critical_debug[0].title


def test_check_vite_secrets(scan_ctx: ScanContext):
    findings = environment.check_vite_secrets(scan_ctx)
    vite_findings = [f for f in findings if "VITE_STRIPE_SECRET" in f.title]
    assert len(vite_findings) > 0
    assert vite_findings[0].severity == Severity.CRITICAL
