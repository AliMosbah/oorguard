"""Unit tests for Livewire security checks."""

from oorguard.checks import livewire
from oorguard.core.context import ScanContext
from oorguard.core.finding import Severity


def test_check_public_properties(scan_ctx: ScanContext):
    findings = livewire.check_public_properties(scan_ctx)
    user_id_findings = [f for f in findings if "$user_id" in f.title]
    assert len(user_id_findings) > 0
    assert user_id_findings[0].severity == Severity.HIGH


def test_check_unprotected_methods(scan_ctx: ScanContext):
    findings = livewire.check_unprotected_methods(scan_ctx)
    delete_findings = [f for f in findings if "delete()" in f.title]
    assert len(delete_findings) > 0


def test_check_livewire_sql_injection(scan_ctx: ScanContext):
    findings = livewire.check_livewire_sql_injection(scan_ctx)
    sql_findings = [f for f in findings if "SQL injection" in f.title]
    assert len(sql_findings) > 0
    assert sql_findings[0].severity == Severity.CRITICAL
