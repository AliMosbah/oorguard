"""Unit tests for Laravel core security checks."""

from oorguard.checks import laravel_core
from oorguard.core.context import ScanContext
from oorguard.core.finding import Severity


def test_check_mass_assignment(scan_ctx: ScanContext):
    findings = laravel_core.check_mass_assignment(scan_ctx)
    guarded_findings = [f for f in findings if "$guarded = []" in f.title]
    assert len(guarded_findings) > 0
    assert guarded_findings[0].file.endswith("Post.php")
