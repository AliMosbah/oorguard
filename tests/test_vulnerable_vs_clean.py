"""Integration test comparing vulnerable_project vs clean_project."""

from pathlib import Path
from oorguard.core.context import ScanContext
from oorguard.core.config import OorGuardConfig
from oorguard.core.engine import ScanEngine
from oorguard.core.finding import Severity


def test_clean_project_has_no_critical_or_high_findings():
    clean_path = Path(__file__).parent / "fixtures" / "clean_project"
    ctx = ScanContext(project_path=clean_path, config=OorGuardConfig())
    engine = ScanEngine(ctx=ctx)
    findings = engine.run()

    critical_or_high = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(critical_or_high) == 0


def test_mock_laravel_has_findings():
    vulnerable_path = Path(__file__).parent / "fixtures" / "mock_laravel"
    ctx = ScanContext(project_path=vulnerable_path, config=OorGuardConfig())
    engine = ScanEngine(ctx=ctx)
    findings = engine.run()

    assert len(findings) > 0
    categories = {f.category for f in findings}
    assert "Environment" in categories
    assert "Laravel Core" in categories
