"""Fixture Laravel project helper for pytest."""

from pathlib import Path
import pytest
from oorguard.core.context import ScanContext
from oorguard.core.config import OorGuardConfig


@pytest.fixture
def fixture_dir() -> Path:
    """Return the absolute path to tests/fixtures/mock_laravel."""
    return Path(__file__).parent / "fixtures" / "mock_laravel"


@pytest.fixture
def scan_ctx(fixture_dir: Path) -> ScanContext:
    """Create a ScanContext pointing to the mock Laravel fixture directory."""
    return ScanContext(project_path=fixture_dir, config=OorGuardConfig())
