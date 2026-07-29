"""Fixture Laravel project helper for pytest."""

import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path for pytest discovery
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from oorguard.core.context import ScanContext
from oorguard.core.config import OorGuardConfig


@pytest.fixture
def fixture_dir() -> Path:
    """Return the absolute path to tests/fixtures/mock_laravel, ensuring it exists."""
    path = Path(__file__).parent / "fixtures" / "mock_laravel"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def scan_ctx(fixture_dir: Path) -> ScanContext:
    """Create a ScanContext pointing to the mock Laravel fixture directory."""
    return ScanContext(project_path=fixture_dir, config=OorGuardConfig())
