"""Configuration loader for OorGuard.

Reads an optional `.oorguard.yml` config file from the project root (or a
custom path via --config) and merges with CLI-provided overrides. This lets
users disable specific checks, set ignore paths, and define severity thresholds
without modifying CLI arguments every run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class OorGuardConfig:
    """Parsed OorGuard configuration.

    Attributes:
        disabled_checks: Set of check names to skip (e.g. 'live_exposure').
        ignore_paths: Glob patterns for paths to exclude from scanning.
        min_severity: Minimum severity to include in report output.
        exclude_categories: Categories to skip entirely.
    """

    disabled_checks: set[str] = field(default_factory=set)
    ignore_paths: set[str] = field(default_factory=set)
    min_severity: str = "info"
    exclude_categories: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OorGuardConfig:
        """Create a config from a parsed YAML dict."""
        return cls(
            disabled_checks=set(data.get("disabled_checks", [])),
            ignore_paths=set(data.get("ignore_paths", [])),
            min_severity=data.get("min_severity", "info").lower(),
            exclude_categories=set(data.get("exclude_categories", [])),
        )

    def merge_cli_overrides(
        self,
        min_severity: str | None = None,
        exclude_categories: list[str] | None = None,
    ) -> None:
        """Apply CLI flag overrides on top of file-based config."""
        if min_severity:
            self.min_severity = min_severity.lower()
        if exclude_categories:
            self.exclude_categories.update(exclude_categories)


def load_config(
    config_path: str | Path | None = None,
    project_path: str | Path | None = None,
) -> OorGuardConfig:
    """Load OorGuard config from a YAML file.

    Resolution order:
    1. Explicit --config path (if provided).
    2. `.oorguard.yml` in the project root.
    3. Default config (everything enabled, no ignores).

    Args:
        config_path: Explicit path to a config file.
        project_path: Project root directory to search for `.oorguard.yml`.

    Returns:
        Parsed OorGuardConfig instance.
    """
    paths_to_try: list[Path] = []

    if config_path:
        paths_to_try.append(Path(config_path))
    if project_path:
        paths_to_try.append(Path(project_path) / ".oorguard.yml")
        paths_to_try.append(Path(project_path) / ".oorguard.yaml")

    for path in paths_to_try:
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                return OorGuardConfig.from_dict(data)
            except (yaml.YAMLError, OSError):
                # Malformed or unreadable config — fall through to defaults
                pass

    return OorGuardConfig()
