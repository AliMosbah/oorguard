"""ScanContext — project path, configuration, and cached file operations.

ScanContext is the shared state object passed to every check module. It caches
the project file tree on first access (excluding vendor/, node_modules/, .git/)
and provides helper methods for reading files and matching paths by pattern.
"""

from __future__ import annotations

import os
import fnmatch
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from oorguard.core.config import OorGuardConfig


# Directories always excluded from scanning
_EXCLUDED_DIRS: frozenset[str] = frozenset({
    "vendor",
    "node_modules",
    ".git",
    "__pycache__",
    ".idea",
    ".vscode",
})


class ScanContext:
    """Shared context passed to every security check.

    Attributes:
        project_path: Absolute path to the Laravel project root.
        config: Loaded OorGuard configuration.
        base_url: Optional base URL for live exposure checks.
        verbose: Whether to print per-check progress detail.
    """

    def __init__(
        self,
        project_path: str | Path,
        config: OorGuardConfig | None = None,
        base_url: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.project_path: Path = Path(project_path).resolve()
        self.config: OorGuardConfig = config or OorGuardConfig()
        self.base_url: str | None = base_url
        self.verbose: bool = verbose
        self._file_cache: list[Path] | None = None

        if not self.project_path.is_dir():
            raise FileNotFoundError(
                f"Project path does not exist or is not a directory: {self.project_path}"
            )

    @property
    def all_files(self) -> list[Path]:
        """Lazily cached list of all project files (excluding ignored dirs)."""
        if self._file_cache is None:
            self._file_cache = self._walk_project()
        return self._file_cache

    def _walk_project(self) -> list[Path]:
        """Walk the project tree, respecting exclusions."""
        files: list[Path] = []
        ignore_paths = set(self.config.ignore_paths)

        for dirpath, dirnames, filenames in os.walk(self.project_path):
            # Prune excluded directories in-place (modifying dirnames affects os.walk)
            dirnames[:] = [
                d for d in dirnames
                if d not in _EXCLUDED_DIRS
                and not any(fnmatch.fnmatch(d, p) for p in ignore_paths)
            ]
            for filename in filenames:
                full_path = Path(dirpath) / filename
                rel_path = full_path.relative_to(self.project_path)
                if not any(fnmatch.fnmatch(str(rel_path), p) for p in ignore_paths):
                    files.append(full_path)
        return files

    def get_files(self, *extensions: str) -> list[Path]:
        """Return project files matching one or more extensions.

        Args:
            extensions: File extensions including the dot (e.g. '.php', '.blade.php').
        """
        if not extensions:
            return self.all_files
        return [
            f for f in self.all_files
            if any(f.name.endswith(ext) for ext in extensions)
        ]

    def get_files_in(self, subdir: str, *extensions: str) -> list[Path]:
        """Return files under a specific subdirectory, optionally filtered by extension."""
        target = self.project_path / subdir
        files = [f for f in self.all_files if f.is_relative_to(target)]
        if extensions:
            files = [f for f in files if any(f.name.endswith(ext) for ext in extensions)]
        return files

    def read_file(self, path: str | Path) -> str | None:
        """Read a file's content, returning None if it doesn't exist or can't be read."""
        full_path = self._resolve_path(path)
        try:
            return full_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

    def read_json(self, path: str | Path) -> dict[str, Any] | None:
        """Read and parse a JSON file, returning None on failure."""
        content = self.read_file(path)
        if content is None:
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def file_exists(self, path: str | Path) -> bool:
        """Check if a file exists relative to the project root."""
        return self._resolve_path(path).exists()

    def dir_exists(self, path: str | Path) -> bool:
        """Check if a directory exists relative to the project root."""
        return self._resolve_path(path).is_dir()

    def relative_path(self, path: str | Path) -> str:
        """Convert an absolute path to a project-relative string."""
        full_path = Path(path).resolve()
        try:
            return str(full_path.relative_to(self.project_path))
        except ValueError:
            return str(full_path)

    def _resolve_path(self, path: str | Path) -> Path:
        """Resolve a path — if relative, join with project root."""
        p = Path(path)
        if p.is_absolute():
            return p
        return self.project_path / p

    @lru_cache(maxsize=1)
    def get_composer_lock(self) -> dict[str, Any] | None:
        """Read and cache composer.lock contents."""
        return self.read_json("composer.lock")

    @lru_cache(maxsize=1)
    def get_composer_json(self) -> dict[str, Any] | None:
        """Read and cache composer.json contents."""
        return self.read_json("composer.json")

    @lru_cache(maxsize=1)
    def get_package_json(self) -> dict[str, Any] | None:
        """Read and cache package.json contents."""
        return self.read_json("package.json")

    @lru_cache(maxsize=1)
    def get_laravel_version(self) -> str | None:
        """Extract Laravel framework version from composer.lock."""
        lock = self.get_composer_lock()
        if lock is None:
            return None
        for package in lock.get("packages", []):
            if package.get("name") == "laravel/framework":
                return package.get("version", "").lstrip("v")
        return None

    def get_env_values(self, filename: str = ".env") -> dict[str, str]:
        """Parse a .env file into a key=value dict (ignores comments and empty lines)."""
        content = self.read_file(filename)
        if content is None:
            return {}
        values: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                # Strip surrounding quotes from value
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                values[key] = value
        return values
