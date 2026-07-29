"""Package Inventory extractor.

Reads installed PHP (Composer) and JS (NPM) packages from composer.lock, composer.json,
package-lock.json, and package.json. Optionally queries composer/npm outdated to get
available latest versions.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import shutil
import subprocess
from typing import Any

from oorguard.core.context import ScanContext


@dataclass
class PackageInfo:
    """Information about an installed package."""

    name: str
    type: str  # "PHP (Composer)" or "JS (NPM)"
    installed_version: str
    required_version: str = ""
    latest_version: str = ""
    is_dev: bool = False
    status: str = "Up-to-date"  # "Up-to-date", "Outdated", "Unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_installed_packages(ctx: ScanContext, fetch_latest: bool = True) -> list[PackageInfo]:
    """Retrieve all installed Composer and NPM packages in the project."""
    packages: list[PackageInfo] = []
    packages.extend(_get_composer_packages(ctx))
    packages.extend(_get_npm_packages(ctx))

    if fetch_latest and packages:
        _enrich_with_latest_versions(ctx, packages)

    return packages


def _get_composer_packages(ctx: ScanContext) -> list[PackageInfo]:
    packages: list[PackageInfo] = []
    composer_json = ctx.get_composer_json() or {}
    require = composer_json.get("require", {})
    require_dev = composer_json.get("require-dev", {})

    lock = ctx.get_composer_lock()
    if lock:
        for pkg in lock.get("packages", []):
            name = pkg.get("name", "")
            ver = pkg.get("version", "").lstrip("v")
            req = str(require.get(name, ""))
            packages.append(
                PackageInfo(
                    name=name,
                    type="PHP (Composer)",
                    installed_version=ver,
                    required_version=req,
                    is_dev=False,
                )
            )
        for pkg in lock.get("packages-dev", []):
            name = pkg.get("name", "")
            ver = pkg.get("version", "").lstrip("v")
            req = str(require_dev.get(name, ""))
            packages.append(
                PackageInfo(
                    name=name,
                    type="PHP (Composer)",
                    installed_version=ver,
                    required_version=req,
                    is_dev=True,
                )
            )
    elif composer_json:
        for name, req in require.items():
            if name != "php" and not name.startswith("ext-"):
                packages.append(
                    PackageInfo(
                        name=name,
                        type="PHP (Composer)",
                        installed_version="installed",
                        required_version=str(req),
                        is_dev=False,
                    )
                )
        for name, req in require_dev.items():
            packages.append(
                PackageInfo(
                    name=name,
                    type="PHP (Composer)",
                    installed_version="installed",
                    required_version=str(req),
                    is_dev=True,
                )
            )

    return packages


def _get_npm_packages(ctx: ScanContext) -> list[PackageInfo]:
    packages: list[PackageInfo] = []
    pkg_json = ctx.get_package_json() or {}
    deps = pkg_json.get("dependencies", {})
    dev_deps = pkg_json.get("devDependencies", {})

    lock = ctx.read_json("package-lock.json")
    lock_packages: dict[str, str] = {}

    if lock:
        if "packages" in lock and isinstance(lock["packages"], dict):
            for k, v in lock["packages"].items():
                if isinstance(v, dict) and k.startswith("node_modules/"):
                    pkg_name = k[len("node_modules/"):]
                    if "/" not in pkg_name or (pkg_name.startswith("@") and pkg_name.count("/") == 1):
                        lock_packages[pkg_name] = v.get("version", "")
        elif "dependencies" in lock and isinstance(lock["dependencies"], dict):
            for k, v in lock["dependencies"].items():
                if isinstance(v, dict):
                    lock_packages[k] = v.get("version", "")

    for name, req in deps.items():
        installed_ver = lock_packages.get(name, "")
        packages.append(
            PackageInfo(
                name=name,
                type="JS (NPM)",
                installed_version=installed_ver or "installed",
                required_version=str(req),
                is_dev=False,
            )
        )

    for name, req in dev_deps.items():
        installed_ver = lock_packages.get(name, "")
        packages.append(
            PackageInfo(
                name=name,
                type="JS (NPM)",
                installed_version=installed_ver or "installed",
                required_version=str(req),
                is_dev=True,
            )
        )

    return packages


def _enrich_with_latest_versions(ctx: ScanContext, packages: list[PackageInfo]) -> None:
    pkg_map = {p.name: p for p in packages}

    # Try composer outdated --format=json
    composer_bin = shutil.which("composer")
    if composer_bin and ctx.file_exists("composer.lock"):
        try:
            res = subprocess.run(
                [composer_bin, "outdated", "--format=json", "--no-interaction"],
                capture_output=True,
                text=True,
                cwd=str(ctx.project_path),
                timeout=10,
            )
            if res.stdout.strip():
                data = json.loads(res.stdout.strip())
                for item in data.get("installed", []):
                    name = item.get("name")
                    latest = item.get("latest", "").lstrip("v")
                    if name in pkg_map and latest:
                        pkg_map[name].latest_version = latest
                        if pkg_map[name].installed_version != latest:
                            pkg_map[name].status = "Outdated"
        except Exception:
            pass

    # Try npm outdated --json
    npm_bin = shutil.which("npm")
    if npm_bin and ctx.file_exists("package-lock.json"):
        try:
            res = subprocess.run(
                [npm_bin, "outdated", "--json"],
                capture_output=True,
                text=True,
                cwd=str(ctx.project_path),
                timeout=10,
            )
            if res.stdout.strip():
                data = json.loads(res.stdout.strip())
                for name, info in data.items():
                    if isinstance(info, dict) and name in pkg_map:
                        latest = info.get("latest", "")
                        if latest:
                            pkg_map[name].latest_version = latest
                            if pkg_map[name].installed_version != latest:
                                pkg_map[name].status = "Outdated"
        except Exception:
            pass

    # Fill in latest_version default if empty
    for p in packages:
        if not p.latest_version and p.installed_version and p.installed_version != "installed":
            p.latest_version = p.installed_version
