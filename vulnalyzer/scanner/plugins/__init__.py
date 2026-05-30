"""
vulnalyzer.scanner.plugins
===========================
Plugin registry.

All ``ManifestPlugin`` subclasses defined in this package are auto-registered.
Adding a new ecosystem is as simple as:
  1. Create a new module in this folder.
  2. Subclass ``ManifestPlugin``.
  3. Import it here.

Registered ecosystems
---------------------
  npm        — package.json, package-lock.json, yarn.lock
  PyPI       — requirements.txt, pyproject.toml, setup.cfg
  Maven      — pom.xml
  Go         — go.mod, go.sum
  crates.io  — Cargo.toml, Cargo.lock
  NuGet      — packages.config, project.csproj, project.fsproj,
               Directory.Packages.props, packages.lock.json
"""

from __future__ import annotations

from .base import ManifestPlugin, DependencyInfo
from .npm import PackageJsonPlugin, PackageLockPlugin, YarnLockPlugin
from .pypi import RequirementsTxtPlugin, PyprojectTomlPlugin, SetupCfgPlugin
from .maven import PomXmlPlugin
from .go import GoModPlugin, GoSumPlugin
from .crates import CargoTomlPlugin, CargoLockPlugin
from .nuget import (
    PackagesConfigPlugin,
    CsProjPlugin,
    DirectoryPackagesPropsPlugin,
    NuGetLockJsonPlugin,
)

# Master registry: filename -> plugin instance
_REGISTRY: dict[str, ManifestPlugin] = {}


def _register(plugin: ManifestPlugin) -> None:
    for filename in plugin.manifest_files:
        _REGISTRY[filename] = plugin


# ── npm ──────────────────────────────────────────────────────────────────────
_register(PackageJsonPlugin())
_register(PackageLockPlugin())
_register(YarnLockPlugin())

# ── PyPI ─────────────────────────────────────────────────────────────────────
_register(RequirementsTxtPlugin())
_register(PyprojectTomlPlugin())
_register(SetupCfgPlugin())

# ── Maven ────────────────────────────────────────────────────────────────────
_register(PomXmlPlugin())

# ── Go ───────────────────────────────────────────────────────────────────────
_register(GoModPlugin())
_register(GoSumPlugin())

# ── crates.io ────────────────────────────────────────────────────────────────
_register(CargoTomlPlugin())
_register(CargoLockPlugin())

# ── NuGet ────────────────────────────────────────────────────────────────────
_register(PackagesConfigPlugin())
_register(CsProjPlugin())
_register(DirectoryPackagesPropsPlugin())
_register(NuGetLockJsonPlugin())


def get_plugin_for_file(filename: str) -> ManifestPlugin | None:
    return _REGISTRY.get(filename)


def all_manifest_filenames() -> list[str]:
    """Return every filename that at least one plugin handles."""
    return list(_REGISTRY.keys())


__all__ = [
    "ManifestPlugin",
    "DependencyInfo",
    "get_plugin_for_file",
    "all_manifest_filenames",
]
