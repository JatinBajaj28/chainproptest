"""
vulnalyzer.scanner.plugins.nuget
==================================
Plugins for NuGet / .NET dependency manifests:
  - packages.config         (classic NuGet format)
  - *.csproj / *.fsproj     (SDK-style PackageReference)
  - Directory.Packages.props (central package version management)
  - nuget.lock.json          (NuGet lock file — requires <RestorePackagesWithLockFile>true)

OSV ecosystem name for NuGet is "NuGet".

References:
  https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files
  https://learn.microsoft.com/en-us/nuget/reference/packages-config
  https://learn.microsoft.com/en-us/nuget/consume-packages/central-package-management
"""

from __future__ import annotations

import json
import logging
import re

from .base import ManifestPlugin, DependencyInfo

logger = logging.getLogger(__name__)


class PackagesConfigPlugin(ManifestPlugin):
    """
    Parses the legacy ``packages.config`` XML format::

        <?xml version="1.0" encoding="utf-8"?>
        <packages>
          <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
        </packages>

    All packages are treated as direct (packages.config has no transitive model).
    ``developmentDependency="true"`` entries are flagged as dev.
    """

    manifest_files = ["packages.config"]
    ecosystem = "NuGet"

    _PKG_RE = re.compile(
        r'<package\b[^>]*\bid\s*=\s*"(?P<id>[^"]+)"'
        r'[^>]*\bversion\s*=\s*"(?P<version>[^"]+)"'
        r'(?P<rest>[^>]*)>?',
        re.IGNORECASE,
    )
    _DEV_RE = re.compile(r'developmentDependency\s*=\s*"true"', re.IGNORECASE)

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        for m in self._PKG_RE.finditer(text):
            pkg_id  = m.group("id")
            version = m.group("version")
            rest    = m.group("rest") + m.group(0)  # search dev flag in full tag
            is_dev  = bool(self._DEV_RE.search(m.group(0)))

            deps[pkg_id] = DependencyInfo(
                version=version,
                source="packages.config",
                is_direct=True,
                is_dev=is_dev,
                depth=1,
                dependency_path=[pkg_id],
            )

        return deps


class CsProjPlugin(ManifestPlugin):
    """
    Parses SDK-style ``.csproj`` / ``.fsproj`` files for ``<PackageReference>`` items::

        <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
        <PackageReference Include="xunit" Version="2.4.2">
          <PrivateAssets>all</PrivateAssets>
        </PackageReference>

    ``<PrivateAssets>all</PrivateAssets>`` conventionally marks dev/test-only packages.

    Note: The plugin is registered under the fixed filename ``project.csproj`` as a
    sentinel, but the engine's manifest-discovery step matches any ``*.csproj`` /
    ``*.fsproj`` via the ``_EXTRA_PATTERNS`` list below (see plugin ``__init__``).
    For the registry-based lookup we register ``project.csproj`` and let the engine
    fall back to it for any ``.csproj`` file.
    """

    # Registered as a sentinel; the engine discovers *.csproj paths via the tree API.
    manifest_files = ["project.csproj", "project.fsproj"]
    ecosystem = "NuGet"

    # Matches self-closing AND open <PackageReference … /> or <PackageReference …>
    _PKG_REF_RE = re.compile(
        r"<PackageReference\b[^>]*\bInclude\s*=\s*\"(?P<id>[^\"]+)\""
        r"[^>]*(?:Version\s*=\s*\"(?P<ver_attr>[^\"]*)\"|)"
        r"[^>]*>?(?P<inner>.*?)</PackageReference>|"
        r"<PackageReference\b[^>]*\bInclude\s*=\s*\"(?P<id2>[^\"]+)\""
        r"[^>]*\bVersion\s*=\s*\"(?P<ver_attr2>[^\"]*)\"[^/]*/?>",
        re.DOTALL | re.IGNORECASE,
    )
    # Inline version child element
    _VERSION_ELEM_RE = re.compile(r"<Version>([^<]+)</Version>", re.IGNORECASE)
    _PRIVATE_RE      = re.compile(
        r"<PrivateAssets>\s*all\s*</PrivateAssets>", re.IGNORECASE
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        # Simpler, more robust approach: find all PackageReference tags
        # with a two-pass regex.
        block_re = re.compile(
            r"<PackageReference\b(?P<attrs>[^>]*)>(?P<inner>.*?)</PackageReference>"
            r"|<PackageReference\b(?P<attrs2>[^/]*)/?>",
            re.DOTALL | re.IGNORECASE,
        )
        id_re  = re.compile(r'\bInclude\s*=\s*"([^"]+)"',  re.IGNORECASE)
        ver_re = re.compile(r'\bVersion\s*=\s*"([^"]+)"',  re.IGNORECASE)

        for m in block_re.finditer(text):
            attrs = (m.group("attrs") or "") + (m.group("attrs2") or "")
            inner = m.group("inner") or ""

            id_m  = id_re.search(attrs)
            ver_m = ver_re.search(attrs) or self._VERSION_ELEM_RE.search(inner)

            if not id_m:
                continue

            pkg_id  = id_m.group(1)
            version = ver_m.group(1) if ver_m else "UNKNOWN"
            is_dev  = bool(self._PRIVATE_RE.search(inner))

            deps[pkg_id] = DependencyInfo(
                version=version,
                source="project.csproj",
                is_direct=True,
                is_dev=is_dev,
                depth=1,
                dependency_path=[pkg_id],
            )

        return deps


class DirectoryPackagesPropsPlugin(ManifestPlugin):
    """
    Parses ``Directory.Packages.props`` (Central Package Management).

    Defines the *versions* of packages centrally; individual projects reference
    them without a version attribute.  We treat every ``<PackageVersion>`` entry
    as a direct dependency (conservative — better safe than sorry).

    Format::

        <Project>
          <ItemGroup>
            <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
          </ItemGroup>
        </Project>
    """

    manifest_files = ["Directory.Packages.props"]
    ecosystem = "NuGet"

    _PKG_VER_RE = re.compile(
        r'<PackageVersion\b[^>]*\bInclude\s*=\s*"(?P<id>[^"]+)"'
        r'[^>]*\bVersion\s*=\s*"(?P<version>[^"]+)"',
        re.IGNORECASE,
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        for m in self._PKG_VER_RE.finditer(text):
            pkg_id  = m.group("id")
            version = m.group("version")
            deps[pkg_id] = DependencyInfo(
                version=version,
                source="Directory.Packages.props",
                is_direct=True,
                is_dev=False,
                depth=1,
                dependency_path=[pkg_id],
            )

        return deps


class NuGetLockJsonPlugin(ManifestPlugin):
    """
    Parses ``packages.lock.json`` (NuGet lock file).

    Enabled in a project with::

        <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>

    JSON structure::

        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": {
                "type": "Direct",
                "requested": "[13.0.3, )",
                "resolved": "13.0.3",
                "contentHash": "..."
              }
            }
          }
        }

    We record one entry per package, preferring the resolved version.
    ``type == "Direct"`` maps to ``is_direct=True``; ``"Transitive"`` → False.
    """

    manifest_files = ["packages.lock.json"]
    ecosystem = "NuGet"

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        try:
            data = json.loads(text)
        except Exception:
            return {}

        all_deps = data.get("dependencies", {})

        # Iterate over all target frameworks; last-write wins (same package
        # usually appears in all targets with identical resolved version).
        for _framework, pkgs in all_deps.items():
            if not isinstance(pkgs, dict):
                continue
            for pkg_id, info in pkgs.items():
                if not isinstance(info, dict):
                    continue
                resolved  = info.get("resolved", "UNKNOWN")
                dep_type  = info.get("type", "Transitive")
                is_direct = dep_type.lower() == "direct"
                deps[pkg_id] = DependencyInfo(
                    version=resolved,
                    source="packages.lock.json",
                    is_direct=is_direct,
                    is_dev=False,
                    depth=1 if is_direct else 2,
                    dependency_path=[pkg_id],
                )

        return deps
