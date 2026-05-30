"""
vulnalyzer.scanner.plugins.crates
===================================
Plugins for Rust / crates.io dependency manifests:
  - Cargo.toml   (workspace and package manifests)
  - Cargo.lock   (resolved lockfile — Cargo.lock v3 format)

OSV ecosystem name for crates.io is "crates.io".

Cargo.toml reference: https://doc.rust-lang.org/cargo/reference/manifest.html
Cargo.lock reference:  https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html
"""

from __future__ import annotations

import logging
import re

from .base import ManifestPlugin, DependencyInfo

logger = logging.getLogger(__name__)


class CargoTomlPlugin(ManifestPlugin):
    """
    Parses Cargo.toml for direct dependencies.

    Handles the most common formats::

        [dependencies]
        serde = "1.0"
        tokio = { version = "1", features = ["full"] }
        rand = { version = "0.8", optional = true }

        [dev-dependencies]
        criterion = "0.5"

        [build-dependencies]
        cc = "1.0"

    All sections are captured; dev-dependencies are flagged ``is_dev=True``.
    Workspace members' ``[workspace.dependencies]`` are also captured.
    """

    manifest_files = ["Cargo.toml"]
    ecosystem = "crates.io"

    # Section headers we care about
    _SECTION_RE = re.compile(
        r"^\[(?P<section>"
        r"(?:workspace\.)?(?:dev-|build-)?dependencies"
        r")\]",
        re.MULTILINE | re.IGNORECASE,
    )
    # Next section that could close a deps block
    _NEXT_SECTION_RE = re.compile(r"^\[", re.MULTILINE)

    # Simple string version:   serde = "1.0"
    _SIMPLE_RE = re.compile(
        r'^(?P<name>[A-Za-z0-9_\-]+)\s*=\s*"(?P<version>[^"]+)"',
        re.MULTILINE,
    )
    # Inline table with version key:   tokio = { version = "1", ... }
    _TABLE_RE  = re.compile(
        r'^(?P<name>[A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"(?P<version>[^"]+)"',
        re.MULTILINE,
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        sections = list(self._SECTION_RE.finditer(text))

        for i, sec_match in enumerate(sections):
            section_name = sec_match.group("section").lower()
            is_dev = "dev" in section_name

            block_start = sec_match.end()
            # Find end of block: next `[` header or end of file
            next_sec = self._NEXT_SECTION_RE.search(text, block_start)
            block_end = next_sec.start() if next_sec else len(text)
            block = text[block_start:block_end]

            # Try both simple and table forms
            for pattern in (self._SIMPLE_RE, self._TABLE_RE):
                for m in pattern.finditer(block):
                    name    = m.group("name")
                    version = m.group("version")
                    # Simple form may catch table entries that lack version;
                    # TABLE_RE has already handled those — skip if duplicate
                    if name not in deps or not is_dev:
                        deps[name] = DependencyInfo(
                            version=version,
                            source="Cargo.toml",
                            is_direct=True,
                            is_dev=is_dev,
                            depth=1,
                            dependency_path=[name],
                        )

        return deps


class CargoLockPlugin(ManifestPlugin):
    """
    Parses Cargo.lock (v3 TOML format) for the full resolved dependency tree.

    Cargo.lock package entries look like::

        [[package]]
        name    = "serde"
        version = "1.0.188"
        source  = "registry+https://github.com/rust-lang/crates.io-index"
        dependencies = [
          "serde_derive",
        ]

    We emit every crates.io package (non-path / non-git).
    Packages with ``dependencies`` listed can have their dependency paths
    reconstructed; we record a flat list here (depth = 2) as a conservative
    baseline.  Direct packages (those present in the root package's dep list)
    are detected by checking which names appear in the first ``[[package]]``
    entry's ``dependencies`` list.
    """

    manifest_files = ["Cargo.lock"]
    ecosystem = "crates.io"

    # Split on [[package]] boundaries
    _PKG_SPLIT_RE = re.compile(r"\[\[package\]\]")
    _NAME_RE      = re.compile(r'^name\s*=\s*"(?P<val>[^"]+)"',    re.MULTILINE)
    _VER_RE       = re.compile(r'^version\s*=\s*"(?P<val>[^"]+)"', re.MULTILINE)
    _SRC_RE       = re.compile(r'^source\s*=\s*"(?P<val>[^"]+)"',  re.MULTILINE)
    # All deps of a package block
    _DEPS_RE      = re.compile(
        r'dependencies\s*=\s*\[([^\]]*)\]', re.DOTALL
    )
    _DEP_ITEM_RE  = re.compile(r'"([A-Za-z0-9_\-]+)')

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        blocks = self._PKG_SPLIT_RE.split(text)

        # First block is pre-amble (lockfile header); skip it
        pkg_blocks = blocks[1:]

        # Collect root package deps (first block) for is_direct detection
        root_direct: set[str] = set()
        if pkg_blocks:
            dm = self._DEPS_RE.search(pkg_blocks[0])
            if dm:
                root_direct = {
                    m.group(1) for m in self._DEP_ITEM_RE.finditer(dm.group(1))
                }

        for block in pkg_blocks:
            nm = self._NAME_RE.search(block)
            vm = self._VER_RE.search(block)
            sm = self._SRC_RE.search(block)

            if not nm or not vm:
                continue

            name    = nm.group("val")
            version = vm.group("val")
            source  = sm.group("val") if sm else ""

            # Only index packages from crates.io registry (skip path / git deps)
            if source and not source.startswith("registry+"):
                continue

            is_direct = name in root_direct

            deps[name] = DependencyInfo(
                version=version,
                source="Cargo.lock",
                is_direct=is_direct,
                is_dev=False,
                depth=1 if is_direct else 2,
                dependency_path=[name],
            )

        return deps
