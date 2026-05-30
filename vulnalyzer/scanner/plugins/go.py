"""
vulnalyzer.scanner.plugins.go
==============================
Plugins for Go module dependency manifests:
  - go.mod   (module declaration + direct require directives)
  - go.sum   (checksums — used to extract the full transitive closure with versions)

OSV ecosystem name for Go is "Go".

go.mod format reference: https://go.dev/ref/mod#go-mod-file
go.sum format reference:  https://go.dev/ref/mod#go-sum-files
"""

from __future__ import annotations

import logging
import re

from .base import ManifestPlugin, DependencyInfo

logger = logging.getLogger(__name__)


class GoModPlugin(ManifestPlugin):
    """
    Parses go.mod for direct dependencies declared with ``require`` directives.

    Handles both single-line and block forms::

        require github.com/gin-gonic/gin v1.9.1

        require (
            github.com/gin-gonic/gin v1.9.1
            golang.org/x/net        v0.17.0 // indirect
        )

    Packages marked ``// indirect`` are recorded as non-direct (depth = 2).
    """

    manifest_files = ["go.mod"]
    ecosystem = "Go"

    # Single-line: require module/path v1.2.3
    _SINGLE_RE = re.compile(
        r"^require\s+(?P<module>\S+)\s+(?P<version>v[\w.\-+]+)",
        re.MULTILINE,
    )
    # Inside a require ( ... ) block: module/path v1.2.3 [// indirect]
    _BLOCK_LINE_RE = re.compile(
        r"^\s+(?P<module>\S+)\s+(?P<version>v[\w.\-+]+)(?P<indirect>\s*//\s*indirect)?",
        re.MULTILINE,
    )
    # Detect opening of a require block
    _BLOCK_START_RE = re.compile(r"^require\s*\(", re.MULTILINE)
    _BLOCK_END_RE   = re.compile(r"^\)", re.MULTILINE)

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        # Single-line requires
        for m in self._SINGLE_RE.finditer(text):
            module  = m.group("module")
            version = m.group("version")
            deps[module] = DependencyInfo(
                version=version,
                source="go.mod",
                is_direct=True,
                is_dev=False,
                depth=1,
                dependency_path=[module],
            )

        # Block requires — extract each block between `require (` and `)`
        for blk_start in self._BLOCK_START_RE.finditer(text):
            blk_end = self._BLOCK_END_RE.search(text, blk_start.end())
            if not blk_end:
                continue
            block_text = text[blk_start.end(): blk_end.start()]
            for m in self._BLOCK_LINE_RE.finditer(block_text):
                module   = m.group("module")
                version  = m.group("version")
                indirect = bool(m.group("indirect"))
                # Don't override a direct entry with an indirect one
                if module not in deps or not indirect:
                    deps[module] = DependencyInfo(
                        version=version,
                        source="go.mod",
                        is_direct=not indirect,
                        is_dev=False,
                        depth=1 if not indirect else 2,
                        dependency_path=[module],
                    )

        return deps


class GoSumPlugin(ManifestPlugin):
    """
    Parses go.sum for the full transitive dependency closure.

    go.sum lines look like::

        github.com/gin-gonic/gin v1.9.1 h1:<hash>
        github.com/gin-gonic/gin v1.9.1/go.mod h1:<hash>

    We deduplicate by (module, version) and skip ``/go.mod`` lines so each
    package appears once.  All entries are treated as transitive (depth = 2)
    because go.sum does not distinguish direct from indirect — use GoModPlugin
    to get the direct ones; the scanner engine deduplicates by keeping the
    entry with the richer dependency_path.
    """

    manifest_files = ["go.sum"]
    ecosystem = "Go"

    # module/path v1.2.3 h1:...   OR   module/path v1.2.3/go.mod h1:...
    _LINE_RE = re.compile(
        r"^(?P<module>\S+)\s+(?P<version>v[\w.\-+]+?)(?:/go\.mod)?\s+h\d:",
        re.MULTILINE,
    )

    def parse(self, text: str) -> dict[str, DependencyInfo]:
        deps: dict[str, DependencyInfo] = {}

        for m in self._LINE_RE.finditer(text):
            module  = m.group("module")
            version = m.group("version")

            if module not in deps:
                deps[module] = DependencyInfo(
                    version=version,
                    source="go.sum",
                    is_direct=False,   # go.sum = transitive closure
                    is_dev=False,
                    depth=2,
                    dependency_path=[module],
                )

        return deps
