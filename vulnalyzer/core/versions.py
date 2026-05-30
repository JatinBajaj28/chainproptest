"""
vulnalyzer.core.versions
========================
Semver / PEP-440 version matching against OSV affected-ranges.
"""

from __future__ import annotations

from packaging.version import Version, InvalidVersion


def clean_version(v: str) -> str:
    """Strip npm-style range prefixes so packaging.version can parse.

    Handles:
      "^4.17.1"         → "4.17.1"
      "~1.2.3"          → "1.2.3"
      ">=4.0.0 <5.0.0"  → "4.0.0"   (take the lower bound only)
      "4.17.21"         → "4.17.21"  (exact — unchanged)
      "= 1.2.3"         → "1.2.3"
    """
    import re as _re
    v = str(v).strip()
    # Strip leading range operator prefix (^, ~, >=, <=, >, <, =, and whitespace)
    # Use regex instead of lstrip to avoid stripping meaningful characters
    # e.g. lstrip(">=< ") would strip the '4' from '>= 4.0' if it appeared in the set
    v = _re.sub(r'^[~^<>=\s]+', '', v)
    # If a compound range remains (e.g. "4.0.0 <5.0.0"), take only the
    # first whitespace-delimited token (the lower bound).
    return v.split()[0] if v else v


def safe_version(v: str) -> Version | None:
    try:
        return Version(clean_version(v))
    except (InvalidVersion, TypeError):
        return None


def version_in_range(dep_version: str, ranges: list[dict]) -> bool:
    """
    Return True if *dep_version* falls within any of the OSV affected ranges.

    Each range dict has optional keys: ``introduced``, ``fixed``, ``last_affected``.
    """
    dv = safe_version(dep_version)
    if dv is None:
        return False

    for r in ranges:
        introduced = safe_version(r.get("introduced", "0"))
        fixed = safe_version(r["fixed"]) if "fixed" in r else None
        last_affected = safe_version(r["last_affected"]) if "last_affected" in r else None

        if introduced and dv < introduced:
            continue

        if fixed is not None:
            if dv < fixed:
                return True
            # version is at or beyond the fix → not in this range
            continue

        if last_affected is not None:
            if dv <= last_affected:
                return True
            continue

        # introduced but no fixed / last_affected → still open-ended
        return True

    return False
