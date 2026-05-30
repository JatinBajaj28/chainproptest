"""
vulnalyzer.graph.ai_patches
============================
Generate AI-powered patch recommendations using Google Gemini (free API).

Requires a free Gemini API key from https://aistudio.google.com/app/apikey

Usage:
    from vulnalyzer.graph.ai_patches import AIPatchSuggester

    suggester = AIPatchSuggester(api_key="YOUR_GEMINI_API_KEY")
    advice_dict = suggester.suggest_patches(scan_result)

    for pkg_key, advice in advice_dict.items():
        print(advice.to_markdown())
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from vulnalyzer.scanner.engine import ScanResult, Finding

logger = logging.getLogger(__name__)

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent"
)


class AIPatchSuggester:
    """Generate AI-powered patch recommendations using Gemini (free tier)."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the AI patch suggester.

        Args:
            api_key: Gemini API key from https://aistudio.google.com/app/apikey
                     Falls back to GEMINI_API_KEY environment variable.
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Gemini API key required.\n"
                "  Get a free key at: https://aistudio.google.com/app/apikey\n"
                "  Then pass api_key=... or set GEMINI_API_KEY environment variable."
            )

    def _call_gemini(self, prompt: str) -> str:
        """Make a raw HTTP request to Gemini API (no extra libraries needed)."""
        url = f"{GEMINI_API_URL}?key={self.api_key}"
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1024,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Gemini API error {e.code}: {body}\n"
                "Check your API key at https://aistudio.google.com/app/apikey"
            ) from e

        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            raise RuntimeError(
                f"Unexpected Gemini response format: {json.dumps(data)}"
            ) from e

    def generate_executive_summary(self, scan_result: "ScanResult") -> str:
        """
        Ask Gemini to write a short executive-level CVE summary for the whole repo.
        Returns a markdown string.
        """
        findings = scan_result.findings
        if not findings:
            return "_No vulnerabilities found — repository appears clean._"

        vuln_lines = "\n".join(
            f"- {f.osv_id} ({f.severity}) in {f.package_name}@{f.version_found} "
            f"[{f.ecosystem}]: {f.summary}"
            for f in findings
        )
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        sev_summary = ", ".join(f"{v} {k}" for k, v in sev_counts.items())

        prompt = f"""You are a senior application security engineer writing an executive summary.

Repository: {scan_result.repo_url}
Branch: {scan_result.branch_ref}
Commit: {scan_result.revision_id[:12]}
Total vulnerabilities: {len(findings)} ({sev_summary})

All CVE findings:
{vuln_lines}

Write a concise executive summary (3-5 sentences) in Markdown that:
1. States the overall risk posture of this repository
2. Calls out the most critical CVEs by ID and what they expose
3. Gives a clear top-level recommendation (upgrade, mitigate, or monitor)

Return ONLY the markdown text — no JSON, no preamble."""

        try:
            return self._call_gemini(prompt)
        except Exception as exc:
            logger.warning("Executive summary failed: %s", exc)
            return f"_AI summary unavailable: {exc}_"

    def suggest_patches(self, scan_result: "ScanResult") -> dict[str, "PatchAdvice"]:
        """
        Generate AI patch suggestions for all vulnerable packages in a scan.

        Returns:
            Dict mapping package key to PatchAdvice.
            Returns an empty dict if no findings.
        """
        if not scan_result.findings:
            return {}

        by_package: dict[str, list["Finding"]] = {}
        for f in scan_result.findings:
            key = f"{f.package_name}@{f.version_found} ({f.ecosystem})"
            by_package.setdefault(key, []).append(f)

        suggestions: dict[str, PatchAdvice] = {}
        for pkg_key, findings in by_package.items():
            try:
                advice = self._generate_advice(
                    package_key=pkg_key,
                    findings=findings,
                )
                suggestions[pkg_key] = advice
            except Exception as exc:
                logger.warning("AI patch failed for %s: %s", pkg_key, exc)
                # Graceful fallback
                suggestions[pkg_key] = PatchAdvice(
                    recommended_version=(
                        findings[0].fixed_versions[0]
                        if findings[0].fixed_versions
                        else None
                    ),
                    strategy="Upgrade to patched version",
                    explanation="(AI analysis unavailable — using fallback)",
                    breaking_changes=[],
                    migration_steps=[],
                    risk_level="unknown",
                )
        return suggestions

    def _generate_advice(
        self,
        package_key: str,
        findings: list["Finding"],
    ) -> "PatchAdvice":
        """Ask Gemini to generate patch advice for one vulnerable package."""
        fixed_versions = sorted(
            {v for f in findings for v in f.fixed_versions}
        )
        vulns_text = "\n".join(
            f"- {f.osv_id} ({f.severity}): {f.summary}\n"
            f"  Fixed in: {', '.join(f.fixed_versions) or 'N/A'}"
            for f in findings
        )
        dep_type = "direct" if findings[0].is_direct else "transitive"
        ecosystem = findings[0].ecosystem
        manifest = findings[0].manifest_source

        prompt = f"""You are a security expert helping developers fix vulnerable dependencies.

Package: {package_key}
Dependency type: {dep_type}
Found in: {manifest}
Ecosystem: {ecosystem}
Available patched versions: {', '.join(fixed_versions) if fixed_versions else 'None yet'}

Vulnerabilities:
{vulns_text}

Return ONLY a valid JSON object (no markdown, no explanation outside JSON):
{{
    "recommended_version": "X.Y.Z or null",
    "strategy": "short strategy name",
    "explanation": "1-2 sentence explanation",
    "breaking_changes": ["potential breaking change 1", "..."],
    "migration_steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
    "risk_level": "low | medium | high",
    "additional_notes": "any extra context or empty string"
}}

Rules:
- recommended_version: oldest version that fixes ALL listed CVEs (conservative)
- breaking_changes: based on semver — major bump = likely breaking, patch = safe
- migration_steps: 2-4 steps specific to {ecosystem}
- risk_level: reflects upgrade difficulty, not vuln severity
- For transitive deps, suggest updating the parent package too"""

        raw = self._call_gemini(prompt)

        # Strip markdown fences if present
        text = raw.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        data = json.loads(text)
        return PatchAdvice(
            recommended_version=data.get("recommended_version"),
            strategy=data.get("strategy", "Upgrade to patched version"),
            explanation=data.get("explanation", ""),
            breaking_changes=data.get("breaking_changes", []),
            migration_steps=data.get("migration_steps", []),
            risk_level=data.get("risk_level", "medium"),
            additional_notes=data.get("additional_notes", ""),
        )


class PatchAdvice:
    """Structured patch advice for a single vulnerable package."""

    def __init__(
        self,
        recommended_version: Optional[str] = None,
        strategy: str = "",
        explanation: str = "",
        breaking_changes: Optional[list[str]] = None,
        migration_steps: Optional[list[str]] = None,
        risk_level: str = "medium",
        additional_notes: str = "",
    ):
        self.recommended_version = recommended_version
        self.strategy = strategy
        self.explanation = explanation
        self.breaking_changes = breaking_changes or []
        self.migration_steps = migration_steps or []
        self.risk_level = risk_level
        self.additional_notes = additional_notes

    def to_markdown(self) -> str:
        lines: list[str] = []

        if self.recommended_version:
            lines.append(f"**Recommended version:** `{self.recommended_version}`")
        else:
            lines.append("**Status:** No patched version available yet — monitor upstream")

        lines.append(f"**Strategy:** {self.strategy}")
        lines.append("")

        if self.explanation:
            lines.append(f"_{self.explanation}_")
            lines.append("")

        if self.breaking_changes:
            lines.append("**⚠️ Potential breaking changes:**")
            for change in self.breaking_changes:
                lines.append(f"- {change}")
            lines.append("")

        if self.migration_steps:
            lines.append("**📝 Migration steps:**")
            for i, step in enumerate(self.migration_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        if self.additional_notes:
            lines.append(f"**ℹ️ Notes:** {self.additional_notes}")
            lines.append("")

        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(
            self.risk_level, "⚪"
        )
        lines.append(f"{risk_emoji} **Upgrade risk:** {self.risk_level}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"PatchAdvice(version={self.recommended_version!r}, "
            f"strategy={self.strategy!r}, risk={self.risk_level!r})"
        )
