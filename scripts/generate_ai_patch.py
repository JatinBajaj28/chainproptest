#!/usr/bin/env python
"""
Generate AI-powered patch suggestions for a scanned repository.

Usage:
    # Set your free Gemini API key (https://aistudio.google.com/app/apikey)
    export GEMINI_API_KEY=AIza...

    # Scan a repo and get AI patch suggestions
    python scripts/generate_ai_patch.py --repo https://github.com/owner/repo

    # Save to a markdown file
    python scripts/generate_ai_patch.py --repo https://github.com/owner/repo --output issue.md

    # Basic mode without AI (no API key needed)
    python scripts/generate_ai_patch.py --repo https://github.com/owner/repo --no-ai
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnalyzer.scanner.engine import Scanner
from vulnalyzer.graph.patch_request import generate_issue_body, generate_issue_body_with_ai


def main():
    parser = argparse.ArgumentParser(
        description="Generate AI-powered patch recommendations for a repository"
    )
    parser.add_argument("--repo", required=True, help="GitHub repo URL to scan")
    parser.add_argument("--api-key", default=os.getenv("GEMINI_API_KEY"),
                        help="Gemini API key (default: $GEMINI_API_KEY)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI, generate basic recommendations only")
    parser.add_argument("--output", default=None,
                        help="Save output to file (default: print to stdout)")
    args = parser.parse_args()

    use_ai = not args.no_ai

    if use_ai and not args.api_key:
        print(
            "Error: GEMINI_API_KEY not set.\n"
            "  Get a free key at: https://aistudio.google.com/app/apikey\n"
            "  Then: export GEMINI_API_KEY=AIza...\n"
            "  Or use --no-ai for basic recommendations.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"🔍 Scanning {args.repo} ...", file=sys.stderr)
    scanner = Scanner()
    result = scanner.scan(args.repo)

    if not result.findings:
        print("✅ No vulnerabilities found.", file=sys.stderr)
        sys.exit(0)

    print(f"Found {len(result.findings)} vulnerability findings.", file=sys.stderr)

    if use_ai:
        print("🤖 Generating Gemini AI patch suggestions ...", file=sys.stderr)
        body = generate_issue_body_with_ai(result, use_ai=True, api_key=args.api_key)
    else:
        body = generate_issue_body(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"✅ Saved to {args.output}", file=sys.stderr)
    else:
        print(body)


if __name__ == "__main__":
    main()
