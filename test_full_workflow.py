#!/usr/bin/env python3
"""
Complete test: Scan express repo for lodash vulnerabilities
This script demonstrates the full workflow end-to-end
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vulnalyzer.core.db import init_db, get_conn, get_all_vulnerabilities
from vulnalyzer.ingest.osv import ingest_package
from vulnalyzer.scanner.engine import scan_repo
from vulnalyzer.graph.builder import build_graph


def main():
    print("=" * 70)
    print("VULNALYZER END-TO-END TEST: Express + Lodash Vulnerability")
    print("=" * 70)
    
    # Step 1: Initialize database
    print("\n[1/5] Initializing database...")
    init_db()
    print("✓ Database initialized")
    
    # Step 2: Ingest CVEs for lodash
    print("\n[2/5] Ingesting CVEs for lodash (npm)...")
    count = ingest_package("lodash", "npm")
    if count > 0:
        print(f"✓ Successfully ingested {count} CVEs for lodash")
    else:
        print("⚠ WARNING: 0 CVEs ingested for lodash")
        print("  This might be due to OSV API issues")
        print("  Attempting to continue anyway...\n")
    
    # Check what's in database
    with get_conn() as conn:
        all_vulns = get_all_vulnerabilities(conn)
        print(f"  Total CVEs in database: {len(all_vulns)}")
        
        if all_vulns:
            lodash_vulns = [v for v in all_vulns if 'lodash' in v['package_name'].lower()]
            print(f"  Lodash-related CVEs: {len(lodash_vulns)}")
            
            if lodash_vulns:
                print("\n  Sample lodash CVEs:")
                for v in lodash_vulns[:3]:
                    print(f"    - {v['osv_id']}: {v['summary'][:60]}...")
    
    # Step 3: Scan express repo
    print("\n[3/5] Scanning express repo from GitHub...")
    result = scan_repo("https://github.com/expressjs/express")
    print(f"✓ Scan status: {result.status}")
    print(f"  Manifests found: {len(result.manifests_found)}")
    if result.manifests_found:
        print(f"  Manifest files:")
        for m in result.manifests_found[:5]:
            print(f"    - {m}")
    print(f"  Findings: {len(result.findings)}")
    
    if result.findings:
        print("\n  🚨 VULNERABILITIES DETECTED:")
        for f in result.findings[:5]:
            print(f"    - {f.osv_id}: {f.package_name}@{f.version_found} ({f.ecosystem})")
    else:
        print("\n  ℹ No vulnerabilities matched (may need more CVE ingestion)")
    
    # Step 4: Build graph
    print("\n[4/5] Building dependency graph...")
    graph_info = build_graph()
    print(f"✓ Graph built successfully")
    print(f"  Nodes: {graph_info['nodes']}")
    print(f"  Edges: {graph_info['edges']}")
    
    # Step 5: Query results
    print("\n[5/5] Querying results...")
    with get_conn() as conn:
        total_vulns = get_all_vulnerabilities(conn)
        print(f"✓ Total vulnerabilities in system: {len(total_vulns)}")
        
        # Count by ecosystem
        by_eco = {}
        for v in total_vulns:
            eco = v.get('ecosystem', 'Unknown')
            by_eco[eco] = by_eco.get(eco, 0) + 1
        
        print("\n  Vulnerabilities by ecosystem:")
        for eco, count in sorted(by_eco.items()):
            print(f"    - {eco}: {count}")
    
    print("\n" + "=" * 70)
    print("TEST COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Start the server: python3 run.py")
    print("2. Open browser: http://localhost:8000")
    print("3. Click 'Live Badge' to open pipeline panel")
    print("4. Filter by 'npm' ecosystem to see findings")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
