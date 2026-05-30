"""
vulnalyzer.api.app
==================
FastAPI application.

Run with:
    uvicorn vulnalyzer.api.app:app --reload --port 8000

Endpoints
---------
GET /api/graph          Full graph in frontend-compatible shape
GET /api/graph/raw      Raw internal graph (nodes + edges as stored)
GET /healthz            Health check
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote

try:
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
except ImportError:
    raise ImportError(
        "FastAPI is required to run the API layer.\n"
        "Install it with:  pip install fastapi uvicorn"
    )

from vulnalyzer.core.db import get_conn, init_db, get_all_vulnerabilities
from vulnalyzer.graph.patch_request import generate_issue_body, generate_issue_title, generate_issue_body_with_ai
from vulnalyzer.scanner.engine import Finding, ScanResult

app = FastAPI(title="Vulnalyzer API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

_SEV_NORM = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "MODERATE": "Medium",
    "LOW":      "Low",
    "UNKNOWN":  None,
}

_ECOSYSTEM_SOURCE = {
    "npm":       "npm",
    "pypi":      "PyPI",
    "maven":     "Maven",
    "go":        "Go",
    "crates.io": "crates.io",
    "nuget":     "NuGet",
}


def _norm_sev(raw: str | None) -> str | None:
    if not raw:
        return None
    return _SEV_NORM.get(raw.upper(), raw.title())


def _norm_source(ecosystem: str | None) -> str:
    if not ecosystem:
        return "GitHub"
    return _ECOSYSTEM_SOURCE.get(ecosystem.lower(), ecosystem)


def _severity_rank(severity: str | None) -> int:
    return {
        "CRITICAL": 5,
        "HIGH": 4,
        "MODERATE": 3,
        "MEDIUM": 3,
        "LOW": 2,
        "UNKNOWN": 1,
    }.get((severity or "UNKNOWN").upper(), 0)


def _registry_url(package_name: str, ecosystem: str | None) -> str | None:
    eco = (ecosystem or "").lower()
    if not package_name:
        return None
    if eco == "npm":
        return f"https://www.npmjs.com/package/{quote(package_name)}"
    if eco == "pypi":
        return f"https://pypi.org/project/{quote(package_name)}/"
    if eco == "maven":
        return f"https://central.sonatype.com/search?q={quote(package_name)}"
    if eco == "go":
        return f"https://pkg.go.dev/{quote(package_name, safe='/')}"
    if eco in ("crates.io", "crates"):
        return f"https://crates.io/crates/{quote(package_name)}"
    if eco == "nuget":
        return f"https://www.nuget.org/packages/{quote(package_name)}"
    return None


def _display_cve(vuln: dict, osv_id: str) -> str:
    aliases = vuln.get("aliases", [])
    return next((a for a in aliases if a.startswith("CVE-")), osv_id)


def _finding_to_frontend(f, vuln: dict, repo_by_id: dict[int, dict]) -> dict:
    fixed = vuln.get("fixed_versions", [])
    dependency_path = json.loads(f["dependency_path"] or "[]")
    repo = repo_by_id.get(f["repo_id"], {})
    return {
        "osvId": f["osv_id"],
        "cve": _display_cve(vuln, f["osv_id"]),
        "severity": _norm_sev(f["severity"]) or "Unknown",
        "package": f["package_name"],
        "ecosystem": f["ecosystem"],
        "version": f["version_found"],
        "summary": vuln.get("summary", ""),
        "details": vuln.get("details", ""),
        "fixedVersions": fixed,
        "fix": f"Upgrade to {fixed[0]}+" if fixed else "No fix available yet - monitor upstream",
        "direct": bool(f["is_direct"]),
        "dev": bool(f["is_dev"]),
        "depth": f["depth"] or 1,
        "manifest": f["manifest_source"],
        "dependencyPath": dependency_path,
        "osvUrl": f"https://osv.dev/vulnerability/{quote(f['osv_id'])}",
        "repo": repo.get("full_name") or repo.get("name"),
        "repoUrl": repo.get("url"),
    }


def _issue_draft_for_repo(repo: dict, finding_rows: list, vulns: dict[str, dict]) -> dict:
    findings = []
    for f in finding_rows:
        vuln = vulns.get(f["osv_id"], {})
        findings.append(Finding(
            package_name=f["package_name"],
            ecosystem=f["ecosystem"],
            version_found=f["version_found"],
            is_direct=bool(f["is_direct"]),
            manifest_source=f["manifest_source"],
            osv_id=f["osv_id"],
            severity=(_norm_sev(f["severity"]) or "UNKNOWN").upper(),
            summary=vuln.get("summary", ""),
            fixed_versions=vuln.get("fixed_versions", []),
            is_dev=bool(f["is_dev"]),
            parent_package=f["parent_package"],
            depth=f["depth"] or 1,
            dependency_path=json.loads(f["dependency_path"] or "[]"),
        ))

    result = ScanResult(
        repo_url=repo.get("url", ""),
        platform=repo.get("platform", "github"),
        owner=repo.get("owner", ""),
        repo_name=repo.get("name", ""),
        revision_id=repo.get("commit_sha") or "",
        branch_ref=repo.get("branch_ref") or "",
        status="SCANNED_OK",
        findings=findings,
    )
    return {
        "title": generate_issue_title(result),
        "body": generate_issue_body(result),
    }


# ---------------------------------------------------------------------------
# Graph → frontend shape conversion
# ---------------------------------------------------------------------------

def _build_frontend_graph() -> dict:
    """
    Convert the internal graph (graph_nodes + graph_edges) into the exact
    { nodes, links } shape the frontend RAW object expects.

    Node type mapping
    -----------------
    Repository      → "root"
    Vulnerability   → used to annotate Package nodes, not emitted itself
    PackageVersion  → mapped to vulnerable / high / medium / safe
    Package         → same as PackageVersion (deduped)

    We emit one frontend node per unique package name+ecosystem.
    The type is determined by whether it's directly vulnerable, a parent
    of a vulnerable package, or has no known vulnerability path.
    """
    init_db()

    with get_conn() as conn:
        # Collect all raw graph nodes and edges
        raw_nodes = conn.execute("SELECT * FROM graph_nodes").fetchall()
        raw_edges = conn.execute("SELECT * FROM graph_edges").fetchall()

        # Build vuln lookup: osv_id -> vuln record
        vulns_list = get_all_vulnerabilities(conn)
        vulns: dict[str, dict] = {v["osv_id"]: v for v in vulns_list}

        # Build scan findings for enrichment: package_name+ecosystem -> findings list
        findings_rows = conn.execute(
            """
            SELECT
                sf.*,
                rs.repo_id,
                rs.commit_sha,
                rs.branch_ref,
                rs.scanned_at,
                r.platform,
                r.owner,
                r.name AS repo_name,
                r.url AS repo_url
            FROM scan_findings sf
            JOIN repo_scans rs ON rs.id = sf.scan_id
            JOIN repos r ON r.id = rs.repo_id
            WHERE rs.status = 'SCANNED_OK'
            """
        ).fetchall()

    # Index edges by rel type
    edges_by_rel: dict[str, list[dict]] = {}
    for e in raw_edges:
        rel = e["rel"]
        edges_by_rel.setdefault(rel, []).append({
            "src": e["src"],
            "dst": e["dst"],
            "data": json.loads(e["data"]) if e["data"] else {},
        })

    # Index nodes by id
    nodes_by_id: dict[str, dict] = {}
    for n in raw_nodes:
        nodes_by_id[n["id"]] = {
            "id":        n["id"],
            "label":     n["label"],
            "ecosystem": n["ecosystem"],
            "data":      json.loads(n["data"]) if n["data"] else {},
        }

    # Build a findings index: pkg_name.lower() + ecosystem → list of finding rows
    repo_by_id: dict[int, dict] = {}
    findings_by_repo_node: dict[str, list] = {}

    for f in findings_rows:
        repo_node = f"repo:{f['owner']}/{f['repo_name']}"
        repo_by_id[f["repo_id"]] = {
            "platform": f["platform"],
            "owner": f["owner"],
            "name": f["repo_name"],
            "full_name": f"{f['owner']}/{f['repo_name']}",
            "url": f["repo_url"],
            "commit_sha": f["commit_sha"],
            "branch_ref": f["branch_ref"],
            "scanned_at": f["scanned_at"],
        }
        findings_by_repo_node.setdefault(repo_node, []).append(f)

    findings_by_pkg: dict[str, list] = {}
    for f in findings_rows:
        key = f"{f['package_name'].lower()}|{(f['ecosystem'] or '').lower()}"
        findings_by_pkg.setdefault(key, []).append(f)

    # ---------------------------------------------------------------------------
    # Synthesize intermediate nodes + edges from dependency_path stored in findings.
    # The graph builder only creates nodes/edges for the vulnerable package itself.
    # Intermediates like "zipstream" or "mkdirp" may not have their own finding rows
    # and may not exist in graph_nodes / graph_edges if the graph was built before
    # our builder.py patch.  We reconstruct them here from scan_findings directly
    # so the full path always renders regardless of when the graph was last rebuilt.
    # ---------------------------------------------------------------------------
    # synthetic_pkg_nodes: fe_id → {name, eco}  — intermediates not already in DB
    synthetic_pkg_nodes: dict[str, dict] = {}
    # synthetic_uses: repo_fe_id → set of pkg_fe_id  — direct dep links
    synthetic_uses: dict[str, set[str]] = {}
    # synthetic_depends: set of (parent_fe_id, child_fe_id) tuples
    synthetic_depends: set[tuple[str, str]] = set()

    for f in findings_rows:
        dep_path = json.loads(f["dependency_path"] or "[]")
        if len(dep_path) < 2:
            continue  # direct dep or no path info — no intermediates needed

        eco = (f["ecosystem"] or "").lower()
        repo_fe_id = f"repo:{f['owner']}/{f['repo_name']}"

        # Build fe_ids for every package in the path
        path_fe_ids = [f"pkg:{pkg.lower()}:{eco}" for pkg in dep_path]

        # Ensure every intermediate node exists (first and last may already exist)
        for pkg_name, pkg_fe in zip(dep_path, path_fe_ids):
            if pkg_fe not in nodes_by_id:
                synthetic_pkg_nodes[pkg_fe] = {"name": pkg_name, "eco": eco}

        # Repo → first package in path (the direct dependency)
        first_fe = path_fe_ids[0]
        synthetic_uses.setdefault(repo_fe_id, set()).add(first_fe)

        # Every hop: path[i+1] → path[i]  (child → parent, reversed for arrows)
        for parent_fe, child_fe in zip(path_fe_ids, path_fe_ids[1:]):
            synthetic_depends.add((child_fe, parent_fe))  # child → parent direction

    # ---------------------------------------------------------------------------
    # Collect repository nodes → become "root" frontend nodes
    # ---------------------------------------------------------------------------
    repo_nodes = [n for n in nodes_by_id.values() if n["label"] == "Repository"]

    # Collect all EXPOSED_TO edges: repo → vuln (via package)
    # exposed_pkgs: repo_id → set of pkg names that are directly vulnerable
    exposed_direct: dict[str, set[str]] = {}   # repo id → pkg names (direct)
    exposed_trans:  dict[str, set[str]] = {}   # repo id → pkg names (transitive)
    for e in edges_by_rel.get("EXPOSED_TO", []):
        repo_id = e["src"]
        data    = e["data"]
        pkg     = data.get("via_package", "")
        is_direct = data.get("direct", False)
        if is_direct:
            exposed_direct.setdefault(repo_id, set()).add(pkg.lower())
        else:
            exposed_trans.setdefault(repo_id, set()).add(pkg.lower())

    # USES edges: repo → pkgver
    uses_edges: dict[str, list[dict]] = {}
    for e in edges_by_rel.get("USES", []):
        uses_edges.setdefault(e["src"], []).append(e)

    # DEPENDS_ON edges: pkg → pkg  (src=parent, dst=child in DB)
    depends_on_edges = edges_by_rel.get("DEPENDS_ON", [])
    # parent -> set of children  (e.g. ts-node -> {mkdirp, minimist})
    depends_children: dict[str, set[str]] = {}
    # child  -> set of parents   (e.g. minimist -> {ts-node})
    depends_parents: dict[str, set[str]] = {}
    for e in depends_on_edges:
        depends_children.setdefault(e["src"], set()).add(e["dst"])
        depends_parents.setdefault(e["dst"], set()).add(e["src"])

    # AFFECTED_BY: pkgver → vuln
    affected_by: dict[str, list[dict]] = {}
    for e in edges_by_rel.get("AFFECTED_BY", []):
        affected_by.setdefault(e["src"], []).append(e)

    # ---------------------------------------------------------------------------
    # Build frontend nodes list
    # ---------------------------------------------------------------------------
    fe_nodes: list[dict] = []
    fe_links: list[dict] = []
    emitted_ids: set[str] = set()

    # --- Repository nodes → "root" ---
    for repo in repo_nodes:
        d = repo["data"]
        fe_id = f"repo:{d.get('owner','')}/{d.get('name','')}"
        repo_findings = findings_by_repo_node.get(fe_id, [])
        frontend_findings = [
            _finding_to_frontend(f, vulns.get(f["osv_id"], {}), repo_by_id)
            for f in sorted(
                repo_findings,
                key=lambda row: (_severity_rank(row["severity"]), -(row["depth"] or 1)),
                reverse=True,
            )
        ]
        issue_draft = _issue_draft_for_repo(d, repo_findings, vulns) if repo_findings else None
        fe_nodes.append({
            "id":       fe_id,
            "name":     d.get("name", repo["id"]),
            "type":     "root",
            "version":  d.get("commit_sha", "")[:7] if d.get("commit_sha") else None,
            "source":   "GitHub",
            "repoUrl":  d.get("url"),
            "commit":   d.get("commit_sha"),
            "branch":   d.get("branch_ref"),
            "scannedAt": d.get("scanned_at"),
            "exposureScore": d.get("exposure_score", 0),
            "maxRisk": d.get("max_risk", 0),
            "vulnerabilityCount": d.get("vuln_count", len(repo_findings)),
            "criticalCount": d.get("critical_count", 0),
            "directVulnerabilityCount": d.get("direct_vuln_count", 0),
            "findings": frontend_findings,
            "issueDraft": issue_draft,
            "cve":      None,
            "severity": None,
            "fix":      None,
            "desc":     f"Scanned at {d.get('scanned_at','')[:10]}  ·  {d.get('vuln_count',0)} finding(s)" if d.get("vuln_count") else None,
        })
        emitted_ids.add(fe_id)

    # ---------------------------------------------------------------------------
    # --- Package nodes → vulnerable / high / medium / safe ---
    # ---------------------------------------------------------------------------
    # IMPORTANT: We must emit ALL Package nodes from the graph DB — not just
    # ones with findings. Non-vulnerable intermediates like "zipstream" exist
    # only as Package nodes created when builder.py walked dependency_path.
    # If we skip them, _add_link silently drops every edge touching them and
    # the path lodash → zipstream → repo becomes lodash → repo (A→C skip).
    # ---------------------------------------------------------------------------

    # Step 1: collect the set of package fe_ids that are directly vulnerable
    # so we can do a proper transitive "has_vuln_descendant" check below.
    vulnerable_pkg_fe_ids: set[str] = set()
    for f in findings_rows:
        pname = f["package_name"].lower()
        peco  = (f["ecosystem"] or "").lower()
        vulnerable_pkg_fe_ids.add(f"pkg:{pname}:{peco}")

    def _has_vuln_descendant(node_id: str, visited: set[str]) -> bool:
        """
        Walk DEPENDS_ON children recursively.
        node_id is a raw DB node id like 'pkg:zipstream:npm'.
        Returns True if any descendant (child, grandchild…) is vulnerable.
        """
        for child_id in depends_children.get(node_id, set()):
            if child_id in visited:
                continue
            visited.add(child_id)
            cn = nodes_by_id.get(child_id)
            if not cn:
                continue
            cn_name = cn["data"].get("name", "").lower()
            cn_eco  = (cn["data"].get("ecosystem") or cn["ecosystem"] or "").lower()
            cn_fe   = f"pkg:{cn_name}:{cn_eco}"
            if cn_fe in vulnerable_pkg_fe_ids:
                return True
            if _has_vuln_descendant(child_id, visited):
                return True
        return False

    pkg_nodes = [n for n in nodes_by_id.values() if n["label"] in ("Package", "PackageVersion")]
    seen_pkg_keys: set[str] = set()
    package_vuln_links: set[tuple[str, str]] = set()

    for pn in pkg_nodes:
        d      = pn["data"]
        name   = d.get("name", "")
        eco    = d.get("ecosystem") or pn["ecosystem"] or ""
        ver    = d.get("version", "")
        key    = f"{name.lower()}|{eco.lower()}"

        if key in seen_pkg_keys:
            continue
        seen_pkg_keys.add(key)

        fe_id  = f"pkg:{name.lower()}:{eco.lower()}"
        if fe_id in emitted_ids:
            continue
        emitted_ids.add(fe_id)

        # Find scan findings for this package (only vulnerable packages have these)
        pkg_findings = findings_by_pkg.get(key, [])
        frontend_findings = [
            _finding_to_frontend(f, vulns.get(f["osv_id"], {}), repo_by_id)
            for f in sorted(
                pkg_findings,
                key=lambda row: (_severity_rank(row["severity"]), -(row["depth"] or 1)),
                reverse=True,
            )
        ]
        if pkg_findings:
            ver = pkg_findings[0]["version_found"] or ver

        cve_id   = None
        severity = None
        fix_str  = None
        desc_str = None

        if pkg_findings:
            # This package itself is vulnerable
            best      = max(pkg_findings, key=lambda f: _severity_rank(f["severity"]))
            osv_id    = best["osv_id"]
            vuln      = vulns.get(osv_id, {})
            cve_id    = _display_cve(vuln, osv_id)
            severity  = _norm_sev(best["severity"])
            fixed     = vuln.get("fixed_versions", [])
            fix_str   = f"Upgrade to {fixed[0]}+" if fixed else "No fix available yet - monitor upstream"
            desc_str  = vuln.get("summary", "")
            node_type = "vulnerable"
            for finding in frontend_findings:
                vuln_fe_id = f"vuln:{finding['osvId']}"
                if vuln_fe_id not in emitted_ids:
                    emitted_ids.add(vuln_fe_id)
                    fe_nodes.append({
                        "id":          vuln_fe_id,
                        "name":        finding.get("cve") or finding["osvId"],
                        "type":        "vulnerable",
                        "version":     finding.get("version"),
                        "source":      _norm_source(finding.get("ecosystem")),
                        "ecosystem":   finding.get("ecosystem"),
                        "repoUrl":     finding.get("repoUrl"),
                        "findings":    [finding],
                        "affectedRepos": [finding["repoUrl"]] if finding.get("repoUrl") else [],
                        "cve":         finding.get("cve"),
                        "severity":    finding.get("severity"),
                        "fix":         finding.get("fix"),
                        "desc":        finding.get("summary"),
                    })
                package_vuln_links.add((fe_id, vuln_fe_id))
        else:
            # Not directly vulnerable — check if any descendant is vulnerable
            # using the full recursive walk (covers zipstream → lodash etc.)
            if _has_vuln_descendant(pn["id"], {pn["id"]}):
                node_type = "high"
                desc_str  = "Depends on a vulnerable package in its dependency tree."
                fix_str   = "Run a dependency audit and update vulnerable transitive deps."
            else:
                node_type = "safe"

        source = _norm_source(eco)

        fe_nodes.append({
            "id":          fe_id,
            "name":        name,
            "type":        node_type,
            "version":     ver or None,
            "source":      source,
            "ecosystem":   eco,
            "registryUrl": _registry_url(name, eco),
            "repoUrl":     frontend_findings[0]["repoUrl"] if frontend_findings else None,
            "findings":    frontend_findings,
            "affectedRepos": sorted({
                f["repoUrl"] for f in frontend_findings if f.get("repoUrl")
            }),
            "cve":         cve_id,
            "severity":    severity,
            "fix":         fix_str,
            "desc":        desc_str,
        })

    # Emit any synthetic intermediate package nodes not already emitted
    for syn_fe, syn_data in synthetic_pkg_nodes.items():
        if syn_fe in emitted_ids:
            continue
        emitted_ids.add(syn_fe)
        # Check if this synthetic intermediate has any vulnerable descendant
        # by checking whether any of its children in synthetic_depends are vuln
        def _syn_has_vuln(fe: str, seen: set) -> bool:
            for child_fe, parent_fe in synthetic_depends:
                if parent_fe == fe and child_fe not in seen:
                    seen.add(child_fe)
                    if child_fe in vulnerable_pkg_fe_ids:
                        return True
                    if _syn_has_vuln(child_fe, seen):
                        return True
            return False
        is_risky = syn_fe in vulnerable_pkg_fe_ids or _syn_has_vuln(syn_fe, {syn_fe})
        fe_nodes.append({
            "id":          syn_fe,
            "name":        syn_data["name"],
            "type":        "high" if is_risky else "safe",
            "version":     None,
            "source":      _norm_source(syn_data["eco"]),
            "ecosystem":   syn_data["eco"],
            "registryUrl": _registry_url(syn_data["name"], syn_data["eco"]),
            "repoUrl":     None,
            "findings":    [],
            "affectedRepos": [],
            "cve":         None,
            "severity":    None,
            "fix":         "Run a dependency audit and update vulnerable transitive deps." if is_risky else None,
            "desc":        "Depends on a vulnerable package in its dependency tree." if is_risky else None,
        })

    # ---------------------------------------------------------------------------
    # Build frontend links
    # ---------------------------------------------------------------------------
    emitted_link_keys: set[tuple] = set()

    def _add_link(s: str, t: str, direct: bool):
        k = (s, t)
        if k not in emitted_link_keys and s in emitted_ids and t in emitted_ids:
            emitted_link_keys.add(k)
            fe_links.append({"s": s, "t": t, "d": direct})

    # 1. vuln-node → package  (CVE bubble points to the package carrying it)
    for pkg_fe, vuln_fe in package_vuln_links:
        _add_link(vuln_fe, pkg_fe, False)

    # 2. Package → Repo  (via USES edges: package points toward the repo that uses it)
    #    Only emit this link if the package is a DIRECT dependency of the repo.
    #    Transitive packages reach the repo through intermediate DEPENDS_ON links (step 3).
    for repo in repo_nodes:
        repo_fe_id = f"repo:{repo['data'].get('owner','')}/{repo['data'].get('name','')}"
        for use_edge in uses_edges.get(repo["id"], []):
            pkgver_id = use_edge["dst"]
            pkgver    = nodes_by_id.get(pkgver_id)
            if not pkgver:
                continue
            pd        = pkgver["data"]
            pname     = pd.get("name", "")
            peco      = pd.get("ecosystem") or pkgver["ecosystem"] or ""
            pkg_fe    = f"pkg:{pname.lower()}:{peco.lower()}"
            is_direct = use_edge["data"].get("direct", True)
            # Arrow: pkg → repo
            _add_link(pkg_fe, repo_fe_id, is_direct)

    # 3. Package → Package  (DEPENDS_ON, reversed: child → parent)
    #    DB stores src=parent, dst=child.  We emit dst→src so the arrow
    #    reads: lodash → zipstream → ts-node → repo (vulnerability flows up).
    for e in depends_on_edges:
        src_node = nodes_by_id.get(e["src"])   # parent
        dst_node = nodes_by_id.get(e["dst"])   # child
        if not src_node or not dst_node:
            continue
        sd    = src_node["data"]
        dd    = dst_node["data"]
        s_eco = sd.get("ecosystem") or src_node["ecosystem"] or ""
        d_eco = dd.get("ecosystem") or dst_node["ecosystem"] or ""
        s_fe  = f"pkg:{sd.get('name','').lower()}:{s_eco.lower()}"   # parent fe id
        d_fe  = f"pkg:{dd.get('name','').lower()}:{d_eco.lower()}"   # child fe id
        # child → parent: lodash → zipstream → ts-node
        _add_link(d_fe, s_fe, False)

    # 4. Synthetic repo → direct-dep links (from dependency_path[0])
    for repo_fe_id, pkg_fe_set in synthetic_uses.items():
        for pkg_fe in pkg_fe_set:
            _add_link(pkg_fe, repo_fe_id, True)

    # 5. Synthetic child → parent links for every hop in dependency_path
    for child_fe, parent_fe in synthetic_depends:
        _add_link(child_fe, parent_fe, False)

    return {"nodes": fe_nodes, "links": fe_links}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/healthz")
def health():
    return {"status": "ok"}


@app.get("/api/graph")
def get_graph():
    """
    Returns the vulnerability graph in the exact shape the frontend expects:
        { nodes: [...], links: [...] }
    """
    try:
        data = _build_frontend_graph()
        return JSONResponse(content=data)
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@app.get("/api/graph/raw")
def get_raw_graph():
    """Returns the raw internal graph nodes and edges."""
    from vulnalyzer.graph.export import get_graph_json
    try:
        return JSONResponse(content=get_graph_json())
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


# ---------------------------------------------------------------------------
# Pipeline status
# ---------------------------------------------------------------------------

@app.get("/api/status")
def get_status():
    """
    Returns a summary of what's in the database — lets the frontend
    know whether it's in demo mode or has real data.
    """
    try:
        init_db()
        with get_conn() as conn:
            vuln_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            repo_count = conn.execute("SELECT COUNT(*) FROM repos").fetchone()[0]
            scan_count = conn.execute("SELECT COUNT(*) FROM repo_scans WHERE status='SCANNED_OK'").fetchone()[0]
            finding_count = conn.execute("SELECT COUNT(*) FROM scan_findings").fetchone()[0]
            node_count = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
            last_scan = conn.execute(
                "SELECT scanned_at FROM repo_scans ORDER BY scanned_at DESC LIMIT 1"
            ).fetchone()

        return JSONResponse(content={
            "hasData": vuln_count > 0 and node_count > 0,
            "vulnerabilities": vuln_count,
            "repos": repo_count,
            "scans": scan_count,
            "findings": finding_count,
            "graphNodes": node_count,
            "lastScan": last_scan[0] if last_scan else None,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


# ---------------------------------------------------------------------------
# Pipeline: ingest CVEs
# ---------------------------------------------------------------------------

@app.post("/api/pipeline/ingest")
def run_ingest(package: str, ecosystem: str, version: str | None = None):
    """
    Trigger CVE ingestion from OSV for a given package + ecosystem.

    Query params: package, ecosystem, version (optional)
    """
    from vulnalyzer.ingest.osv import ingest_package
    try:
        count = ingest_package(package, ecosystem, version or None)
        return JSONResponse(content={
            "ok": True,
            "package": package,
            "ecosystem": ecosystem,
            "stored": count,
            "message": f"Ingested {count} vulnerability record(s) for {ecosystem}/{package}",
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Pipeline: scan repositories
# ---------------------------------------------------------------------------

@app.post("/api/pipeline/scan")
def run_scan(url: str, force: bool = False):
    """
    Trigger a scan of a single GitHub repository URL.

    Query params: url, force (optional, default false)
    """
    from vulnalyzer.scanner.engine import scan_repo
    _FAILED_STATUSES = {"FETCH_FAILED", "INVALID_URL", "ERROR"}
    _STATUS_MSGS = {
        "FETCH_FAILED": (
            "Could not fetch repository from GitHub. "
            "Check the URL is correct and set the GITHUB_TOKEN environment variable "
            "(unauthenticated GitHub API is rate-limited to 60 req/hr)."
        ),
        "INVALID_URL": "Invalid GitHub URL. Expected: https://github.com/owner/repo",
        "NO_MANIFEST": (
            "Scan succeeded but no supported manifest files were found "
            "(package.json, requirements.txt, go.mod, Cargo.toml, pom.xml, etc.). "
            "Ensure the repository contains a dependency manifest."
        ),
        "ERROR": "An unexpected error occurred during scanning.",
    }
    try:
        result = scan_repo(url, force=force)
        is_ok = result.status not in _FAILED_STATUSES
        resp: dict = {
            "ok": is_ok,
            "repoUrl": result.repo_url,
            "status": result.status,
            "skipped": result.skipped,
            "manifests": result.manifests_found,
            "findings": len(result.findings),
            "severityCounts": result.severity_counts,
            "revisionId": result.revision_id[:12] if result.revision_id else None,
            "branchRef": result.branch_ref,
        }
        if not is_ok:
            resp["error"] = _STATUS_MSGS.get(
                result.status, f"Scan failed with status: {result.status}"
            )
        return JSONResponse(content=resp)
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@app.post("/api/pipeline/scan/batch")
async def run_batch_scan(request: Request):
    """
    Trigger batch scan from a JSON body: { "urls": [...], "force": false }
    """
    from vulnalyzer.scanner.engine import batch_scan
    try:
        body = await request.json()
        urls = body.get("urls", [])
        force = body.get("force", False)
        if not urls:
            return JSONResponse(status_code=400, content={"ok": False, "error": "No URLs provided"})
        results = batch_scan(urls, force=force)
        summary = [
            {
                "url": r.repo_url,
                "status": r.status,
                "findings": len(r.findings),
                "skipped": r.skipped,
            }
            for r in results
        ]
        return JSONResponse(content={
            "ok": True,
            "total": len(results),
            "results": summary,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Pipeline: rebuild graph
# ---------------------------------------------------------------------------

@app.post("/api/pipeline/build-graph")
def run_build_graph():
    """Rebuild the vulnerability propagation graph from all scan data."""
    from vulnalyzer.graph.builder import build_graph
    try:
        summary = build_graph()
        return JSONResponse(content={
            "ok": True,
            "nodes": summary["nodes"],
            "edges": summary["edges"],
            "message": f"Graph rebuilt: {summary['nodes']} nodes, {summary['edges']} edges",
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Pipeline: full run (ingest + scan repos from file + build graph)
# ---------------------------------------------------------------------------

@app.post("/api/pipeline/run-all")
async def run_all(request: Request):
    """
    Convenience endpoint: ingest a list of packages, scan a list of repos,
    then rebuild the graph.

    Body: {
        "packages": [{"package": "lodash", "ecosystem": "npm"}, ...],
        "repos": ["https://github.com/..."],
        "force": false
    }
    """
    from vulnalyzer.ingest.osv import ingest_package
    from vulnalyzer.scanner.engine import batch_scan
    from vulnalyzer.graph.builder import build_graph

    try:
        body = await request.json()
        packages = body.get("packages", [])
        repos    = body.get("repos", [])
        force    = body.get("force", False)

        ingested = 0
        for p in packages:
            ingested += ingest_package(p["package"], p["ecosystem"])

        scan_results = batch_scan(repos, force=force)
        graph_summary = build_graph()

        return JSONResponse(content={
            "ok": True,
            "ingested": ingested,
            "scanned": len(scan_results),
            "findings": sum(len(r.findings) for r in scan_results),
            "graph": graph_summary,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Repos: list tracked repos with their scan status
# ---------------------------------------------------------------------------

@app.get("/api/repos")
def list_repos():
    """Returns all tracked repositories with their latest scan metadata."""
    try:
        init_db()
        with get_conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    r.id, r.platform, r.owner, r.name, r.url,
                    r.last_scanned_sha,
                    (SELECT MAX(rs.scanned_at) FROM repo_scans rs WHERE rs.repo_id=r.id) AS last_scanned_at,
                    (SELECT COUNT(*) FROM repo_scans rs WHERE rs.repo_id=r.id AND rs.status='SCANNED_OK') AS scan_count,
                    (SELECT COUNT(*) FROM scan_findings sf
                     JOIN repo_scans rs ON rs.id=sf.scan_id
                     WHERE rs.repo_id=r.id) AS finding_count
                FROM repos r
                ORDER BY last_scanned_at DESC
                """
            ).fetchall()
        return JSONResponse(content={
            "repos": [
                {
                    "id": r["id"],
                    "platform": r["platform"],
                    "owner": r["owner"],
                    "name": r["name"],
                    "url": r["url"],
                    "lastScanSha": r["last_scanned_sha"],
                    "lastScannedAt": r["last_scanned_at"],
                    "scanCount": r["scan_count"],
                    "findingCount": r["finding_count"],
                }
                for r in rows
            ]
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


# ---------------------------------------------------------------------------
# CVEs: list ingested vulnerabilities
# ---------------------------------------------------------------------------

@app.get("/api/vulns")
def list_vulns(ecosystem: str | None = None):
    """Returns all ingested vulnerability records, optionally filtered by ecosystem."""
    try:
        init_db()
        with get_conn() as conn:
            if ecosystem:
                rows = conn.execute(
                    "SELECT osv_id, package_name, ecosystem, summary, severity, fixed_versions FROM vulnerabilities WHERE ecosystem=? ORDER BY severity DESC",
                    (ecosystem,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT osv_id, package_name, ecosystem, summary, severity, fixed_versions FROM vulnerabilities ORDER BY severity DESC"
                ).fetchall()

        import json as _json
        return JSONResponse(content={
            "vulns": [
                {
                    "osvId": r["osv_id"],
                    "package": r["package_name"],
                    "ecosystem": r["ecosystem"],
                    "summary": r["summary"],
                    "severity": r["severity"],
                    "type": "Unknown",
                    "fixedVersions": _json.loads(r["fixed_versions"] or "[]"),
                }
                for r in rows
            ]
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


# ---------------------------------------------------------------------------
# Patch request draft for a specific repo
# ---------------------------------------------------------------------------

@app.get("/api/patch-request")
def get_patch_request(owner: str, repo: str, platform: str = "github", use_ai: bool = False):
    """
    Generate a GitHub issue patch-request draft for a specific repository.

    Query params:
      owner    — repo owner
      repo     — repo name
      platform — git platform (default: github)
      use_ai   — include Gemini AI patch recommendations (default: false)
                 Requires GEMINI_API_KEY env var to be set.
    """
    try:
        init_db()
        with get_conn() as conn:
            repo_row = conn.execute(
                "SELECT * FROM repos WHERE platform=? AND owner=? AND name=?",
                (platform, owner, repo),
            ).fetchone()

            if not repo_row:
                return JSONResponse(status_code=404, content={"error": "Repo not found"})

            scan_row = conn.execute(
                "SELECT * FROM repo_scans WHERE repo_id=? AND status='SCANNED_OK' ORDER BY scanned_at DESC LIMIT 1",
                (repo_row["id"],),
            ).fetchone()

            if not scan_row:
                return JSONResponse(status_code=404, content={"error": "No successful scan found for this repo"})

            finding_rows = conn.execute(
                "SELECT * FROM scan_findings WHERE scan_id=?", (scan_row["id"],)
            ).fetchall()

            vulns_list = get_all_vulnerabilities(conn)
            vulns = {v["osv_id"]: v for v in vulns_list}

        # Build Finding + ScanResult objects
        findings = []
        for f in finding_rows:
            vuln = vulns.get(f["osv_id"], {})
            findings.append(Finding(
                package_name=f["package_name"],
                ecosystem=f["ecosystem"],
                version_found=f["version_found"],
                is_direct=bool(f["is_direct"]),
                manifest_source=f["manifest_source"],
                osv_id=f["osv_id"],
                severity=((_norm_sev(f["severity"]) or "UNKNOWN").upper()),
                summary=vuln.get("summary", ""),
                fixed_versions=vuln.get("fixed_versions", []),
                is_dev=bool(f["is_dev"]),
                parent_package=f["parent_package"],
                depth=f["depth"] or 1,
                dependency_path=json.loads(f["dependency_path"] or "[]"),
            ))

        scan_result = ScanResult(
            repo_url=repo_row["url"],
            platform=repo_row["platform"],
            owner=repo_row["owner"],
            repo_name=repo_row["name"],
            revision_id=scan_row["commit_sha"] or "",
            branch_ref=scan_row["branch_ref"] or "",
            status="SCANNED_OK",
            findings=findings,
        )

        if use_ai:
            gemini_key = os.environ.get("GEMINI_API_KEY")
            if not gemini_key:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": (
                            "GEMINI_API_KEY is not set. "
                            "Get a free key at https://aistudio.google.com/app/apikey "
                            "then POST to /api/config/gemini-key or set the env var."
                        )
                    },
                )
            body = generate_issue_body_with_ai(scan_result, use_ai=True, api_key=gemini_key)
        else:
            body = generate_issue_body(scan_result)

        return JSONResponse(content={
            "ok": True,
            "title": generate_issue_title(scan_result),
            "body": body,
            "used_ai": use_ai,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


# ---------------------------------------------------------------------------
# Gemini API key configuration
# ---------------------------------------------------------------------------

@app.post("/api/config/gemini-key")
async def set_gemini_key(request: Request):
    """
    Set the GEMINI_API_KEY used for AI patch recommendations.

    Body: { "key": "<your-gemini-api-key>" }

    Get a free key at: https://aistudio.google.com/app/apikey
    """
    try:
        body = await request.json()
        key = (body.get("key") or "").strip()
        if key:
            os.environ["GEMINI_API_KEY"] = key
            return JSONResponse(content={"ok": True, "message": "Gemini API key configured."})
        else:
            os.environ.pop("GEMINI_API_KEY", None)
            return JSONResponse(content={"ok": True, "message": "Gemini API key cleared."})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@app.get("/api/config/gemini-key")
def get_gemini_key_status():
    """Returns whether a Gemini API key is currently configured (never returns the key itself)."""
    key = os.environ.get("GEMINI_API_KEY", "")
    return JSONResponse(content={
        "configured": bool(key),
        "preview": f"{key[:4]}...{key[-4:]}" if len(key) >= 8 else None,
    })



# ---------------------------------------------------------------------------
# GitHub token configuration
# ---------------------------------------------------------------------------

@app.post("/api/config/github-token")
async def set_github_token(request: Request):
    """
    Set or clear the GITHUB_TOKEN used for GitHub API requests.
    Body: { "token": "<personal-access-token>" }
    """
    try:
        body = await request.json()
        token = (body.get("token") or "").strip()
        if token:
            os.environ["GITHUB_TOKEN"] = token
            return JSONResponse(content={"ok": True, "message": "GitHub token configured successfully."})
        else:
            os.environ.pop("GITHUB_TOKEN", None)
            return JSONResponse(content={"ok": True, "message": "GitHub token cleared."})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


@app.get("/api/config/github-token")
def get_github_token_status():
    """Returns whether a GitHub token is currently configured (never returns the token itself)."""
    token = os.environ.get("GITHUB_TOKEN", "")
    return JSONResponse(content={
        "configured": bool(token),
        "preview": f"{token[:4]}...{token[-4:]}" if len(token) >= 8 else None,
    })


# ---------------------------------------------------------------------------
# Pipeline: batch scan from CSV / newline-separated URL list
# ---------------------------------------------------------------------------

@app.post("/api/pipeline/scan/csv")
async def run_csv_scan(request: Request):
    """
    Scan multiple repos from a plain-text or CSV body.

    Accepts either:
      - Content-Type: text/plain  — newline-separated GitHub URLs
      - Content-Type: application/json — { "urls": [...], "force": false }

    Lines starting with # are ignored (comments).
    For CSV files, the first column (split by comma) is used as the URL.
    """
    from vulnalyzer.scanner.engine import batch_scan
    try:
        content_type = request.headers.get("content-type", "")
        if "json" in content_type:
            body = await request.json()
            urls = body.get("urls", [])
            force = body.get("force", False)
        else:
            raw = (await request.body()).decode("utf-8", errors="replace")
            force = False
            urls = []
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Take first CSV column
                url = line.split(",")[0].strip()
                if url.startswith("http"):
                    urls.append(url)

        # Deduplicate while preserving order
        seen: set = set()
        deduped = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        urls = deduped

        if not urls:
            return JSONResponse(status_code=400, content={"ok": False, "error": "No valid GitHub URLs found in input."})

        results = batch_scan(urls, force=force)
        _FAILED = {"FETCH_FAILED", "INVALID_URL", "ERROR"}
        summary = [
            {
                "url": r.repo_url,
                "status": r.status,
                "ok": r.status not in _FAILED,
                "findings": len(r.findings),
                "skipped": r.skipped,
                "manifests": r.manifests_found,
            }
            for r in results
        ]
        ok_count = sum(1 for s in summary if s["ok"])
        return JSONResponse(content={
            "ok": True,
            "total": len(results),
            "succeeded": ok_count,
            "failed": len(results) - ok_count,
            "results": summary,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Serve the frontend HTML from /
# ---------------------------------------------------------------------------
_FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "index.html"

@app.get("/")
def serve_frontend():
    if _FRONTEND.exists():
        return FileResponse(str(_FRONTEND))
    return JSONResponse(
        status_code=404,
        content={"error": f"Frontend not found at {_FRONTEND}. Place index.html in frontend/"}
    )
