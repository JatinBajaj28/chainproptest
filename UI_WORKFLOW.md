# Vulnalyzer — Complete UI-Based Workflow (No CLI Needed)
# =========================================================

## STEP 1: Setup (One Time - CLI Only)
## ====================================

These steps you still do in terminal once, then everything is UI:

```bash
# Extract
unzip vulnalyzer-updated.zip
cd vulnalyzer-src

# Install
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Initialize database
python3 -c "from vulnalyzer.core.db import init_db; init_db()"

# Start the server
python3 run.py
```

Output should show:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```


## STEP 2: Open Browser & Access UI
## ==================================

Open: http://localhost:8000

You'll see the Vulnalyzer dashboard with a "Live Badge" button in the top right.


## STEP 3: Open Pipeline Control Panel
## =====================================

3.1) In the UI, click the orange/green "Live Badge" button (top right)
     - This opens the pipeline control panel
     - You'll see 4 sections: Ingest, Scan, Build Graph, Run All


## STEP 4: INGEST CVEs (Through UI)
## ==================================

4.1) In Pipeline panel, you'll see:
     - Package name input field: "e.g. lodash"
     - Ecosystem dropdown/input: "e.g. npm"
     - "Ingest" button

4.2) Enter package details:
     Package:   lodash
     Ecosystem: npm
     Click "Ingest"
     
     → CVEs from OSV database are downloaded and stored ✓

4.3) Repeat for other packages:
     Package:   Newtonsoft.Json
     Ecosystem: NuGet
     Click "Ingest"
     
     Package:   django
     Ecosystem: PyPI
     Click "Ingest"
     
     Package:   golang.org/x/net
     Ecosystem: Go
     Click "Ingest"
     
     Package:   openssl-sys
     Ecosystem: crates.io
     Click "Ingest"
     
     Package:   org.apache.logging.log4j:log4j-core
     Ecosystem: Maven
     Click "Ingest"


## STEP 5: SCAN REPOSITORIES (Through UI)
## ========================================

5.1) In Pipeline panel, you'll see:
     - GitHub URL input field
     - "Scan" button
     - "Batch Scan" button (for multiple repos)

5.2) Enter a repo URL:
     https://github.com/dotnet/aspnetcore
     Click "Scan"
     
     → Repo is downloaded, manifests parsed, CVEs matched ✓
     → Status shows: "SCANNED_OK · X finding(s)"

5.3) Scan more repos:
     https://github.com/expressjs/express
     Click "Scan"
     
     https://github.com/django/django
     Click "Scan"
     
     https://github.com/gin-gonic/gin
     Click "Scan"

5.4) For batch scanning (multiple at once):
     Click "Load batch file" or paste multiple URLs
     Click "Batch Scan"
     
     → All repos scanned sequentially ✓


## STEP 6: BUILD DEPENDENCY GRAPH (Through UI)
## =============================================

6.1) In Pipeline panel:
     Click "Build Graph" button
     
     → Graph is reconstructed from all scans
     → Status shows: "Graph built: X nodes, Y edges" ✓


## STEP 7: VIEW RESULTS IN UI
## ============================

7.1) Close pipeline panel (click elsewhere)

7.2) You'll now see:
     - Dependency graph visualization (center)
     - Node list with filters (left sidebar)
     - Details panel (right sidebar)

7.3) Filter by ecosystem:
     - Left sidebar has source filter
     - Click "npm", "PyPI", "Maven", "Go", "crates.io", "NuGet"
     - Graph updates to show only selected ecosystem ✓

7.4) View CVE details:
     - Click any vulnerable node (red)
     - Right panel shows: CVE ID, severity, fix recommendations
     - Click "View on registry" link to package registry
     - Click "OSV Link" to open OSV.dev details ✓

7.5) View exposure scores:
     - Click a Repository node (blue)
     - See: Exposure score, critical findings count, total findings
     - See which packages cause the exposure ✓


## STEP 8: ONE-CLICK "RUN ALL" (Through UI)
## ==========================================

If you have test_repos.txt in the project root:

8.1) In Pipeline panel:
     Click "Run All" button
     
     This automatically:
     ✓ Ingest all CVEs from test_repos.txt
     ✓ Scan all repos from test_repos.txt
     ✓ Build the graph
     
     Watch progress in real-time!


## COMPLETE UI WORKFLOW (Summary)
## ================================

```
1. python3 run.py
   ↓
2. Open http://localhost:8000
   ↓
3. Click Live Badge (top right)
   ↓
4. Enter package → Click Ingest
   (repeat for multiple packages)
   ↓
5. Enter repo URL → Click Scan
   (repeat for multiple repos)
   ↓
6. Click "Build Graph"
   ↓
7. Close pipeline panel
   ↓
8. Explore graph & filter by ecosystem
```


## UI SCREENSHOT WALKTHROUGH
## ==========================

When you open http://localhost:8000:

┌─────────────────────────────────────────────────────────┐
│  Vulnalyzer                              [Live Badge] ↗ │  ← Click this
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────┐    ┌──────────────┐    ┌────────────┐  │
│  │ FILTER     │    │              │    │  DETAILS   │  │
│  │            │    │   GRAPH      │    │            │  │
│  │ npm ☑      │    │              │    │ Node info  │  │
│  │ PyPI ☑     │    │   ◯──USES──◯ │    │ CVEs       │  │
│  │ Maven      │    │   │         │    │ Fix        │  │
│  │ Go         │    │   ◯──◯──◯──◯│    │            │  │
│  │ crates.io  │    │              │    │            │  │
│  │ NuGet      │    │              │    └────────────┘  │
│  └────────────┘    └──────────────┘                    │
│                                                          │
└─────────────────────────────────────────────────────────┘

When you click Live Badge:

┌─────────────────────────────────────────────────────────┐
│  PIPELINE CONTROLS                            [X]        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  📦 INGEST CVEs                                         │
│  Package: [lodash________________]                      │
│  Ecosystem: [npm ▼]                                     │
│  [Ingest] [Status: ✓ Stored 5 vulns]                   │
│                                                          │
│  🔍 SCAN REPOSITORY                                     │
│  URL: [https://github.com/expressjs/express]           │
│  [Scan] [Status: ✓ Found 3 findings]                   │
│                                                          │
│  📊 BUILD GRAPH                                         │
│  [Build Graph] [Status: ✓ 42 nodes, 156 edges]        │
│                                                          │
│  ⚡ RUN ALL (load test_repos.txt)                       │
│  [Run All] [Progress: 3/15 repos scanned...]           │
│                                                          │
└─────────────────────────────────────────────────────────┘


## API ENDPOINTS (For Reference)
## ===============================

These are called automatically by the UI:

POST /api/pipeline/ingest
  Body: { "package": "lodash", "ecosystem": "npm" }
  → Fetches CVEs from OSV, stores in DB

POST /api/pipeline/scan
  Body: { "url": "https://github.com/...", "force": false }
  → Scans repo, finds manifests, matches CVEs

POST /api/pipeline/scan/batch
  Body: { "urls": ["repo1", "repo2", ...] }
  → Scans multiple repos sequentially

POST /api/pipeline/build-graph
  → Reconstructs graph from all scan results

POST /api/pipeline/run-all
  Body: { "file": "test_repos.txt" }
  → Ingest + Scan + Build in one call

GET /api/graph
  → Returns dependency graph for visualization

GET /api/vulns?ecosystem=npm
  → Returns all ingested CVEs (filtered by ecosystem)

GET /api/repos
  → Returns all scanned repositories

GET /api/patch-request?owner=owner&repo=repo
  → Generates GitHub issue draft with fixes


## KEYBOARD SHORTCUTS (In Graph)
## ==============================

Ctrl+F     Search packages in graph
Click      Select node, show details
Drag       Pan the graph
Scroll     Zoom in/out
Double-click  Center on node


## WHAT IF API IS NOT RESPONDING?
## ================================

Problem: UI shows "Error connecting to backend"

Solution:
1. Make sure python3 run.py is still running
2. Check terminal for error messages
3. Try http://localhost:8000/healthz (should return {"status": "ok"})
4. Restart the server:
   - Press Ctrl+C in terminal
   - Run: python3 run.py again


## ADVANCED: MONITOR INGESTION PROGRESS
## ======================================

While ingesting/scanning in UI:

Open browser console (F12 → Console tab):
- You'll see real-time status updates
- Watch as CVEs are downloaded
- See when repos are scanned
- Graph building progress

In the server terminal (where you ran python3 run.py):
- You'll see detailed logs
- Helps debug if anything fails


## COMPLETE EXAMPLE WORKFLOW
## ===========================

1. Terminal:
   python3 run.py

2. Browser:
   http://localhost:8000

3. Click Live Badge

4. Ingest CVEs:
   Package: lodash, Ecosystem: npm → Ingest ✓
   Package: django, Ecosystem: PyPI → Ingest ✓
   Package: Newtonsoft.Json, Ecosystem: NuGet → Ingest ✓

5. Scan repos:
   URL: https://github.com/expressjs/express → Scan ✓
   URL: https://github.com/django/django → Scan ✓
   URL: https://github.com/dotnet/aspnetcore → Scan ✓

6. Build Graph:
   Click "Build Graph" ✓

7. Explore:
   - Filter by npm → see express dependencies
   - Filter by PyPI → see django dependencies
   - Filter by NuGet → see aspnetcore dependencies
   - Click on CVEs to see details
   - See exposure scores for each repo ✓


THAT'S IT! Everything is done through the UI. No CLI commands needed after setup.
