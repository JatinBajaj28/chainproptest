# Vulnalyzer — Complete Step-by-Step Setup & Execution Guide
# ============================================================

## STEP 1: Extract and Setup
## ==========================

1.1) Extract the zip file:
   - Download: vulnalyzer-updated.zip
   - Extract it to your machine (e.g., ~/projects/vulnalyzer-updated/)
   
   Command:
   ```
   unzip vulnalyzer-updated.zip -d ~/projects/
   cd ~/projects/vulnalyzer-src
   ```

1.2) Verify the directory structure:
   ```
   ls -la
   ```
   
   You should see:
   - vulnalyzer/     (main package)
   - frontend/       (HTML UI)
   - scripts/        (CLI scripts)
   - tests/          (test files)
   - requirements.txt
   - run.py
   - test_repos.txt
   - README.md


## STEP 2: Install Dependencies
## ==============================

2.1) Install Python (if not already installed):
   - Python 3.10+ required
   - Verify: `python3 --version`

2.2) Create a virtual environment (recommended):
   ```
   python3 -m venv venv
   source venv/bin/activate    # On Windows: venv\Scripts\activate
   ```

2.3) Install required packages:
   ```
   pip install -r requirements.txt
   ```
   
   This installs: fastapi, uvicorn, requests, etc.

2.4) Verify installation:
   ```
   python3 -c "import fastapi; print('FastAPI OK')"
   python3 -c "import requests; print('Requests OK')"
   ```


## STEP 3: Initialize the Database
## =================================

3.1) Initialize the SQLite database:
   ```
   python3 -c "from vulnalyzer.core.db import init_db; init_db(); print('DB initialized')"
   ```
   
   This creates `vulnalyzer.db` in your current directory.

3.2) Verify database was created:
   ```
   ls -lh vulnalyzer.db
   ```
   
   Should show a file ~50KB in size.


## STEP 4: Ingest CVE Data for NuGet Packages
## ============================================

4.1) Open your terminal and run EACH ingest command separately:

   Command 1 — Ingest Newtonsoft.Json CVEs:
   ```
   python3 scripts/ingest_cves.py --package Newtonsoft.Json --ecosystem NuGet
   ```
   
   Expected output:
   ```
   INFO:vulnalyzer.ingest.osv:Querying OSV: NuGet / Newtonsoft.Json
   INFO:vulnalyzer.ingest.osv:Found X advisories from OSV.
   INFO:vulnalyzer.ingest.osv:Stored/updated X vulnerability records.
   ```

   Command 2 — Ingest System.Text.Json CVEs:
   ```
   python3 scripts/ingest_cves.py --package System.Text.Json --ecosystem NuGet
   ```

   Command 3 — Ingest log4j CVEs (for Maven example):
   ```
   python3 scripts/ingest_cves.py --package org.apache.logging.log4j:log4j-core --ecosystem Maven
   ```

   Command 4 — Ingest lodash CVEs (for npm example):
   ```
   python3 scripts/ingest_cves.py --package lodash --ecosystem npm
   ```

   Command 5 — Ingest golang x/net CVEs (for Go example):
   ```
   python3 scripts/ingest_cves.py --package golang.org/x/net --ecosystem Go
   ```

   Command 6 — Ingest openssl-sys CVEs (for crates.io example):
   ```
   python3 scripts/ingest_cves.py --package openssl-sys --ecosystem crates.io
   ```

4.2) What each command does:
   - Queries the OSV (Open Source Vulnerabilities) API
   - Fetches all known CVEs for that package + ecosystem
   - Stores them in your local vulnalyzer.db

4.3) Monitor the ingestion:
   - Each command should take 10-30 seconds
   - You'll see progress: "Found X advisories from OSV"
   - If it says "No vulnerabilities found" — that package may have no public CVEs


## STEP 5: Scan a Repository
## ===========================

5.1) Scan the ASP.NET Core repo:
   ```
   python3 scripts/scan_repo.py https://github.com/dotnet/aspnetcore
   ```
   
   Expected output:
   ```
   INFO:vulnalyzer.scanner.engine:Scanning [1/1]: https://github.com/dotnet/aspnetcore
   ✓ SCANNED_OK · X finding(s) · manifests: package.json, packages.config, ...
   ```

5.2) What the scan does:
   - Downloads the repo from GitHub
   - Finds all manifest files (package.json, pom.xml, go.mod, Cargo.toml, etc.)
   - Parses each manifest to extract dependencies
   - Matches dependencies against the CVE database you ingested
   - Stores findings in vulnalyzer.db

5.3) This time, you should see X finding(s) instead of 0!


## STEP 6: Build the Dependency Graph
## ====================================

6.1) Build the graph (processes all scans and creates relationships):
   ```
   python3 scripts/build_graph.py
   ```
   
   Expected output:
   ```
   INFO:vulnalyzer.graph.builder:Graph built: X nodes, Y edges
   ```

6.2) What this does:
   - Creates nodes: Repository, Package, PackageVersion, Vulnerability
   - Creates edges: USES, INSTANCE_OF, AFFECTED_BY, DEPENDS_ON, EXPOSED_TO
   - Calculates exposure scores for each repo
   - Identifies transitive dependencies


## STEP 7: Start the Web UI
## =========================

7.1) Start the API server:
   ```
   python3 run.py
   ```
   
   Expected output:
   ```
   INFO:     Uvicorn running on http://127.0.0.1:8000
   Press CTRL+C to quit
   ```

7.2) Open your browser:
   - URL: http://localhost:8000
   - You should see the Vulnalyzer dashboard with the dependency graph
   - Filter by ecosystem: npm, PyPI, Maven, Go, crates.io, NuGet
   - Click on nodes to see details

7.3) Stop the server:
   - In terminal: press Ctrl+C


## STEP 8: Scan Multiple Repos (Batch Mode)
## ==========================================

8.1) Using test_repos.txt (included in the zip):
   ```
   python3 scripts/batch_scan.py test_repos.txt
   ```
   
   This file contains 15 repos across all 6 ecosystems:
   - npm: express, create-react-app, axios
   - PyPI: django, flask, ansible
   - Maven: spring-framework, mybatis-3
   - Go: gin-gonic/gin, hashicorp/terraform, grpc/grpc-go
   - crates.io: tokio, actix-web, reqwest
   - NuGet: dotnet/aspnetcore, SignalR, NuGetGallery

8.2) Format of test_repos.txt (if you want to customize):
   ```
   REPO_URL    https://github.com/owner/repo
   ECOSYSTEM   npm
   PACKAGE     lodash
   
   REPO_URL    https://github.com/owner/repo2
   ECOSYSTEM   PyPI
   PACKAGE     django
   ```

8.3) Ingest CVEs for all packages in test_repos.txt:
   ```
   # Create a script to ingest all at once
   python3 scripts/ingest_cves.py --package lodash --ecosystem npm
   python3 scripts/ingest_cves.py --package django --ecosystem PyPI
   python3 scripts/ingest_cves.py --package org.apache.logging.log4j:log4j-core --ecosystem Maven
   python3 scripts/ingest_cves.py --package golang.org/x/net --ecosystem Go
   python3 scripts/ingest_cves.py --package openssl-sys --ecosystem crates.io
   python3 scripts/ingest_cves.py --package Newtonsoft.Json --ecosystem NuGet
   ```

8.4) Then scan all repos:
   ```
   python3 scripts/batch_scan.py test_repos.txt
   ```

8.5) Rebuild the graph:
   ```
   python3 scripts/build_graph.py
   ```

8.6) Start the UI again:
   ```
   python3 run.py
   ```


## STEP 9: Quick Test with Single Repo
## =====================================

9.1) Quick test flow (for impatient users):
   ```
   # Terminal 1: Ingest CVEs
   python3 scripts/ingest_cves.py --package lodash --ecosystem npm
   
   # Terminal 1: Scan repo
   python3 scripts/scan_repo.py https://github.com/expressjs/express
   
   # Terminal 1: Build graph
   python3 scripts/build_graph.py
   
   # Terminal 1: Start UI
   python3 run.py
   ```

9.2) Then in your browser:
   - http://localhost:8000
   - Filter by npm
   - Click on "lodash" node
   - See CVE-2021-23337 details


## TROUBLESHOOTING
## ================

Problem: "ModuleNotFoundError: No module named 'fastapi'"
Solution: Run: pip install -r requirements.txt

Problem: "GitHub API rate limit hit"
Solution: Set GITHUB_TOKEN env var
   ```
   export GITHUB_TOKEN=your_github_token_here
   python3 scripts/scan_repo.py ...
   ```

Problem: "No vulnerabilities found" after scan
Solution: You haven't ingested CVEs yet!
   Run step 4 first (ingest_cves.py commands)

Problem: Scan shows "FETCH_FAILED"
Solution: GitHub repo doesn't exist or network issue
   Check URL is correct and you have internet

Problem: Port 8000 already in use
Solution: Use different port
   ```
   python3 -c "from vulnalyzer.api.app import app; import uvicorn; uvicorn.run(app, port=8001)"
   ```


## COMPLETE MINIMAL EXAMPLE
## =========================

Copy-paste these commands in order (takes ~5 min):

```bash
# Setup
cd ~/projects/vulnalyzer-src
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize DB
python3 -c "from vulnalyzer.core.db import init_db; init_db()"

# Ingest CVEs (pick 2-3 packages)
python3 scripts/ingest_cves.py --package lodash --ecosystem npm
python3 scripts/ingest_cves.py --package Newtonsoft.Json --ecosystem NuGet

# Scan a repo
python3 scripts/scan_repo.py https://github.com/expressjs/express

# Build graph
python3 scripts/build_graph.py

# Start UI
python3 run.py

# Open browser: http://localhost:8000
```


## ENVIRONMENT VARIABLES (Optional)
## ==================================

GITHUB_TOKEN
   Set your GitHub personal access token for higher API rate limits
   ```
   export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
   ```

LOG_LEVEL
   Set logging verbosity: DEBUG, INFO, WARNING, ERROR
   ```
   export LOG_LEVEL=DEBUG
   ```


## AVAILABLE ECOSYSTEMS & MANIFEST FILES
## =======================================

npm
   - package.json (direct dependencies)
   - package-lock.json (locked versions)
   - yarn.lock (Yarn lock file)

PyPI
   - requirements.txt (pinned dependencies)
   - pyproject.toml (PEP 621 & Poetry format)
   - setup.cfg (setuptools config)

Maven
   - pom.xml (Java build manifest)

Go
   - go.mod (module declaration + direct requires)
   - go.sum (full transitive closure)

crates.io
   - Cargo.toml (Rust manifest)
   - Cargo.lock (resolved lockfile)

NuGet
   - packages.config (legacy format)
   - project.csproj / project.fsproj (SDK-style)
   - Directory.Packages.props (central package management)
   - packages.lock.json (NuGet lock file)


## NEXT STEPS
## ==========

1. Run the minimal example above
2. Explore the UI at http://localhost:8000
3. Filter by ecosystem
4. Click on nodes to see CVE details
5. Try different repos from test_repos.txt
6. Check the dependency graphs and exposure scores
