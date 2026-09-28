# Wintermute — Project Roadmap

## Vision

Explore whether an individual layman, equipped with subscription-based AI agents and open-source tooling, can meaningfully contribute to internet security by identifying and responsibly disclosing vulnerabilities through public bug bounty programs.

This project is educational and ethical by design. Every component respects program scope, rate limits, and disclosure guidelines.

---

## Phase 0: Foundation ✅

**Goal:** Establish project infrastructure, accounts, and legal/ethical framework.

### 0.1 Project Setup
- [x] Create project folder and directory structure
- [x] Write initial roadmap
- [x] Initialize git repository
- [x] Create GitHub repository
- [x] Set up `.gitignore` (exclude secrets, credentials, scan results with PII)
- [ ] Choose open-source license (Apache 2.0 or MIT recommended)

### 0.2 Platform Accounts
- [x] Create HackerOne hacker account
- [x] Generate API keys
- [x] Store API keys securely (environment variables via .env)
- [ ] Create Bugcrowd researcher account (deferred — starting with HackerOne)

### 0.3 Ethics & Legal Framework
- [x] Draft `docs/ETHICS.md` — rules of engagement
- [x] Build scope-checking into the pipeline as a hard gate
- [ ] Draft `docs/LEGAL.md` — relevant laws, safe harbor provisions

### 0.4 Development Environment
- [x] Python 3.14 with virtual environment
- [x] Dependencies installed (requests, httpx, sqlalchemy, dnspython, etc.)
- [x] Linting with ruff
- [x] Testing with pytest (26 tests passing)
- [ ] Create basic CI pipeline (GitHub Actions: lint, test)

---

## Phase 1: Program Ingestion & Scope Management ✅

**Goal:** Automatically discover bug bounty programs and parse their scope into structured data.

### 1.1 Platform API Integration
- [x] HackerOne API client (`src/platforms/hackerone.py`)
  - Authenticate with API token (basic auth)
  - List programs accepting submissions
  - Fetch program policy and scope
  - Fetch program weaknesses (accepted CWEs)
  - Submit reports via API
- [ ] Bugcrowd API client (deferred)

### 1.2 Scope Parser
- [x] Parse in-scope domains, IPs, URLs
- [x] Parse out-of-scope exclusions
- [x] Store parsed scope in local database (SQLite)

### 1.3 Scope Checker (`src/core/scope.py`)
- [x] Wildcard domain matching (*.example.com)
- [x] CIDR/IP range matching
- [x] Out-of-scope exclusions override in-scope wildcards
- [x] Default deny for unmatched targets
- [x] Full audit logging
- [x] `require_scope()` hard gate function
- [x] 24 unit tests

---

## Phase 2: Reconnaissance Pipeline ✅

**Goal:** For each in-scope target, discover the attack surface automatically.

### 2.1 Subdomain Enumeration
- [x] Certificate Transparency log queries (crt.sh)
- [x] DNS resolution validation (A and AAAA records)
- [x] Deduplicate discovered subdomains
- [x] Store results in database with timestamps

### 2.2 Web Technology Fingerprinting
- [x] HTTP response header analysis
- [x] Server identification
- [x] Technology detection (CloudFront, Cloudflare, Drupal, etc.)
- [x] Security header gap analysis

### 2.3 Recon Pipeline (`src/recon/pipeline.py`)
- [x] Orchestrated pipeline: fetch scope → enumerate → filter → fingerprint → store
- [x] Scope-gated: every target checked before interaction
- [x] Database storage with change tracking
- [x] Validated end-to-end against HackerOne's own program

### 2.4 Not Yet Implemented
- [ ] Port & service scanning (nmap integration)
- [ ] Content discovery (directory brute-forcing)
- [ ] Wayback Machine historical URL retrieval
- [ ] Additional passive sources (Subfinder, Amass)

---

## Phase 3: Vulnerability Detection ✅

**Goal:** Scan discovered assets for known and common vulnerabilities.

### 3.1 Subdomain Takeover Detection
- [x] Check for dangling CNAME records
- [x] Match against known vulnerable services (20+ services)
- [x] Verify takeover feasibility via HTTP fingerprinting

### 3.2 Security Header Analysis
- [x] Flag missing critical security headers as findings
- [x] Severity classification per missing header
- [x] Generate actionable remediation advice

### 3.3 CORS Misconfiguration Detection
- [x] Test for wildcard origin reflection
- [x] Test for null origin acceptance
- [x] Test for credential-inclusive CORS with open origins

### 3.4 SSL/TLS Analysis
- [x] Certificate expiration checks
- [x] Weak protocol detection (TLS 1.0, 1.1)
- [x] Certificate hostname mismatch detection

### 3.5 Exposed Sensitive Files
- [x] Check for .git, .env, .DS_Store, backup files
- [x] Check for exposed admin panels
- [ ] Check for directory listing enabled

### 3.6 Open Redirect Detection
- [ ] Test common redirect parameters (deferred)

### 3.7 Validation Layer
- [x] Confidence scoring (0.0 - 1.0)
- [x] False positive reduction (content-length soft match, content fingerprinting)
- [x] Subdoc: `docs/vulnerability-detection.md`

---

## Phase 4: Reporting Engine ✅

**Goal:** Generate clear, professional vulnerability reports and submit them.

### 4.1 Report Generation
- [x] Report template system (per vulnerability class)
- [x] Auto-populate: title, description, impact, reproduction steps
- [x] Remediation recommendations with CWE references
- [ ] Use LLM (Claude API) to refine report language (future enhancement)

### 4.2 Duplicate Avoidance
- [x] Internal dedup against database (previous submissions)
- [x] Platform dedup via HackerOne API (report history)
- [x] Heuristic scoring (program popularity × vuln type commonality)

### 4.3 Submission Pipeline
- [x] Interactive review queue (preview before submit)
- [x] Submit via HackerOne API with full report formatting
- [x] Track submission status in database
- [x] Auto-submit option for high-confidence findings (off by default)
- [x] Subdoc: `docs/reporting-engine.md`

---

## Phase 5: Operations & Monitoring

**Goal:** Run the system continuously and monitor its effectiveness.

- [ ] Cron-based pipeline scheduling
- [ ] New program monitoring
- [ ] Web dashboard (Streamlit)
- [ ] Feedback loop: track what gets accepted vs rejected

---

## Phase 6: Education & Public Release

**Goal:** Package the project for others to learn from and use responsibly.

- [x] Glossary of terms (`docs/GLOSSARY.md`)
- [x] How It Works guide (`docs/how-it-works.md`)
- [ ] Comprehensive setup guide
- [ ] Video walkthroughs or blog posts
- [ ] Security audit before public release
- [ ] CONTRIBUTING.md, CODE_OF_CONDUCT.md

---

## Key Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-27 | Project initiated as "Wintermute" | Explore feasibility of AI-assisted bounty hunting |
| 2026-09-27 | Python as primary language | Best ecosystem for security tooling |
| 2026-09-27 | Start with HackerOne only | Largest platform, good API, defer Bugcrowd |
| 2026-09-27 | Passive recon only in v1 | Safety first — CT logs and DNS are public data |
| 2026-09-27 | SQLite for storage | Simple, no server needed, good enough for v1 |

---

## Documentation Index

- `docs/GLOSSARY.md` — Plain-language definitions of all technical terms
- `docs/how-it-works.md` — Step-by-step explanation of the full pipeline
- `docs/ETHICS.md` — Mandatory rules of engagement
- `docs/vulnerability-detection.md` — How each vulnerability check works (Phase 3)
- `docs/LEGAL.md` — Legal considerations (TODO)
