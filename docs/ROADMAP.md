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

### 3.6 Active Content Discovery ✅
- [x] API documentation endpoints (Swagger, GraphQL, OpenAPI)
- [x] Common API path patterns (/api/v1/, /api/v2/, etc.)
- [x] Admin and management interfaces (Tomcat, phpMyAdmin, Adminer)
- [x] Development/debug endpoints (Spring Boot Actuator, Go pprof)
- [x] robots.txt Disallow path mining
- [x] Source maps and build artifacts
- [x] Custom 404 detection to filter false positives

### 3.7 Injection Testing ✅
- [x] Reflected XSS detection (canary-based, multi-stage confirmation)
- [x] SQL injection via error-based detection (15+ DB error patterns)
- [x] Open redirect testing (redirect parameter fuzzing)
- [x] Server-Side Template Injection (SSTI) detection
- [x] Automatic parameter discovery from page links and forms
- [x] Common parameter wordlist fallback

### 3.8 Authentication & Authorization Checks ✅
- [x] Session cookie security flags (Secure, HttpOnly, SameSite)
- [x] Unauthenticated access to sensitive API endpoints
- [x] JWT token exposure and weak algorithm detection
- [x] Login form CSRF protection check
- [x] HTTP credential submission detection

### 3.9 Business Logic Analysis ✅
- [x] Verbose error/stack trace detection (Python, Java, .NET, PHP, Node)
- [x] Version disclosure in response headers
- [x] Dangerous HTTP methods (PUT, DELETE, TRACE via OPTIONS)
- [x] HTTP → HTTPS redirect check
- [x] Clickjacking protection (X-Frame-Options, CSP frame-ancestors)
- [x] Cache control on sensitive pages
- [x] TRACE method / Cross-Site Tracing (XST)

### 3.10 Validation Layer
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

## Operating Cycle

Wintermute follows a rotating cycle across sessions to maintain balanced progress. See `CLAUDE.md` for the full session continuation protocol.

| Cycle Step | Frequency | What to do |
|------------|-----------|------------|
| **Scan** | Every session | Quick or deep scan against an active program |
| **Scout** | Every 2-3 sessions | `scout` for new programs, quick-scan 1-2 |
| **R&D** | Every 3-4 sessions | Prototype a new bug class from Phase 6 list |
| **Review** | As needed | Check HackerOne outcomes, update docs, fix FPs |

**Rule:** Don't do the same step three sessions in a row. Vary the mix.

---

## Phase 5: Operations & Monitoring (Current)

**Goal:** Run the system continuously and monitor its effectiveness.

### 5.1 Scheduling & Automation
- [x] Single command to run full pipeline (recon → scan → report)
- [x] Batch scanning: `--limit N`, `--filter TERM`, `--checks a,b,c`
- [x] Quick scan mode: `--quick` runs 4 fast checks only
- [x] Program scouting: `scout` command to discover new targets
- [ ] Cron-based scheduling for recurring scans
- [ ] New program monitoring (alert when new programs appear)
- [ ] Scope change detection (re-scan when scope expands)

### 5.2 Program Rotation & Diversification
- [x] `scout` command ranks programs by opportunity (new, bounty, scope)
- [x] Tracks which programs have been scanned vs. untouched
- [ ] Periodic rotation reminder (don't get stuck on one target)
- [ ] Program health scoring (response time, bounty history, scope width)
- [ ] Multi-program batch runs (scan N programs in sequence)

### 5.2 Dashboard & Metrics
- [ ] CLI dashboard showing pipeline status
- [ ] Program coverage stats
- [ ] Findings by severity and status
- [ ] Submission outcomes tracking

### 5.3 Feedback Loop
- [ ] Track which finding types get accepted vs rejected
- [ ] Adjust scanning priorities based on success rates
- [ ] Log reasons for rejected reports to improve detection

---

## Phase 6: Scanner R&D (Ongoing)

**Goal:** Continuously research, develop, and refine detection capabilities. Each cycle identifies new bug classes, evaluates feasibility, builds proof-of-concept checks, and integrates what works into the pipeline.

### R&D Cycle Process
1. **Research** — Study recent CVEs, HackerOne Hacktivity, OWASP updates, and real-world disclosures to identify high-value bug classes we're not yet detecting
2. **Prioritize** — Rank candidates by: bounty value × detection feasibility × automation potential
3. **Prototype** — Build a standalone check module with test cases
4. **Validate** — Run against known-vulnerable test targets (OWASP Juice Shop, DVWA, etc.)
5. **Integrate** — Wire into the scanner pipeline with report templates
6. **Measure** — Track acceptance rate of new finding types across programs

### Candidate Bug Classes to Investigate

#### High Priority (Common, High Bounty Value)
- [ ] **IDOR (Insecure Direct Object Reference)** — Enumerate predictable IDs in API responses, detect sequential access patterns
- [ ] **Broken Access Control** — Test API endpoints with role escalation patterns (e.g., `/api/admin` accessible without admin cookie)
- [ ] **Server-Side Request Forgery (SSRF)** — Test URL/webhook parameters for internal network access (safe canary payloads)
- [ ] **Path Traversal / LFI** — Test file parameters for directory traversal (safe: `....//etc/hostname`)
- [ ] **Insecure Deserialization markers** — Detect Java serialized objects, PHP serialized data, pickle in responses

#### Medium Priority (Valuable, Moderate Complexity)
- [ ] **Subdomain enumeration expansion** — Integrate multiple passive sources (SecurityTrails, Shodan, VirusTotal APIs)
- [ ] **JavaScript analysis** — Parse JS files for hardcoded API keys, secrets, internal URLs, and cloud service credentials
- [ ] **Broken rate limiting** — Detect missing rate limits on login, password reset, and API endpoints
- [ ] **Email header injection** — Test contact/feedback forms for header injection via newline characters
- [ ] **Host header injection** — Test for password reset poisoning and cache poisoning via Host header manipulation
- [ ] **WebSocket testing** — Check for unauthenticated WebSocket connections and missing origin validation
- [ ] **API versioning gaps** — Test older API versions (v1 when v2 exists) for deprecated, unpatched endpoints

#### Lower Priority (Niche but Rewarding)
- [ ] **Prototype pollution** — Detect JavaScript prototype pollution via `__proto__` in JSON APIs
- [ ] **Race conditions** — Detect TOCTOU issues on coupon/discount/balance endpoints
- [ ] **GraphQL introspection** — If GraphQL found, query full schema and analyze for sensitive mutations
- [ ] **Cloud metadata SSRF** — Test for AWS/GCP/Azure metadata endpoint access (169.254.169.254)
- [ ] **Dependency confusion** — Analyze package.json/requirements.txt for internal package names vulnerable to public registry hijacking
- [ ] **Cache poisoning** — Test for web cache deception via path confusion and unkeyed headers
- [ ] **DNS rebinding** — Detect services vulnerable to DNS rebinding attacks

### Research Resources
- HackerOne Hacktivity (public disclosures for patterns)
- OWASP Testing Guide v4.2
- PortSwigger Web Security Academy
- Recent CVE databases for newly discovered attack patterns
- Bug bounty write-ups and conference talks

### Completed R&D
- [x] Active content discovery (API docs, admin panels, debug endpoints)
- [x] Parameter fuzzing (XSS, SQLi, open redirect, SSTI)
- [x] Authentication/authorization checks (cookies, JWT, CSRF, missing auth)
- [x] Business logic analysis (error leaks, version disclosure, clickjacking, HTTP methods)

---

## Education & Documentation (Ongoing)

Documentation grows organically as we work through cases and learn.
GitHub repo is the public-facing project — docs live alongside code.

- [x] Glossary of terms (`docs/GLOSSARY.md`)
- [x] How It Works guide (`docs/how-it-works.md`)
- [x] Vulnerability detection guide (`docs/vulnerability-detection.md`)
- [x] Reporting engine guide (`docs/reporting-engine.md`)
- [x] Submission decision guide (`docs/submission-guide.md`)
- [ ] Case study docs as we work real bounties

---

## Key Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-27 | Project initiated as "Wintermute" | Explore feasibility of AI-assisted bounty hunting |
| 2026-09-27 | Python as primary language | Best ecosystem for security tooling |
| 2026-09-27 | Start with HackerOne only | Largest platform, good API, defer Bugcrowd |
| 2026-09-27 | Passive recon only in v1 | Safety first — CT logs and DNS are public data |
| 2026-09-27 | SQLite for storage | Simple, no server needed, good enough for v1 |
| 2026-09-27 | GitHub IS the public release | No separate release phase — docs grow with the project |
| 2026-09-27 | Added 4 advanced scanner modules | Content discovery, injection, auth, business logic |
| 2026-09-27 | Created R&D cycle (Phase 6) | Ongoing research to expand detection capabilities |

---

## Documentation Index

- `docs/GLOSSARY.md` — Plain-language definitions of all technical terms
- `docs/how-it-works.md` — Step-by-step explanation of the full pipeline
- `docs/ETHICS.md` — Mandatory rules of engagement
- `docs/vulnerability-detection.md` — How each vulnerability check works
- `docs/reporting-engine.md` — Report generation and submission guide
- `docs/operations.md` — Operational runbook (Phase 5)
- `docs/submission-guide.md` — When to submit, risks of oversubmitting
