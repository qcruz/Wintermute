# Wintermute — Project Roadmap

## Vision

Explore whether an individual layman, equipped with subscription-based AI agents and open-source tooling, can meaningfully contribute to internet security by identifying and responsibly disclosing vulnerabilities through public bug bounty programs.

This project is educational and ethical by design. Every component respects program scope, rate limits, and disclosure guidelines.

---

## Phase 0: Foundation (Current)

**Goal:** Establish project infrastructure, accounts, and legal/ethical framework.

### 0.1 Project Setup
- [x] Create project folder and directory structure
- [x] Write initial roadmap
- [ ] Initialize git repository
- [ ] Create GitHub repository (private during development, public when ready)
- [ ] Set up `.gitignore` (exclude secrets, credentials, scan results with PII)
- [ ] Choose open-source license (Apache 2.0 or MIT recommended)

### 0.2 Platform Accounts
- [ ] Create HackerOne hacker account (https://hackerone.com)
- [ ] Create Bugcrowd researcher account (https://bugcrowd.com)
- [ ] Review and accept platform terms of service
- [ ] Generate API keys for each platform
- [ ] Store API keys securely (environment variables or encrypted config)

### 0.3 Ethics & Legal Framework
- [ ] Draft `docs/ETHICS.md` — rules of engagement the system will always follow
  - Only test explicitly in-scope assets
  - Never attempt denial of service
  - Never exfiltrate real user data
  - Respect rate limits
  - Stop immediately if impact to real users is possible
  - Always disclose through proper channels
- [ ] Draft `docs/LEGAL.md` — relevant laws (CFAA, local equivalents), safe harbor provisions
- [ ] Build scope-checking into the pipeline as a hard gate (not optional)

### 0.4 Development Environment
- [ ] Select primary language (Python recommended)
- [ ] Set up virtual environment / dependency management (poetry or pip + requirements.txt)
- [ ] Set up linting and formatting (ruff, black)
- [ ] Create basic CI pipeline (GitHub Actions: lint, test)

---

## Phase 1: Program Ingestion & Scope Management

**Goal:** Automatically discover bug bounty programs and parse their scope into structured data.

### 1.1 Platform API Integration
- [ ] HackerOne API client (`src/platforms/hackerone.py`)
  - Authenticate with API token
  - List programs accepting submissions
  - Fetch program policy and scope
  - Fetch program response metrics (helps prioritize responsive programs)
- [ ] Bugcrowd API client (`src/platforms/bugcrowd.py`)
  - Same capabilities as above
- [ ] Unified program model — normalize data across platforms
- [ ] Subdoc: `docs/platform-integration.md`

### 1.2 Scope Parser
- [ ] Parse in-scope domains, IPs, URLs, mobile apps
- [ ] Parse out-of-scope exclusions
- [ ] Parse bounty ranges and severity requirements
- [ ] Parse special instructions and testing restrictions
- [ ] Store parsed scope in local database (SQLite initially)

### 1.3 Program Prioritization
- [ ] Score programs by: bounty amount, response time, scope breadth, competition level
- [ ] Filter for programs suited to automated testing (web apps, APIs)
- [ ] Flag programs with restrictions that affect automated tools

---

## Phase 2: Reconnaissance Pipeline

**Goal:** For each in-scope target, discover the attack surface automatically.

### 2.1 Subdomain Enumeration
- [ ] Integrate subfinder or amass (passive enumeration only to start)
- [ ] Certificate transparency log queries
- [ ] DNS brute-forcing (wordlist-based, respecting rate limits)
- [ ] Deduplicate and validate discovered subdomains (DNS resolution check)
- [ ] Store results in database with timestamps

### 2.2 Port & Service Scanning
- [ ] Integrate nmap or masscan (with conservative rate settings)
- [ ] Service version detection
- [ ] Map services to known technologies
- [ ] Hard gate: verify every target is in scope before scanning

### 2.3 Web Technology Fingerprinting
- [ ] HTTP response header analysis
- [ ] Technology stack detection (Wappalyzer-style)
- [ ] CMS detection (WordPress, Drupal, etc.)
- [ ] JavaScript framework detection
- [ ] API endpoint discovery from client-side code

### 2.4 Content Discovery
- [ ] Directory and file brute-forcing (ffuf or feroxbuster integration)
- [ ] Robots.txt and sitemap.xml parsing
- [ ] Wayback Machine historical URL retrieval
- [ ] Common sensitive file checks (.git, .env, .DS_Store, backup files)

### 2.5 Recon Data Store
- [ ] Design database schema for all recon data
- [ ] Build query interface for downstream vulnerability checks
- [ ] Track changes over time (new subdomains, removed services, etc.)
- [ ] Subdoc: `docs/recon-pipeline.md`

---

## Phase 3: Vulnerability Detection

**Goal:** Scan discovered assets for known and common vulnerabilities.

### 3.1 Known CVE Detection
- [ ] Integrate nuclei with community templates
- [ ] Match discovered tech stacks against CVE databases (NVD API)
- [ ] Version-based vulnerability matching
- [ ] Template management: auto-update, custom templates

### 3.2 Common Web Vulnerability Checks
- [ ] Subdomain takeover detection (CNAME pointing to unclaimed services)
- [ ] Open redirect detection
- [ ] CORS misconfiguration checks
- [ ] Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
- [ ] Exposed sensitive files and directories
- [ ] Default credentials on admin panels
- [ ] SSL/TLS configuration issues

### 3.3 API Security Checks
- [ ] Broken authentication patterns
- [ ] IDOR (Insecure Direct Object Reference) pattern detection
- [ ] Rate limiting verification
- [ ] Information disclosure in API responses
- [ ] GraphQL introspection checks

### 3.4 Validation Layer
- [ ] False positive reduction logic for each vulnerability class
- [ ] Confidence scoring (high / medium / low)
- [ ] Safe proof-of-concept generation (non-destructive verification)
- [ ] Human review queue for medium/low confidence findings
- [ ] Subdoc: `docs/vulnerability-detection.md`

---

## Phase 4: Reporting Engine

**Goal:** Generate clear, professional vulnerability reports and submit them through proper channels.

### 4.1 Report Generation
- [ ] Report template system (per vulnerability class)
- [ ] Auto-populate: title, description, impact, CVSS score, reproduction steps
- [ ] Include evidence (screenshots, HTTP request/response pairs)
- [ ] Use LLM (Claude API) to refine report language and clarity
- [ ] Remediation recommendations

### 4.2 Duplicate Avoidance
- [ ] Query platform APIs for existing reports on same asset/vuln
- [ ] Check public disclosure databases
- [ ] Internal dedup against our own previous submissions
- [ ] Confidence-based decision: skip if likely duplicate

### 4.3 Submission Pipeline
- [ ] Auto-submit high-confidence findings via platform API
- [ ] Queue medium-confidence findings for human review before submission
- [ ] Track submission status (triaged, accepted, duplicate, N/A, resolved)
- [ ] Handle triage follow-up questions (flag for human response)
- [ ] Subdoc: `docs/reporting-engine.md`

---

## Phase 5: Operations & Monitoring

**Goal:** Run the system continuously and monitor its effectiveness.

### 5.1 Scheduling & Orchestration
- [ ] Cron-based or event-driven pipeline execution
- [ ] New program monitoring (run recon on newly added programs)
- [ ] Scope change detection (re-scan when scope expands)
- [ ] Rate limit management across all tools and targets

### 5.2 Dashboard & Metrics
- [ ] Web dashboard (simple Flask/Streamlit app)
  - Active programs being monitored
  - Recon coverage per program
  - Findings by status and severity
  - Submission outcomes (accepted, duplicate, N/A)
  - Revenue tracking (bounties earned)
- [ ] Alert system for high-severity findings

### 5.3 Feedback Loop
- [ ] Track which vulnerability classes yield accepted reports
- [ ] Adjust scanning priorities based on success rates
- [ ] Log reasons for rejected/duplicate reports to improve detection
- [ ] Subdoc: `docs/operations.md`

---

## Phase 6: Education & Public Release

**Goal:** Package the project for others to learn from and use responsibly.

### 6.1 Documentation
- [ ] Comprehensive setup guide
- [ ] Tool-by-tool explainer (what each component does and why)
- [ ] Ethical guidelines for users
- [ ] Video walkthroughs or blog posts

### 6.2 Public Repository
- [ ] Security audit of codebase before public release
- [ ] Remove any hardcoded credentials or sensitive data from git history
- [ ] Add CONTRIBUTING.md
- [ ] Add CODE_OF_CONDUCT.md
- [ ] Community discussion setup (GitHub Discussions or Discord)

### 6.3 Ongoing Maintenance
- [ ] Keep nuclei templates and tool integrations current
- [ ] Community contributions and PRs
- [ ] Periodic review of ethical framework as landscape evolves

---

## Development Cycles

Each phase follows this cycle:

```
Design -> Implement -> Test (local) -> Test (safe target*) -> Review -> Merge
```

*Safe targets: use deliberately vulnerable apps (DVWA, Juice Shop, HackTheBox) and your own infrastructure for testing before running against real bounty programs.

---

## Key Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-27 | Project initiated as "Wintermute" | Explore feasibility of AI-assisted bounty hunting |
| 2026-09-27 | Python as primary language | Best ecosystem for security tooling |
| | | |

---

## Subdocument Index

Created as each area develops:

- `docs/ETHICS.md` — Rules of engagement (Phase 0)
- `docs/LEGAL.md` — Legal considerations (Phase 0)
- `docs/platform-integration.md` — API integration details (Phase 1)
- `docs/recon-pipeline.md` — Recon architecture (Phase 2)
- `docs/vulnerability-detection.md` — Detection methodology (Phase 3)
- `docs/reporting-engine.md` — Report generation details (Phase 4)
- `docs/operations.md` — Operational runbook (Phase 5)
