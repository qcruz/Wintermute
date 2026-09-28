# Wintermute — Project Roadmap

## Vision

Explore whether an individual layman, equipped with subscription-based AI agents and open-source tooling, can meaningfully contribute to internet security by identifying and responsibly disclosing vulnerabilities through public bug bounty programs.

This project is educational and ethical by design. Every component respects program scope, rate limits, and disclosure guidelines.

---

## How This Document Works

This roadmap is organized into **work cycles** — rotating categories of work that keep the project moving forward across all fronts. Each cycle has a queue of items. When continuing a session:

1. Read the cycle queues below
2. **Work the first item** in the next cycle due for rotation
3. When done: **remove completed items**, **rotate continuous items to the bottom** of their cycle
4. Over time, completed items disappear and continuous items keep cycling — the project naturally covers its full scope with no blind spots

See `CLAUDE.md` for the session startup checklist that drives this.

---

## Cycle 1: Scanning & Operations

Active scanning, program management, and operational improvements. This is the core revenue-generating activity.

### Queue

1. Hyatt — run recon (own session, 291 targets), then slice scans with `--limit 5 --filter` across subsequent sessions
2. Kiwi.com — deep scan remaining targets, re-check CORS on tequila.kiwi.com
3. Scout for new programs — run `scout`, evaluate 2-3 new candidates, quick-scan the best
4. CLEAR — re-scan with IDOR and path traversal checks on interesting hosts (corpsupport, api)
5. Deriv — scan remaining 8 targets with full checks
6. Scan a fresh program from scout results — pick one never scanned, full pipeline
7. Review submission candidates — verify any high-confidence findings, submit if reproducible
8. Multi-program batch run — scan 3 programs in sequence with `--quick`

**Continuous items** (rotate to bottom after working):
- Scout for new programs
- Scan a fresh program from scout results
- Review submission candidates

---

## Cycle 2: Scanner R&D & Buildout

Research, prototype, and integrate new vulnerability detection capabilities. Each item is a new scanner module or major enhancement.

### Queue

1. **Path Traversal / LFI** — Test file/path parameters with safe traversal canaries (`....//etc/hostname`)
2. **GraphQL Introspection** — When GraphQL endpoints are found, query schema, analyze for sensitive mutations and missing auth
3. **JavaScript Analysis** — Parse JS files for hardcoded API keys, secrets, internal URLs, cloud credentials
4. **SSRF Detection** — Test URL/webhook parameters for internal network access (requires callback server setup)
5. **Host Header Injection** — Test for password reset poisoning and cache poisoning via Host header manipulation
6. **Broken Rate Limiting** — Detect missing rate limits on login, password reset, and API endpoints
7. **API Versioning Gaps** — Test older API versions (v1 when v2 exists) for deprecated, unpatched endpoints
8. **AI/LLM Prompt Injection** — Detect prompt injection vulnerabilities in AI-integrated applications
9. **WebSocket Testing** — Check for unauthenticated WebSocket connections and missing origin validation
10. **Prototype Pollution** — Detect JavaScript prototype pollution via `__proto__` in JSON APIs
11. **Cloud Metadata SSRF** — Test for AWS/GCP/Azure metadata endpoint access (169.254.169.254)
12. **Race Conditions** — Detect TOCTOU issues on coupon/discount/balance endpoints
13. **Cache Poisoning** — Test for web cache deception via path confusion and unkeyed headers

**Continuous items** (rotate to bottom after working):
- Review HackerOne Hacktivity for new bug patterns to add
- Tune existing scanners: reduce false positives, improve confidence scoring

---

## Cycle 3: Research & Strategic Planning

Market research, competitive analysis, and strategic direction. Feeds into R&D priorities and operational focus.

### Queue

1. Research current HackerOne Hacktivity — what bug types are getting accepted and paid this month?
2. Analyze our false positive rate — which modules generate the most noise? Prioritize fixes
3. Study AI/LLM attack surface landscape — OWASP Top 10 for LLMs, emerging patterns
4. Review bounty payout trends — which programs pay well, which are responsive, which to avoid
5. Competitive analysis — what are other automated scanners (Nuclei, Burp, etc.) detecting that we're not?
6. Update `docs/STRATEGY.md` with findings, adjust cycle priorities

**Continuous items** (all — rotate after working):
- All items in this cycle are continuous research tasks

---

## Cycle 4: Project Organization & Documentation

Code quality, documentation, testing, infrastructure. Keeps the project maintainable and educational.

### Queue

1. Choose open-source license (Apache 2.0 or MIT) and add LICENSE file
2. Create GitHub Actions CI pipeline (lint with ruff, run pytest)
3. Add tests for new scanner modules (IDOR, path traversal, etc. — target 80+ tests)
4. Write case study doc for first accepted bounty (when it happens)
5. Draft `docs/LEGAL.md` — relevant laws, safe harbor provisions
6. Review and update all docs for accuracy after recent changes
7. Add CLI dashboard showing pipeline status, program coverage, finding stats
8. Implement submission outcome tracking — log accepted/rejected/duplicate results

**Continuous items** (rotate to bottom after working):
- Review and update all docs for accuracy after recent changes
- Add tests for new scanner modules

---

## Cycle Rotation Schedule

Sessions rotate through cycles to maintain balance. The **next cycle to work** is determined by checking which cycle has been idle longest (via session log and git history).

```
Session flow:
  1. Read ROADMAP.md → find the cycle that's been idle longest
  2. Work the FIRST item in that cycle's queue
  3. If completed → remove it
  4. If continuous → move to bottom of queue
  5. Update SESSION_LOG.md
  6. Push changes
```

**Guidelines:**
- Don't work the same cycle 3 sessions in a row
- Scanning (Cycle 1) should happen most often — it's the core activity
- R&D (Cycle 2) feeds Scanning — build then scan with the new capability
- Research (Cycle 3) feeds R&D — study then build what's most valuable
- Docs (Cycle 4) can be combined with other cycles as a secondary task

---

## Completed Work

### Foundation (Built)
- Project structure, git repo, GitHub remote
- HackerOne API client (auth, scope, programs, submissions)
- Scope checker with wildcard/CIDR matching, default deny, audit logging
- SQLite database with SQLAlchemy ORM
- 61 unit tests, ruff linting

### Recon Pipeline (Built)
- Certificate Transparency subdomain enumeration (crt.sh)
- DNS resolution and validation
- HTTP header fingerprinting and technology detection
- Scope-gated orchestration pipeline

### Scanner Modules (10 Built)
1. Subdomain takeover (20+ services, CNAME chain, HTTP fingerprint)
2. CORS misconfiguration (origin reflection, null origin, credentials)
3. SSL/TLS analysis (expiry, weak protocols, hostname mismatch)
4. Exposed sensitive files (.git, .env, backups, admin panels)
5. Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
6. Content discovery (80+ paths, API docs, admin panels, debug endpoints)
7. Injection testing (XSS, SQLi, open redirect, SSTI)
8. Auth checks (cookies, JWT, missing auth, CSRF)
9. Business logic (error leaks, version disclosure, clickjacking, HTTP methods)
10. IDOR detection (sequential ID enumeration, sensitive field detection)

### Reporting Engine (Built)
- 20 report templates with CWE references
- Duplicate detection (internal DB + HackerOne API)
- Interactive review queue with human approval
- HackerOne API submission

### False Positive Reduction (Ongoing)
- Third-party site detection (Google Sites, Auth0, Okta, etc.)
- Blanket-403 host detection
- SSTI confirmation re-request
- Open redirect validation tightening
- DB-level finding deduplication
- Custom 404 baseline comparison
- Content fingerprinting

---

## Key Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-27 | Project initiated as "Wintermute" | Explore feasibility of AI-assisted bounty hunting |
| 2026-09-27 | Python as primary language | Best ecosystem for security tooling |
| 2026-09-27 | Start with HackerOne only | Largest platform, good API, defer Bugcrowd |
| 2026-09-27 | SQLite for storage | Simple, no server needed, good enough for v1 |
| 2026-09-27 | GitHub IS the public release | No separate release phase — docs grow with the project |
| 2026-09-28 | Cycle-based roadmap | Phases completed; now need continuous rotation across all project areas |
| 2026-09-28 | First item in queue drives sessions | Autonomous session continuation without blind spots |

---

## Documentation Index

- `CLAUDE.md` — Session instructions, cycle protocol, architecture, safety rules
- `docs/ROADMAP.md` — This file: cycle queues and project direction
- `docs/SESSION_LOG.md` — What happened each session
- `docs/STRATEGY.md` — Strategic analysis, performance tracking, research
- `docs/vulnerability-detection.md` — How each scanner module works
- `docs/reporting-engine.md` — Report generation and submission guide
- `docs/submission-guide.md` — When to submit, risks of oversubmitting
- `docs/operations.md` — Command reference and workflow
- `docs/how-it-works.md` — Step-by-step pipeline explanation
- `docs/ETHICS.md` — Mandatory rules of engagement
- `docs/GLOSSARY.md` — Plain-language definitions
