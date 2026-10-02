# Wintermute — Project Roadmap

## Vision

Explore whether an individual layman, equipped with subscription-based AI agents and open-source tooling, can meaningfully contribute to internet security by identifying and responsibly disclosing vulnerabilities through public bug bounty programs.

**Specialty focus: AI agent security.** As AI agents become ubiquitous in web applications, a new class of vulnerabilities is emerging — prompt injection, tool-use abuse, agent authorization flaws, MCP server exploits, and insecure AI integrations. Wintermute aims to develop specialized detection capabilities for these AI-specific attack surfaces, making this its long-term strategic differentiator while maintaining strong general web security scanning as the foundation.

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

Active scanning, program management, and operational improvements. This is the core revenue-generating activity. **After every scan cycle:** analyze results, document new FP patterns, add capability gaps to the R&D queue, and update STRATEGY.md with findings. Never remove a program from the scan list — the list grows continuously.

### Queue

1. **Anthropic** — unauthenticated scan complete (Session 37): 24 targets, 0 reportable findings. Public surface well-hardened. Needs authenticated scanning for real coverage. Also: Claude Code permission bypass and MCP servers explicitly in scope — requires local testing, not remote scanning.
2. Investigate CLEAR corpsupport.clearme.com JS secret exposure — verify JWT tokens in JS files
3. Multi-program batch run — re-run recon on GitHub, Tinder, Grab with new subdomain sources, then scan new targets
4. Hyatt — slice recon by domain subsets across sessions (61 base domains, 805 subdomains), then scan with `--limit 5 --filter`
5. CLEAR — rescan with AI modules (prompt injection, data exfil, MCP) now that they exist
6. GitHub — revisit with auth scanning when capability exists; deep scan education.github.com, npmjs.com, classroom.github.com
7. Notion — revisit with auth scanning (retool admin panel has real `/api/chat`, `/api/mcp` behind 401; Notion AI asset needs auth)
8. Wealthsimple — revisit with auth scanning; staging hosts are locked down, needs authenticated access for real coverage
9. Grab — revisit with auth scanning and better recon (crt.sh 502'd on 10/18 domains); 115 hungrygowhere.com subdomains enumerated but only 3 alive; API/staging targets need auth
10. Tinder — needs recon re-run (crt.sh 502'd on all 6 domains); staging targets at *.tstaging.com well-secured
11. Deriv — fully scanned, 0 reportable findings; revisit if new modules added
12. Scout for new programs — run `scout`, evaluate 2-3 new candidates, quick-scan the best
13. Scan a fresh program from scout results — pick one never scanned, full pipeline

**Continuous items** (rotate to bottom after working):
- Scout for new programs
- Scan a fresh program from scout results
- Review submission candidates

---

## Cycle 2: Scanner R&D & Buildout

Research, prototype, and integrate new vulnerability detection capabilities. Each item is a new scanner module or major enhancement.

### Queue

**False positive fixes (high priority — directly improves scan quality):**
1. ~~**Catch-all routing detection**~~ ✅ DONE (Session 22) — Pipeline detects catch-all hosts and skips path-based discovery checks (content_discovery, ai_prompt_injection, ai_data_exfil, mcp_security). Fixes 110+ FPs across GitHub and Notion.
2. ~~**SSTI baseline comparison**~~ ✅ DONE (Session 24) — Changed canary from `{{7*7}}→49` to `{{91*71}}→6461` (49 too common in Cloudflare tokens). Added non-200 status code filter. Fixes 25 SSTI FPs across Deriv and Quora/Poe.
3. ~~**Content discovery confidence tuning**~~ ✅ DONE (Session 26) — Granular confidence: fingerprint=0.85, redirect-to-login=0.5, forbidden=0.5, status-only=0.4. Only fingerprint-confirmed findings exceed 0.7 threshold. Added catch-all redirect detection (skips hosts where 404 baseline redirects to login). Fixes 18+ FPs on paymentcard.wealthsimple.com and similar hosts.

**FP fixes & scanner quality (Session 29-30):**
4. ~~**CORS wildcard+credentials fix**~~ ✅ DONE (Session 30) — `ACAO: *` with `ACAC: true` no longer flagged as vulnerable (browsers block credentials with wildcard origin). Only origin reflection is a real finding.
5. ~~**AI endpoint discovery heuristic**~~ ✅ DONE (Session 30) — Static assets (.css, .js, .png, etc.) and static directories (/static/, /assets/, /dist/) filtered from AI endpoint link discovery. Fixes CSS-file-as-AI-endpoint FP.
6. ~~**MCP security timeout**~~ ✅ DONE (Session 30) — Added 5-minute module timeout and 2-minute discovery timeout. Prevents 90+ minute scans on slow/unresponsive hosts.
6b. ~~**Prompt injection reflection FP fix**~~ ✅ DONE (Session 37) — Canary detection now checks raw, HTML-decoded, and URL-decoded (single+double) body for input reflection. Contextual word proximity fallback catches encoded reflections in analytics JS. Fixes FPs on any site with search functionality (support.anthropic.com had 8 FPs from this).

**Infrastructure & capability:**
7. ~~**Authenticated scanning**~~ ✅ DONE (Session 28) — `--auth` flag loads cookies/headers from `.auth/<handle>.json`. Wired through pipeline to content_discovery, ai_prompt_injection, ai_data_exfil, mcp_security. Shared HTTP client in `src/core/http_client.py`.
8. ~~**Subdomain enumeration expansion**~~ ✅ DONE (Session 35) — Added HackerTarget API and AlienVault OTX as passive sources. HackerTarget found 51 github.com subdomains vs crt.sh's 2. Falls back gracefully when sources are down (crt.sh 502 no longer blocks recon).
9. ~~**Manual target injection**~~ ✅ DONE (Session 38) — `--add-targets host1,host2` CLI flag. Checks scope, resolves DNS, stores in DB. Bypasses recon entirely.

**AI Agent Security (priority track):**
10. **Insecure AI Integration** — Test for AI endpoints lacking auth, rate limiting, or input validation; LLM-powered APIs that pass unsanitized user input to backend systems

**General web security:**
11. **SSRF Detection** — Test URL/webhook parameters for internal network access (requires callback server setup)
12. **Host Header Injection** — Test for password reset poisoning and cache poisoning via Host header manipulation
13. **Broken Rate Limiting** — Detect missing rate limits on login, password reset, and API endpoints
14. **API Versioning Gaps** — Test older API versions (v1 when v2 exists) for deprecated, unpatched endpoints
15. **WebSocket Testing** — Check for unauthenticated WebSocket connections and missing origin validation
16. **Prototype Pollution** — Detect JavaScript prototype pollution via `__proto__` in JSON APIs
17. **Cloud Metadata SSRF** — Test for AWS/GCP/Azure metadata endpoint access (169.254.169.254)
18. **Race Conditions** — Detect TOCTOU issues on coupon/discount/balance endpoints
19. **Cache Poisoning** — Test for web cache deception via path confusion and unkeyed headers

**Continuous items** (rotate to bottom after working):
- Review HackerOne Hacktivity for new bug patterns to add
- Tune existing scanners: reduce false positives, improve confidence scoring

---

## Cycle 3: Research & Strategic Planning

Market research, competitive analysis, and strategic direction. Feeds into R&D priorities and operational focus.

### Queue

1. Competitive analysis — what are other automated scanners (Nuclei, Burp, etc.) detecting that we're not?
2. Research AI agent attack patterns — tool-use abuse, indirect prompt injection via stored content, data exfiltration through AI responses
3. Update `docs/STRATEGY.md` with findings, adjust cycle priorities
4. Research current HackerOne Hacktivity — what bug types are getting accepted and paid this month?
5. Study AI/LLM attack surface landscape — OWASP Top 10 for LLMs, prompt injection taxonomy, AI agent authorization models, MCP security gaps
6. Review bounty payout trends — which programs pay well, which are responsive, which to avoid
7. Scout HackerOne programs with AI features — identify targets with chatbots, AI assistants, LLM APIs, AI-powered search
8. Analyze our false positive rate — which modules generate the most noise? Prioritize fixes

**Continuous items** (all — rotate after working):
- All items in this cycle are continuous research tasks

---

## Cycle 4: Project Organization & Documentation

Code quality, documentation, testing, infrastructure. Keeps the project maintainable and educational.

### Queue

1. Write case study doc for first accepted bounty (when it happens)
2. Add CLI dashboard showing pipeline status, program coverage, finding stats
3. Implement submission outcome tracking — log accepted/rejected/duplicate results
4. Document authenticated scanning workflow — expand beyond current inline docs in operations.md (session management, credential rotation, multi-program auth)

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
- 125 unit tests, ruff linting

### Recon Pipeline (Built)
- Certificate Transparency subdomain enumeration (crt.sh)
- DNS resolution and validation
- HTTP header fingerprinting and technology detection
- Scope-gated orchestration pipeline

### Scanner Modules (16 Built)
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
11. Path traversal / LFI (traversal canaries, encoding bypasses, baseline comparison)
12. GraphQL introspection (schema analysis, sensitive mutation/query detection)
13. JavaScript analysis (secret detection, API keys, cloud credentials, internal URLs)
14. AI prompt injection (endpoint discovery, canary injection, system prompt extraction)
15. MCP security (server discovery, auth bypass, dangerous tool detection, tool poisoning, path traversal)
16. AI data exfiltration (context extraction, PII detection, backend leak detection, RAG source exposure)

### Reporting Engine (Built)
- 35 report templates with CWE references
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
- `docs/LEGAL.md` — Legal context, CFAA, safe harbor provisions
- `docs/GLOSSARY.md` — Plain-language definitions
