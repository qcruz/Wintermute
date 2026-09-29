# Wintermute — Session Log

Track what each session accomplished, what was found, and what's queued for next time. Most recent session first.

---

## Session 11 — 2026-09-28 (Research — Cycle 3)

**Cycle step:** Research & Strategic Planning — Study AI/LLM attack surface landscape

**What was done:**
- Deep research on AI agent security landscape — three areas investigated:
  1. **OWASP Top 10 for LLMs 2026** — Excessive Agency rose to #3 (from #6), Unbounded Consumption rose to #6 (from #10), System Prompt Leakage broadened to "Hidden Context Exposure." Key shift: from "protecting the conversation" to "containing the consequences" as agents gain tool-use capabilities
  2. **HackerOne AI bounties** — 540% YoY increase in prompt injection reports, HackerOne launched "Agentic Prompt Injection Testing" (March 2026), Anthropic went public on H1 (May 2026, up to $15K). Real incidents: Claude Code, Gemini CLI, GitHub Copilot agents hijacked via prompt injection
  3. **MCP security** — 30+ CVEs in 60 days, CVE-2026-33032 at CVSS 9.8 actively exploited, OX Security found command execution in Anthropic's official MCP SDKs (~200K vulnerable instances), 82% path traversal risk, only 8.5% use OAuth, NSA/CISA published guidance (June 2026)
- Updated `docs/STRATEGY.md` with comprehensive AI attack surface analysis, attack taxonomy for scanner development, and revised strategic priorities
- Established AI agent security as project specialty focus (updated CLAUDE.md, ROADMAP.md in prior session)

**Key findings:**
- Tool poisoning is the highest-leverage attack on enterprise AI agents — malicious instructions in tool metadata
- Indirect prompt injection via stored content (repos, docs, web pages) is the most common real-world attack vector
- MCP security is extremely weak — designed for functionality, not security
- Anthropic's HackerOne program is a natural first target for our AI security scanners

**Queued for next session:**
- Cycle 1 (Scanning): Deep scan remaining Wealthsimple targets or move to next program (Deriv, fresh scout)
- Cycle 2 (R&D): AI/LLM Prompt Injection module — first in priority track
- Consider: Scout for programs with AI features in scope

---

## Session 10 — 2026-09-28 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Deep scan Wealthsimple

**What was done:**
- Deep scanned 8 Wealthsimple targets across 3 batches (all 13 checks including new JS analysis):
  - Batch 1: `api.production`, `api.sandbox`, `api-legacy` — 18 findings, 0 high-confidence
  - Batch 2: `trade-service-staging`, `trade-service`, `tradehelp` — 9 findings, 0 high-confidence
  - Batch 3: `crypto-trust-staging`, `crypto-trust` — 0 findings
- Content discovery found 9 interesting endpoints on both `api.production` and `trade-service`
- Total scan time: ~13 min across 3 batches (~2 min/target average)

**Findings:** 27 below-threshold findings (content discovery, low-confidence). 0 high-confidence vulnerabilities. Wealthsimple's API/trade/crypto infrastructure is well-secured.

**Queued for next session:**
- Cycle 1: Deep scan remaining Wealthsimple targets (cs-tools, staging, my, www) or move to next program
- Cycle 2 (R&D): SSRF Detection is next
- Consider: Wealthsimple may be too well-defended — try Deriv or scout fresh programs

---

## Session 9 — 2026-09-28 (R&D — Cycle 2)

**Cycle step:** Scanner R&D & Buildout

**What was done:**
- Built JavaScript Analysis module (13th scanner) — scans publicly served JS files for hardcoded secrets
- 20+ regex patterns: AWS keys, Stripe, GitHub tokens, Slack, SendGrid, Google API, Azure, JWT, private keys, internal URLs, generic API keys/passwords
- Shannon entropy validation to filter placeholder values (low-entropy strings)
- False positive detection: known placeholder values, test keys, all-same-character strings
- Full integration: pipeline scan loop, report template (CWE-798), reporting branch, 12 new tests (95 total), educational explainer
- Updated README, CLAUDE.md, ROADMAP.md, vulnerability-detection.md — all counts updated to 13 modules, 23 templates, 95 tests

**Queued for next session:**
- Cycle 1: Deep scan Wealthsimple API targets with `--scan-only --limit 3 --filter api` (now includes JS analysis)
- Cycle 2: SSRF Detection is next in R&D queue

---

## Session 8 — 2026-09-28 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Scout + scan fresh program

**What was done:**
- Scouted 74 programs (69 new), evaluated goodrx, wealthsimple, matomo, grab, att
- Selected Wealthsimple (fintech, wildcard scope `*.wealthsimple.com` + `*.simpletax.ca`)
- Fixed recon pipeline bug: `_extract_base_domains()` only accepted `URL`/`Domain` asset types, skipping `WILDCARD` — added `WILDCARD` support
- Fixed crt.sh query failures: added User-Agent header (crt.sh blocks default httpx UA), increased timeout 30s→60s for large result sets
- Quick scan on Wealthsimple: 159 subdomains, 95 alive, 81 in-scope targets, 28 findings (all missing HSTS — low value, likely dups)
- Identified high-value targets for deep scanning: 6 API endpoints, trade-service, transfers, secureshare, crypto-trust, cs-tools, qa-dashboard

**Bugs fixed:**
- `_extract_base_domains()` ignored WILDCARD scope entries → 0 targets for wildcard-only programs (Wealthsimple, Grab, etc.)
- crt.sh returning 404/502 for httpx default User-Agent → added `Wintermute/0.1 (Security Research)` header
- crt.sh timeout on large domains (3,805 entries for wealthsimple.com) → increased timeout to 60s

**Findings:** 28 missing HSTS headers across Wealthsimple targets — informational, not submittable.

**Queued for next session:**
- Cycle 1: Deep scan Wealthsimple API targets with `--scan-only --limit 3 --filter api`
- Wealthsimple is a large program (81 targets) — slice deep checks by keyword across sessions
- Deriv still needs deep checks in `--limit 3` batches

---

## Session 7 — 2026-09-28 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations

**What was done:**
- Scanned Kiwi.com (6 targets) with new IDOR, path traversal, GraphQL checks — 0 new findings (5m 34s)
- Scanned CLEAR with --filter api,corpsupport — 0 targets matched filter, nothing scanned
- Started Deriv scan (13 targets) — killed after 20+ min, too slow
- Diagnosed scan speed issue: path traversal tested 28 params × 10 payloads = 280 requests/target, IDOR tested 30 patterns × 4 IDs = 120 requests/target — ~400 requests/target total
- Updated scan sizing guidelines: `--limit 3` default batch, check in with user between batches, never run long scans unattended

**Findings:** 0 new findings from deep checks on Kiwi.com. These programs are well-secured.

**Lesson learned:**
- Deep checks take ~2 min/target. Don't reduce thoroughness — reduce batch size instead. Use `--limit 3` (~6 min per batch) and check in with user between batches.

**Queued for next session:**
- Cycle 1: Re-run Deriv in `--limit 3` batches, then scout for fresh programs
- Consider: well-known programs may be picked clean — fresh/newer programs may yield more

---

## Session 6 — 2026-09-28 (R&D — Cycle 2 + housekeeping)

**Cycle step:** Scanner R&D & Buildout (primary)

**What was done:**
- Built GraphQL Introspection module (12th scanner) — probes 8 paths, introspection query via POST/GET, schema analysis for sensitive mutations/queries, severity classification
- Full integration: pipeline scan loop, report template (CWE-200), reporting branch, 12 new tests (83 total), educational explainer
- Added MIT LICENSE file (Cycle 4 quick win), removed from Cycle 4 queue
- Attempted Hyatt recon — killed after 30+ min (340+ targets, sequential header fingerprinting). Moved to bottom of Cycle 1 queue with "slice by domain" strategy
- Researched HackerOne 2026 meta (Cycle 3): AI vulns +210%, prompt injection +540%, broken access control +36%, XSS still #1 but declining 10%, critical bounties avg $3K-$15K
- Updated STRATEGY.md with research findings and revised priorities
- Updated ROADMAP.md — removed completed items, reordered queues

**Lesson learned:**
- One session, one cycle. Don't try to touch all 4 cycles — pick the cycle, work the first item, wrap up.

**Queued for next session:**
- Cycle 1 (Scanning): Kiwi.com deep scan with new checks (IDOR, path traversal, GraphQL)

---

## Session 5 — 2026-09-28 (R&D — Cycle 2)

**Cycle step:** Scanner R&D & Buildout

**What was done:**
- Built IDOR detection module (10th scanner) — 30 REST API patterns, sequential ID testing, PII detection
- Built Path Traversal / LFI detection module (11th scanner) — Unix/Windows payloads, 5 encoding bypasses, baseline comparison, confirmation re-requests
- Added report templates for both modules (CWE-639 for IDOR, CWE-22 for path traversal)
- Added 20 new tests (10 IDOR + 10 path traversal) — 71 total tests passing
- Added educational explainers to vulnerability-detection.md for both modules
- Restructured ROADMAP.md from phase-based to cycle-based with 4 rotating work queues
- Updated README, CLAUDE.md, and all docs to reflect 11 scanner modules

**Improvements made:**
- Cycle-based project management system for autonomous session continuation
- Scan sizing guidelines (small/medium/large/huge programs)

**Queued for next session:**
- Cycle 1 (Scanning): Hyatt recon or Kiwi.com deep scan
- Cycle 2 (R&D): GraphQL Introspection module (next in queue)
- Run path traversal + IDOR checks against existing programs

---

## Session 4 — 2026-09-28 (Scout + Scan + R&D)

**Cycle step:** Scout + Scan + Review + R&D

**What was done:**
- Quick + deep scan on Kiwi.com: 6 targets, 8 real findings + 90 content discovery FPs
- Found CORS misconfiguration on tequila.kiwi.com (HIGH, 0.95 confidence) — reflects arbitrary origin with credentials
- Fixed blanket-403 false positive pattern in content discovery (hosts returning 403 for all paths)
- Cleaned 90 blanket-403 FPs from DB
- Evaluated CORS finding for test submission (first report candidate)
- Built comprehensive README with scanner architecture breakdown
- Created strategic analysis doc (docs/STRATEGY.md) for tracking progress, trends, and research
- R&D: researched current bug bounty meta and AI-assisted vulnerability classes

**Key finding:**
- **CORS on tequila.kiwi.com** — reflects arbitrary origin with `Access-Control-Allow-Credentials: true`. Tequila is Kiwi.com's travel API platform. However, manual re-verification showed the host now returns blanket 403 with no CORS headers — **not reproducible, NOT submitted**. Lesson: verify findings immediately before they go stale.

**Improvements made:**
- Content discovery now skips blanket-403 hosts (baseline probe detects the pattern)
- SSTI detector confirmation request (from earlier this session)

**Queued for next session:**
- Follow up on CORS submission outcome if submitted
- Hyatt: recon session, then sliced scans
- Continue R&D on new scanner modules from research
- Review strategic analysis and adjust priorities

---

## Session 3 — 2026-09-28 (Scout + Scan)

**Cycle step:** Scout + Scan

**What was done:**
- Fixed false positives: added third-party site detection, tightened open redirect validation, added DB dedup
- Cleaned 90 FP findings + 55 duplicates from DB
- Scouted 74 programs on HackerOne (72 new)
- Evaluated Hyatt (huge — 291 alive targets), Deriv (13 targets), Kiwi.com, Algolia (4 targets)
- Quick + deep scan on Deriv: 53 findings, 3 reportable (clickjacking, no HTTPS redirect) — low value
- Quick + deep scan on Algolia: 6 findings, 2 CRITICAL SSTI on dashboard.algolia.com (needs manual verification — could be search query syntax)
- Hyatt recon started but killed — too large for single session (805 subdomains)
- Added scan sizing guidelines to CLAUDE.md
- Created this session log

**Findings to follow up:**
- Algolia HTTP methods (PUT, DELETE, TRACE, PATCH) on www.algolia.com
- Deriv clickjacking on api.deriv.com and partners.deriv.com

**Investigated and closed:**
- Algolia SSTI on dashboard.algolia.com — FALSE POSITIVE. "49" was appearing in Cloudflare challenge tokens (random base64 strings), not template evaluation. Confirmed by re-requesting 3 times: "49" appeared inconsistently at different positions. Fixed SSTI detector to send confirmation request.

**Improvements made:**
- Fixed SSTI false positives: detector now re-requests to confirm "49" is consistent, filtering out random token noise
- Added scan sizing guidelines to CLAUDE.md (small/medium/large/huge program strategies)
- Created session log (this file) and added to startup checklist

**Queued for next session:**
- Hyatt: run recon (will take its own session), then slice scans with --limit 5 --filter
- Kiwi.com: quick scan (wildcard scope, should be manageable)
- Consider R&D step soon (haven't done one yet in the cycle)

---

## Session 2 — 2026-09-27 (Build + Scan)

**Cycle step:** R&D + Scan

**What was done:**
- Built 4 advanced scanner modules: content_discovery, injection, auth_checks, business_logic
- Added batch scanning (--quick, --limit, --filter, --checks)
- Added program scouting (scout command)
- Created CLAUDE.md with session continuation protocol and operating cycle
- Created submission guide (docs/submission-guide.md)
- Deep scan on CLEAR: found JWT on corpsupport.clearme.com, Google Sites FPs

**Findings:** JWT exposure on corpsupport.clearme.com (interesting), lots of Google Sites FPs

---

## Session 1 — 2026-09-27 (Build)

**Cycle step:** R&D + Scan

**What was done:**
- Built Phases 0-4 from scratch: platform integration, scope checker, recon pipeline, 5 scanner modules, reporting engine
- First scan against CLEAR (clearme.com): 46 targets, findings include CORS, SSL, missing headers
- Created all educational docs (glossary, how-it-works, ethics, vulnerability-detection)

**Findings:** CORS misconfig, SSL issues, missing security headers on CLEAR targets
