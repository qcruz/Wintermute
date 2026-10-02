# Wintermute — Session Log

Track what each session accomplished, what was found, and what's queued for next time. Most recent session first.

---

## Session 39 — 2026-10-01 (Research — Cycle 3: Competitive Analysis)

**Cycle step:** Research — Competitive analysis vs Nuclei, Burp Suite, community methodologies

**What was done:**

### Competitive Analysis
- Researched Nuclei (12,000+ templates), Burp Suite, ai-infra-nuclei project (84 AI templates), XSS-Rat 2026 guide, su6osec methodology
- Created detailed coverage comparison table in STRATEGY.md (11 detection categories)
- Identified key gaps and advantages

### Key Findings
- **Our advantage:** MCP security (unique — no competitor), integrated pipeline (recon→report→submit), AI endpoint discovery+testing (deeper than Nuclei's exposure-only detection)
- **Biggest gaps:** SSRF ($1K-$10K bounties, needs callback server), CVE scanning (commodity — don't compete), AI infrastructure exposure (81 products ship without auth, Nuclei's ai-infra project covers this)
- **New R&D item added:** AI Infrastructure Exposure detection — detect unauthenticated Ollama, vLLM, LangServe, MLflow, ChromaDB, Ray services. Natural extension of our AI specialty.
- **Strategic takeaway:** Don't compete on breadth (Nuclei wins). Double down on AI security depth — it's our moat.

### ROADMAP Updates
- Added "AI Infrastructure Exposure" as R&D item #10 (priority track)
- Bumped SSRF as highest-value general web gap
- Rotated competitive analysis to bottom of Cycle 3 queue

**Next:** Cycle 4 (Docs) is due — or Cycle 1 (Scanning) if prioritizing core activity.

---

## Session 38 — 2026-10-01 (R&D — Cycle 2: Manual Target Injection)

**Cycle step:** R&D — Manual target injection CLI feature

**What was done:**

### Manual Target Injection (`--add-targets`)
- New CLI flag: `python -m scripts.wintermute <handle> --add-targets host1,host2,host3`
- Scope-gated: checks each hostname against program scope before adding
- DNS resolution: resolves IPs and marks alive/dead
- Deduplication: skips hostnames already in DB
- Auto-creates program if not in DB (fetches from HackerOne API)
- Source tracked as `"manual"` for audit trail
- Replaces the raw Python workaround used in Session 37 for Anthropic base domains

### Also from background tasks (Session 37)
- Reviewed staging.claude.ai scan results: 7 JWT findings are all Cloudflare Access metadata tokens on the login redirect page, not real secrets. Cleaned 7 FPs.
- API scan (bpa0scomy) completed: only 1 AI endpoint found on internal.api.anthropic.com, 0 reportable

**Tests:** 172 (no change — feature tested manually against live program)
**FPs cleaned:** 7 (Cloudflare Access JWT on staging.claude.ai)

**Next:** Cycle 3 (Research) or Cycle 4 (Docs) — Cycle 1 and 2 done recently.

---

## Session 37 — 2026-10-01 (Scanning — Cycle 1: Anthropic + R&D Fix)

**Cycle step:** Scanning — Anthropic scan with AI/MCP modules

**What was done:**

### Anthropic Scanning
- Recon: 53 subdomains discovered (3 sources), 20 alive, 4 base domains manually injected
- Quick scan (3 targets): only HSTS missing on internal.api.anthropic.com
- AI deep scan on console.anthropic.com: 0 findings
- claude.ai targets: pivot.claude.ai `/api/admin` and `/api/internal` are SPA catch-all (same 7066-byte shell)
- support.anthropic.com: redirects to support.claude.com, has search feature
- docs.anthropic.com: 97 Stripe publishable key hits — all FPs (pk_ keys are intentionally public)
- staging targets: scanned but timed out on MCP module
- **Result: 0 reportable findings.** Anthropic's public surface is well-hardened. Real value is behind auth.

### Prompt Injection Reflection FP Fix (R&D)
- **Discovered scanner bug:** support.anthropic.com search reflects input in `<title>`, `<option>`, and analytics JS. Scanner saw canary string in response and flagged it as prompt injection, but it was just input reflection.
- **Root cause:** reflection check only compared raw prompt string. Missed HTML-encoded (`&quot;`) and URL-encoded (`%2B`, `%253A`) versions.
- **Fix:** new `_is_input_reflected()` function in `ai_prompt_injection.py`:
  - Checks raw, HTML-decoded, single/double URL-decoded versions
  - Falls back to contextual word proximity check (if significant prompt words appear near canary, it's reflection)
- **4 new tests** covering raw, HTML-encoded, URL-encoded reflection, and real injection pass-through
- Cleaned 112 FPs from DB (97 Stripe + 15 prompt injection)
- **This fix prevents FPs on any site with search functionality** — a class of false positive, not just one host

**Findings:** 0 reportable (5 informational: 1 HSTS, 1 robots.txt, 2 SPA catch-all, 1 AI endpoint discovery)
**Tests:** 172 (was 168, +4 new reflection detection tests)
**FPs cleaned:** 112

**Next:** Cycle 2 (R&D) is due. Prompt injection reflection fix was found during scanning — add to ROADMAP completed items. Continue with next R&D queue item (manual target injection or insecure AI integration).

---

## Session 36 — 2026-10-01 (Research — Cycle 3 + Strategy Update)

**Cycle step:** Research — Hacktivity analysis + post-duplicate strategy update

**What was done:**

### Post-Duplicate Strategy Update
- Updated STRATEGY.md with submission tracker, lessons learned, and revised priorities
- Key pivot: stop investing in common vuln types (CORS, headers, SSL) — always duplicates on established programs
- New focus: AI/MCP exploits, brand-new program scanning, authenticated scanning behind login walls

### Hacktivity Analysis (200 recent items)
- **Anthropic** paying $250 bounties recently — program is active
- **Notion** also paying $250 — our Tier 1 targets are viable
- **Vercel** paying $750 — interesting sandbox escape program
- **s-pankki** has 30 reports — likely new program launch
- **Stripe, Coinbase** still paying $1K-2K

### Anthropic Scope Analysis
- 15 in-scope assets, all bounty-eligible:
  - `claude.ai`, `api.anthropic.com`, `console.anthropic.com` — core AI platform
  - **Claude Code** — permission prompt bypass explicitly in scope
  - **Claude Desktop Extensions + MCP servers** — our MCP module directly applicable
  - `anthropic.atlassian.com` — Jira instance
  - `github.com/anthropics` — source code
  - **Leaked Employee API Keys** — JS secret module applicable
- **This is the ideal target for our AI security specialty.**

### Competitive Analysis (brief)
- Nuclei: 9,000+ templates but zero AI/MCP detection
- Burp Suite: no native AI testing
- Garak (NVIDIA): prompt injection only, no recon/scope/reporting
- **Our edge: integrated pipeline with AI-specific detection that no other tool has**

**Files changed:** `docs/STRATEGY.md`, `docs/ROADMAP.md`, `docs/SESSION_LOG.md`

**Queued for next session:**
- Cycle 1 (Scanning) — **Scan Anthropic**: recon + full pipeline with AI/MCP modules

---

## Session 35 — 2026-10-01 (R&D — Cycle 2)

**Cycle step:** R&D — Subdomain enumeration expansion

**What was done:**

### First Submission Confirmed
- Kiwi.com CORS report submitted successfully: **Report #4077213**, state: new
- Verified via API: `/hackers/me/reports` returns 1 report

### Subdomain Enumeration Expansion
- Added two new passive sources to `src/recon/subdomain.py`:
  - **HackerTarget API** — free, no auth, CSV format (hostname,ip)
  - **AlienVault OTX** — free, no auth, passive DNS JSON
- Results merge and deduplicate across all 3 sources
- Test results: HackerTarget found 51 github.com subdomains vs crt.sh's 2 (crt.sh was 502 again). 50 kiwi.com subdomains when crt.sh was down.
- Added 8 unit tests in `tests/test_recon.py` (parsing, filtering, error handling, dedup)
- Fixed test_reporting.py: CORS severity now always medium
- Full suite: 168 tests passing

**Files changed:** `src/recon/subdomain.py`, `tests/test_recon.py`, `tests/test_reporting.py`, `src/reporting/pipeline.py`, `src/reporting/templates.py`, `docs/ROADMAP.md`, `docs/SESSION_LOG.md`

**Queued for next session:**
- Cycle 3 (Research) or Cycle 1 (Scanning) — re-run recon on programs with poor enum (GitHub, Tinder, Grab) using new sources
- Monitor Kiwi.com report #4077213 for triage response

---

## Session 34 — 2026-10-01 (Scanning — Submission)

**Cycle step:** Submission — Kiwi.com CORS report (takes priority over cycle rotation)

**What was done:**

### Report Preparation
- Fixed CORS report pipeline: evidence dict was not being parsed from DB string → template rendered with empty ACAO/ACAC values. Fixed `pipeline.py` to use `ast.literal_eval()` on evidence string.
- Adjusted CORS template severity from auto-"high" (when credentials present) to always "medium" — CORS without proven data theft is Medium per HackerOne norms.
- Verified report renders correctly with actual reflected values.

### Submission Attempt
- API auth works (200 on /me/reports, 0 existing reports)
- Submission returned **400: Identity verification required** — Kiwi.com requires HackerOne ID verification before accepting reports
- **BLOCKER:** User needs to complete identity verification at hackerone.com/settings/identity

### Code Changes
- `src/reporting/pipeline.py`: Parse CORS evidence string back to dict for template
- `src/reporting/templates.py`: CORS severity always "medium" (was conditional on credentials)

**Queued for next session:**
- Re-submit Kiwi.com CORS after identity verification
- Continue Cycle 2 (R&D) — subdomain enumeration expansion

---

## Session 33 — 2026-10-01 (Scanning — Cycle 1)

**Cycle step:** Scanning — Quora/Poe batch scanning + review submission candidates

**What was done:**

### Quora/Poe Scanning
- Scanned 15 of 205 targets (up from 6). Covered all high-value non-dev targets: poe.com, hackathon.poe.com, proddebug.quora.com, phabricator.net.quora.com, help.poe.com, help.quora.com, tch.*.quora.com
- **hackathon.poe.com**: JWT weak config (HS256) + Adminer (403) — interesting but not submittable alone
- **corp.quora.com**: 15 AI + 7 MCP endpoints all behind 401 — needs auth cookies
- Remaining 190 targets are `*.main.quora.com` dev instances and `ww*.poe.com` parking domains — spot-checked, all produce only HSTS noise
- Killed a hung deep scan on proddebug.quora.com (40 min, likely MCP module on slow host)

### FP Cleanup (136 total)
- Deleted 4 old SSTI FPs on Quora (old `{{7*7}}` canary)
- Deleted 21 old SSTI FPs on Deriv (same old canary)
- Deleted 81 gist.github.com catch-all FPs (prompt injection + content discovery on user gist URLs)
- Deleted 24 mail.notion.so prompt injection FPs (catch-all routing)
- Deleted 10 HackerOne FPs (mta-sts takeover — owned by hacker0x01 org; leaderboards.hackerone.live SPA catch-all; hackerone.com /debug SPA route)

### Submission Candidate Review
- **Kiwi.com CORS on tequila.kiwi.com** — CONFIRMED REAL. Server reflects any arbitrary `Origin` with `Access-Control-Allow-Credentials: true`. Verified manually with curl. tequila.kiwi.com is Kiwi.com's B2B partner API portal (login, API keys, bookings). In-scope with bounty. **This is our #1 submission candidate.**
- HackerOne `.env` on leaderboards.hackerone.live — FP (SPA catch-all)
- HackerOne subdomain takeovers — FP (CNAMEs to hacker0x01.github.io, owned org)
- CLEAR JS secrets on corpsupport.clearme.com — needs investigation

**Key insight:** After 33 sessions and 11 programs, **Kiwi.com CORS is our first real submission candidate.** Origin reflection with credentials on a B2B portal is a medium-to-high severity finding.

**Files changed:** `docs/STRATEGY.md`, `docs/SESSION_LOG.md`, `docs/ROADMAP.md`

**Queued for next session:**
- Review Kiwi.com CORS report draft and potentially submit
- Investigate CLEAR corpsupport.clearme.com JS secrets
- Continue Cycle 1 scanning (next programs in queue)

---

## Session 32 — 2026-09-30 (Docs — Cycle 4)

**Cycle step:** Docs — Review and update all docs for accuracy after recent changes + document auth scanning workflow

**What was done:**

### Documentation Audit & Updates
- **`docs/operations.md`**: Added authenticated scanning section (`--auth` flag, `.auth/<handle>.json` config format, which modules support auth). Expanded check table from 9 to 16 modules with descriptions and `--quick` eligibility. Updated date.
- **`docs/vulnerability-detection.md`**: Fixed CORS wildcard+credentials section — was described as "a critical finding", now correctly states it's non-exploitable (browsers block credentials with wildcard origin). Added full Module 16 (AI Data Exfiltration) documentation: what it detects, 4 phases, valid examples, safety, OWASP/CWE references. Updated date.
- **`docs/how-it-works.md`**: Updated Step 4 from "Phase 3 — Current" / "building now" to reflect 16 scanner modules are built, including AI-specific modules and authenticated scanning. Updated Step 5 from "Phase 4 — Future" to document the fully built reporting engine (35 templates, dedup, interactive review, API submission). Updated date.

### Auth Scanning Workflow (partial)
- Documented in operations.md: CLI flag, config file format, supported modules
- Full standalone workflow doc deferred — current inline docs are sufficient

**Files changed:** `docs/operations.md`, `docs/vulnerability-detection.md`, `docs/how-it-works.md`

**Queued for next session:**
- Cycle 1 (Scanning) — Quora/Poe revisit with auth scanning, or review submission candidates

---

## Session 31 — 2026-09-30 (Research — Cycle 3)

**Cycle step:** Research — Review bounty payout trends, program economics, AI bounty landscape

**What was done:**

### Bounty Payout Trends Research
- HackerOne IBB payouts slashed 76-89% across all severity levels (critical $9,250→$2,257). IBB program paused.
- GitHub split into public (payouts halved) and invite-only VIP tier ($30K+ for critical). Quality gate: 1 critical or 2 high or 4 medium findings to qualify.
- AI-generated report flood is overwhelming triage teams — programs raising the bar for acceptance.
- Coinbase removed low/medium from public bounty path.

### Program Economics Analysis
- Documented payout data for our scanned programs: Grab ($200-500 avg), Wealthsimple ($500 avg, up to $20K), Quora ($100-7K), GitHub ($250-10K public, $30K+ VIP).
- Grab: high volume ($1M+ paid) but low per-finding ROI. Wealthsimple: better ROI. GitHub: not worth without VIP.

### AI Bounty Landscape
- 1,121 programs now include AI in scope.
- Realistic AI payout median: $500-$2,500 (not the $15-100K headlines).
- Anthropic: up to $20K, realistic $1.5K-$5K. OpenAI: up to $100K, typical $500-$3K.
- **Google AI VRP excludes prompt injection** — common mistake to avoid.
- What gets paid: tool abuse reaching infra, cross-tenant data exfil, system prompt extraction with secrets, indirect injection.
- What gets rejected: jailbreaks without impact, direct injection without exploitation chain, hallucinations.

### Strategic Implications
1. Stop chasing headers/SSL — pure noise
2. AI bounties are real but modest — need findings with impact beyond injection
3. Authenticated scanning is THE bottleneck — all promising targets behind auth
4. Quality > quantity — one well-documented critical > 100 automated reports
5. Target selection: consider adding Anthropic directly; deprioritize low-ROI programs like Grab

**Updated:** `docs/STRATEGY.md` with full payout intelligence, program comparison tables, AI bounty program details, and strategic recommendations.

**Queued for next session:**
- Cycle 4 (Docs) or Cycle 1 (Scanning): Consider adding Anthropic to scan targets; test auth scanning on a real target

---

## Session 30 — 2026-09-30 (R&D — Cycle 2)

**Cycle step:** Scanner R&D — Fix CORS, AI endpoint heuristic, MCP timeout (items 4-6 in queue)

**What was done:**

### CORS Scanner Fix
- `ACAO: *` with `ACAC: true` no longer marked as vulnerable — browsers block credentials with wildcard origin, so this is NOT exploitable
- Only origin reflection (`ACAO` echoes back attacker origin) is flagged as a real finding
- This was causing noise on Grab (img.geo.azure.myteksi.net) and Tinder (reports.gotinder.com)

### AI Endpoint Discovery Fix
- Static assets now filtered from AI endpoint link discovery:
  - File extensions: .css, .js, .png, .jpg, .jpeg, .gif, .svg, .ico, .woff, .woff2, .ttf, .eot, .map
  - Static directories: /static/, /assets/, /dist/, /build/, /public/
- Fixes the FP where `/static/css/main.b2d4226b.css` was flagged as an "AI feature link" on dev-website.ovofinansial.com

### MCP Security Timeout
- Added `MCP_MODULE_TIMEOUT = 300` (5 minutes) — entire module aborts after this
- Added 2-minute timeout on endpoint discovery phase (probing 24 paths)
- Fixes the 90-minute scan on auth-stg.ovofinansial.com from Session 29

### Tests
- 160 tests pass (+5 new: CORS wildcard behavior, CORS test origin safety, static asset filtering, real path preservation, MCP timeout value)
- Ruff clean

**Queued for next session:**
- Cycle 3 (Research): First item in queue — review bounty payout trends
- Or Cycle 1 (Scanning) if higher priority: test auth scanning on real target, rescan with fixed modules

---

## Session 29 — 2026-09-30 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Deep scan Grab and Tinder, review quick-scan results from Session 28

**What was done:**

### Tinder Review
- Quick scan completed: 59 targets, 25 findings — all missing HSTS headers (95% dup probability)
- CORS finding on `reports.gotinder.com`: `ACAO: *` + `ACAC: true` — verified non-exploitable (no origin reflection)
- crt.sh returned 502 for all 6 Tinder domains — zero subdomains enumerated. The 59 targets were from prior recon.
- **Assessment:** Tinder staging targets well-secured. Needs better recon (crt.sh unreliable) and auth scanning.

### Grab Deep Scan (8 targets across 4 batches)
- `gitlab-oidc.myteksi.net` — 16 checks, only HSTS
- `dev-website.ovofinansial.com` — AI endpoint FP (CSS file flagged as "chat_param"), HSTS only
- `auth-stg.ovofinansial.com` — insecure CSRF cookie (Django default, missing Secure/HttpOnly), HSTS. Scan took 90 min (mcp_security slow). Not bounty-worthy.
- `api.ovo.id` — 16 checks, only HSTS
- `hungrygowhere.com` / `www.hungrygowhere.com` / `go.hungrygowhere.com` — robots.txt, Apache 2.4.52 server version, crossdomain.xml, Bitly redirect cookie. Business logic flagged server version disclosure.
- CORS on `img.geo.azure.myteksi.net`: `ACAO: *` + `ACAC: true` — verified non-exploitable (wildcard origin, no reflection)
- Only 3 of 115 hungrygowhere.com subdomains alive (admin/staging/merchant targets all dead)

### Results
- **Grab total: 54 findings, 0 submittable.** All surface-level (HSTS, SSL, info disclosure)
- **Tinder total: 25 findings, 0 submittable.** All HSTS headers
- Both programs well-hardened at the unauthenticated surface level

### FP patterns identified
- AI `chat_param` heuristic too loose — flagged CSS file as AI endpoint
- CORS `ACAO: *` + `ACAC: true` is NOT exploitable (browsers block credentials with wildcard) — our scanner should check for origin reflection instead

### Analysis
- 11 programs scanned total, 0 submissions. Unauthenticated scanning consistently finds only surface-level noise.
- The real attack surface on every promising target (Quora, Notion, GitHub, Grab, Wealthsimple) is behind authentication.
- Key capability gaps: (1) subdomain enumeration beyond crt.sh, (2) auth scanning on real targets, (3) CORS scanner should test origin reflection not just header presence
- mcp_security module is too slow (90 min on auth-stg) — needs timeout or optimization

**Queued for next session:**
- Cycle 2 (R&D): Fix CORS scanner to test origin reflection; add timeout to mcp_security; improve AI endpoint discovery heuristic
- Cycle 1 backlog: Test auth scanning on a real target (need session cookies)
- Consider: subdomain enum expansion (crt.sh failing frequently), manual target injection

---

## Session 28 — 2026-09-29 (R&D + Scanning — Cycles 2 & 1)

**Cycle steps:** R&D — Build authenticated scanning infrastructure; Scanning — Scout and quick-scan fresh programs

**What was done:**

### Auth Scanning (Cycle 2 — R&D)
- Built `src/core/http_client.py` — shared HTTP client with auth support:
  - `AuthConfig` dataclass (cookies + headers)
  - `load_auth(program_handle)` — loads from `.auth/<handle>.json`
  - `make_client(auth)` — creates httpx client with auth injected
  - `get(url, auth)` — convenience function for one-off authenticated requests
- Wired auth through the full pipeline:
  - CLI: `--auth` flag on `wintermute.py`
  - Runner: `run_full_pipeline(use_auth=True)` loads auth from config
  - Pipeline: `run_scan(auth=auth)` passes to scanner modules
  - Modules updated: `content_discovery`, `ai_prompt_injection`, `ai_data_exfil`, `mcp_security`
- Created `.auth/` directory (gitignored) with example config
- 155 tests pass (+4 auth tests), ruff clean

### Program Scouting (Cycle 1 — Scanning)
- Evaluated 9 new bounty programs: Spotify, AT&T, PayPal, Flipkart, Grab, Tinder, Starbucks, Goldman Sachs, GoodRx
- **Top picks:**
  - **Grab** — 100+ targets discovered (hungrygowhere.com has admin, staging, QA, API, merchant panels). Huge attack surface with test/staging environments.
  - **Tinder** — 59 targets (staging domains explicitly in scope)
- Quick scans launched for both (running in background, results in DB for next session)
- crt.sh had intermittent 502 errors — some domains not fully enumerated

**Queued for next session:**
- Cycle 1 (Scanning): Review Tinder and Grab quick-scan results, deep scan most promising targets
- Cycle 2 backlog: Test auth scanning against corp.quora.com or Notion retool (need to obtain session cookies first)

---

## Session 27 — 2026-09-29 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Deriv revisit with improved SSTI filter

**What was done:**
- Rescanned 5 of 13 Deriv targets: ct, secure-dfadmin, home, cashier, app
- **SSTI fix validated:** 0 new SSTI findings on rescan (all 21 old ones were FPs from `{{7*7}}→49`)
- **Content discovery fix validated:** secure-dfadmin correctly blocked (blanket-403), cashier reduced to 2 fingerprint-confirmed findings
- Verified HTTP methods finding on cashier (TRACE allowed but behind Cloudflare — not bounty-worthy)
- Verified JS internal URL findings (all localhost URL constructor FPs — not reportable)

**Findings assessment:**
- 21 old SSTI findings: confirmed FPs, stale in DB
- 3 clickjacking: low impact (API/partner pages, not user-facing forms)
- 3 missing HSTS: 95% dup probability
- 3 JS internal URLs: FPs (localhost references)
- 1 HTTP methods (TRACE): not bounty-worthy
- 1 no HTTPS redirect: low value
- **0 reportable findings**

**Post-scan analysis:**
- Deriv is well-secured — no actionable vulns found across 2 full scan rounds
- SSTI and content discovery FP fixes both confirmed working in production
- Stale FP data in DB pollutes report list — future improvement: add DB cleanup for invalidated findings
- Deriv moved down in queue, rotated to continuous revisit list

**Queued for next session:**
- Cycle 2 (R&D): Authenticated scanning (#5 in queue)
- Cycle 1 backlog: Quora/Poe remaining targets, review submission candidates

---

## Session 26 — 2026-09-29 (R&D — Cycle 2)

**Cycle step:** Scanner R&D — Content discovery confidence tuning + catch-all redirect detection (FP fixes #3 & #4)

**What was done:**
- **Granular confidence scoring** for content discovery findings based on evidence quality:
  - `fingerprint` (content matched known signatures) → 0.85 confidence
  - `redirect_to_login` (path redirects to login page) → 0.5 confidence
  - `forbidden` (403 on admin/API paths) → 0.5 confidence
  - `status_only` (200 response, no fingerprint) → 0.4 confidence
  - Only fingerprint-confirmed findings now exceed the 0.7 high-confidence threshold
- **Catch-all redirect detection** — if the 404 baseline itself redirects to a login page, the entire host is skipped for content discovery (same approach as blanket-403 detection)
- Added `evidence_type` field to `DiscoveredEndpoint` dataclass for pipeline to use
- Verified fix against paymentcard.wealthsimple.com (correctly detected as catch-all redirect) and www.wealthsimple.com (correctly not flagged)
- 151 tests pass (+3 new), ruff clean

**Impact:** Eliminates 138+ content discovery FPs (the largest noise source at 41% of all findings). Catch-all redirect detection eliminates 18+ additional FPs from paymentcard.wealthsimple.com-type hosts. Total FPs caught: 557+.

**Queued for next session:**
- Cycle 1 (Scanning): Deriv revisit with improved SSTI filter (first item in queue)
- Cycle 2 backlog: Authenticated scanning (#5 in queue)

---

## Session 25 — 2026-09-29 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Wealthsimple deep scan (remaining targets by keyword)

**What was done:**
- Deep scanned 6 high-value Wealthsimple targets: api.sandbox, crypto-trust, paymentcard, trade-service-staging, work-staging, i2c-payment-gateway-server-0
- i2c-payment-gateway-server-0 timed out (locked-down server, stuck on content_discovery) — killed

**Findings (31 total across 6 targets):**

| Target | Findings | Assessment |
|--------|----------|------------|
| api.sandbox.wealthsimple.com | 0 | Clean |
| crypto-trust.wealthsimple.com | 0 | Clean |
| trade-service-staging.wealthsimple.com | 0 | Clean |
| paymentcard.wealthsimple.com | 19 | 1 business logic (clickjacking), **18 catch-all redirect FPs** — every path redirects to login |
| work-staging.wealthsimple.com | 12 | 1 insecure cookie (0.90), 9 content discovery (blanket-403 FPs), 1 AI endpoint (info), 1 dup |
| i2c-payment-gateway-server-0 | — | Timed out |

**New FP pattern discovered: catch-all redirect**
- paymentcard.wealthsimple.com redirects every path to `my.wealthsimple.com/app/login` with path as query param
- Content discovery module interprets this as "endpoint exists but requires auth" for all 18 admin/debug paths
- Different from catch-all 200 (already handled) — this is catch-all 301/302
- Added to R&D queue for fix

**Post-scan analysis:**
- 0 reportable findings from Wealthsimple deep scan — all staging/internal hosts are locked down
- Insecure cookie on work-staging is real but low value (staging domain that redirects to www)
- Wealthsimple's attack surface is well-hardened at the perimeter — real findings likely require auth scanning
- Updated STRATEGY.md with Wealthsimple results and new FP patterns

**Queued for next session:**
- Cycle 2 (R&D): Content discovery confidence tuning (#3 FP fix) or catch-all redirect fix
- Cycle 1 backlog: Deriv revisit, remaining Quora/Poe targets, review submission candidates

---

## Session 24 — 2026-09-29 (R&D — Cycle 2)

**Cycle step:** Scanner R&D — SSTI baseline comparison fix (FP fix #2)

**What was done:**
- Root-caused the SSTI false positive: `{{7*7}}→49` fails because "49" appears randomly in Cloudflare tokens and page content. The existing baseline check and confirmation re-request weren't sufficient because tokens change per request and "49" is a very common 2-digit string.
- **Fix 1:** Changed SSTI canary from `{{7*7}}→49` to `{{91*71}}→6461`. "6461" is far less likely to appear randomly.
- **Fix 2:** Skip SSTI detection entirely on non-200 responses. Template injection on 403/503 error pages is not real — the template engine isn't processing user input.
- Verified fix against all 3 known FP targets: gql.poe.com, corp.quora.com, creator-monetization.poe.com — all correctly filtered now.
- 148 tests pass, ruff clean.
- Updated ROADMAP.md (marked SSTI fix as ✅ DONE) and STRATEGY.md (updated FP count to 401+).

**Impact:** Eliminates 25 SSTI false positives across Deriv (21) and Quora/Poe (4).

**Queued for next session:**
- Cycle 1 (Scanning): Wealthsimple deep scan (first item in queue)
- Cycle 2 backlog: Content discovery confidence tuning (#3 FP fix)

---

## Session 23 — 2026-09-29 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Quora/Poe recon + targeted scan + catch-all validation

**What was done:**
- Ran recon on Quora/Poe: 206 subdomains discovered (172 quora.com, 34 poe.com), 205 in-scope targets
- Deep scanned 7 high-value targets: gql.poe.com, developer.poe.com, corp.quora.com, tch.corp.quora.com, proddebug.quora.com, phabricator.net.quora.com, creator-monetization.poe.com
- Quick scanned 3 poe.com targets (ww25.17173, hackathon, ww25.duowan)

**Catch-all routing validation:**
- corp.quora.com returns 403 for random paths → catch-all detection correctly did NOT fire
- AI/MCP endpoint discoveries on corp.quora.com are legitimate (15 AI + 7 MCP, all return 401)
- Catch-all detection working as designed — no false skips observed

**Findings (33 total across 6 targets):**
- **4 SSTI (all FPs)** — `{{7*7}}→49` on gql.poe.com, corp.quora.com, creator-monetization.poe.com. Verified: "49" appears in baseline response without payload. SSTI baseline fix (#2 R&D) confirmed as next priority.
- **16 AI endpoint discoveries** on corp.quora.com — all auth-gated (401). Real endpoints including `/api/chat`, `/assistant`, `/ai`, `/copilot`. Needs auth scanning.
- **7 MCP endpoint discoveries** on corp.quora.com — `/mcp`, `/mcp/sse`, `/mcp/stdio` etc. All auth-gated.
- **5 missing HSTS** — noise, 95% dup probability
- **1 clickjacking** on developer.poe.com — low impact (docs site)

**Post-scan analysis:**
- 0 reportable findings from Quora/Poe
- corp.quora.com is the most interesting target — real AI/MCP infrastructure behind auth
- SSTI baseline fix is now critical — 4 more FPs on top of 21 from Deriv = 25 total SSTI FPs
- Updated STRATEGY.md with Quora/Poe in programs table

**Identity verification:** Confirmed all HTTP requests use `Wintermute/0.1 (Security Research)` User-Agent consistently across all 16 scanner modules, recon, and pipeline. MCP client identifies as `wintermute-security-test`. No personal identity leaked in any requests.

**Queued for next session:**
- Cycle 2 (R&D): SSTI baseline comparison fix (#2 in queue — 25 FPs to eliminate)
- Cycle 1 backlog: Wealthsimple deep scan, Deriv revisit, remaining Quora/Poe targets

---

## Session 22 — 2026-09-29 (R&D — Cycle 2)

**Cycle step:** Scanner R&D — Catch-all routing detection (FP fix #1)

**What was done:**
- Implemented catch-all routing detection in `src/scanner/pipeline.py`
  - New `_detect_catchall()` function: requests a random UUID path, if it returns 200, host is catch-all
  - New `PATH_DISCOVERY_CHECKS` set: `content_discovery`, `ai_prompt_injection`, `ai_data_exfil`, `mcp_security`
  - Pipeline skips path-based checks for catch-all hosts, runs all other checks normally
  - Prints warning when catch-all detected so user sees it in output
- Verified against known catch-all hosts: mail.notion.so ✓, retool.mail.notion.so ✓
- Added 3 tests (PATH_DISCOVERY_CHECKS contents, exclusions, connection error handling)
- All 148 tests pass, ruff clean
- Updated ROADMAP.md: marked catch-all detection as ✅ DONE
- Updated STRATEGY.md: added catch-all FPs to the fixed FP table (110+ FPs eliminated)

**Impact:** Eliminates 110+ false positives across GitHub and Notion scans. This was the #1 FP source.

**Queued for next session:**
- Cycle 3 (Research): Review bounty payout trends (first item in queue)
- Cycle 2 backlog: SSTI baseline comparison (#2 FP fix), content discovery confidence tuning (#3)

---

## Session 21 — 2026-09-29 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — GitHub + Notion scans

**What was done:**

*GitHub scan:*
- Ran recon — crt.sh found only 2 subdomains (gist, classroom), manually added 4 key in-scope domains
- Scanned api.github.com: 1 finding — GraphQL console at /graphql/console (403, low value)
- Scanned gist.github.com: **86 findings, ALL false positives** — catch-all routing
- Discovered new FP class: **catch-all routing sites**

*Notion scan:*
- Recon found 8 in-scope targets (subdomains of mail.notion.so and calendar.notion.so)
- Quick scan: only 2 HSTS findings (95% dup probability)
- Deep scan on 3 priority targets (mcp.mail.notion.so, retool.mail.notion.so, api.mail.notion.so)
- AI-focused scan (ai_prompt_injection, ai_data_exfil, mcp_security) across all 7 alive targets
- **retool.mail.notion.so** — 17 legitimate findings: Retool admin panel with real `/api/chat` (401), `/api/mcp` (401), `/api/mcp/sse` (401), robots.txt reveals `/embedded/`. All auth-gated.
- **mail.notion.so** — 27 findings, ALL false positives from catch-all routing (second occurrence of this FP class)
- Verified catch-all vs real endpoints: mail.notion.so returns 200 for random paths; retool returns 401 for real API paths

**Post-scan analysis:**
- Updated STRATEGY.md with Notion analysis, programs table, catch-all routing second occurrence
- Catch-all routing fix is #1 R&D priority — 110+ FPs across 2 programs
- Authenticated scanning is the key blocker for all real AI endpoints found
- Base domain enumeration gap confirmed again (crt.sh misses notion.so like it missed github.com)
- No reportable findings from either program

**Queued for next session:**
- Cycle 2 (R&D): Fix catch-all routing FPs (first item in queue)
- Cycle 1 backlog: Quora/Poe, Wealthsimple, Deriv revisit

---

## Session 20 — 2026-09-29 (Docs — Cycle 4)

**Cycle step:** Project Organization & Docs — Draft LEGAL.md

**What was done:**
- Drafted `docs/LEGAL.md` — legal context for security research
  - CFAA overview and interaction with bug bounties
  - DMCA security research exemption
  - International considerations (EU NIS2, UK CMA)
  - Safe harbor provisions: what they mean and don't mean
  - Wintermute's built-in legal risk mitigations
  - Best practices for researchers
- Added LEGAL.md to documentation index
- Removed completed item from Cycle 4 queue

**Queued for next session:**
- Cycle 1 (Scanning): GitHub Copilot scan, Notion, Quora/Poe
- Cycle 2 (R&D): Insecure AI Integration module or SSTI FP fix
- Cycle 3 (Research): Review bounty payout trends

---

## Session 19 — 2026-09-29 (Research — Cycle 3)

**Cycle step:** Research & Strategic Planning — Analyze false positive rate

**What was done:**
- Analyzed all 333 findings across 6 programs for noise vs. signal
- Top noise generators: content_discovery (138, all 0.6 confidence), missing_security_header (57, all HSTS), exposed_file (46, 39 info-level)
- SSTI module: 21 findings, **100% false positive** — all `{{7*7}}→49` Cloudflare token pattern on Deriv
- High-signal modules identified: subdomain_takeover (4, 0.9 conf), cors (2), js_secret (11 after FP fixes)
- 72% of findings come from 3 modules that generate near-zero actionable signal
- Wrote full analysis to STRATEGY.md with fix priorities
- Fix priorities: (1) SSTI baseline comparison, (2) content_discovery confidence tuning, (3) filter info-level exposed_files from reports

**Queued for next session:**
- Cycle 4 (Docs): Case study doc (or combine with FP fixes)
- Cycle 1: GitHub Copilot scan, Notion, Quora/Poe
- Cycle 2: Insecure AI Integration module, or SSTI FP fix

---

## Session 18 — 2026-09-29 (R&D — Cycle 2)

**Cycle step:** Scanner R&D & Buildout — AI Data Exfiltration module

**What was done:**
- Built AI Data Exfiltration module (16th scanner) — third AI-specific detection capability
  - Context extraction probes: 5 prompts testing for user data, memory, RAG sources, tool configs, environment details
  - Indirect exfiltration probes: 3 prompts testing context summary, JSON state export, debug mode
  - Response analysis: PII patterns (email, phone, SSN, credit card), backend patterns (DB strings, internal IPs, API keys, AWS endpoints, bearer tokens), RAG source patterns, context leak patterns, tool config patterns
  - Reuses AI endpoint discovery from prompt injection module
- Full integration: pipeline scan loop with progress output, 4 report templates (CWE-200), reporting dispatch, 20 new tests (145 total)
- Removed completed item from Cycle 2 queue

**Queued for next session:**
- Cycle 3 (Research): Analyze false positive rate
- Then Cycle 4 (Docs): Case study doc
- Cycle 1 backlog: GitHub Copilot scan, Notion, Quora/Poe

---

## Session 17 — 2026-09-29 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Deriv remaining targets

**What was done:**
- Scanned all 13 Deriv targets — program fully complete (94 total findings)
- Added scan progress output to pipeline — shows `[1/3] hostname` and `(1/15) check_name...` for every target and check
- 21 SSTI findings across api-core, cashier, smarttrader — almost certainly FPs (same `{{7*7}}→49` pattern across all parameters on every host)
- No high-value submission candidates — reportable findings are clickjacking, internal URLs, missing HSTS/HTTPS, dangerous HTTP methods

**Lesson learned:** Always set hard time limits on scans. Never chain multiple scans in one command. Use Bash tool timeout parameter (120000ms for single targets).

**Queued for next session:**
- Cycle 2 (R&D): AI Data Exfiltration module
- Then Cycle 3 (Research): Analyze false positive rate
- Then Cycle 4 (Docs): Case study doc
- Cycle 1 backlog: GitHub Copilot scan, Notion, Quora/Poe

---

## Session 16 — 2026-09-29 (Docs — Cycle 4)

**Cycle step:** Project Organization & Docs — Create GitHub Actions CI pipeline

**What was done:**
- Created `.github/workflows/ci.yml` — runs ruff lint and pytest on push/PR to main
- Fixed 63 auto-fixable lint issues (unused imports, f-string placeholders, unsorted imports)
- Fixed 7 unused variable warnings (F841) across 6 files
- Added `E501` to ruff ignore list — long lines are data (regex, templates, descriptions), not code complexity
- Result: ruff passes clean, 125 tests pass
- Removed completed item from Cycle 4 queue

**Queued for next session:**
- Cycle 1 (Scanning): Deriv remaining targets, then GitHub Copilot scan
- Then Cycle 2 (R&D): AI Data Exfiltration module
- Then Cycle 3 (Research): Analyze false positive rate

---

## Session 15 — 2026-09-29 (Research — Cycle 3)

**Cycle step:** Research & Strategic Planning — Scout HackerOne programs with AI features

**What was done:**
- Scouted HackerOne programs for AI-integrated features to match against our prompt injection and MCP security modules
- Evaluated 12 programs: GitHub, Quora, Spotify, GoodRx, PayPal, Grab, Shopify, Notion, Automattic, Grammarly, Canva, Adobe
- Identified 3 Tier 1 AI targets:
  - **GitHub** — Copilot, Copilot Chat, Copilot Coding Agent, Copilot Spaces, GitHub Spark all in scope (27 assets)
  - **Notion** — Explicit `AI_MODEL` asset type for "Notion AI" with bounties; they specifically want data access bugs in AI
  - **Quora/Poe** — `poe.com` (multi-model AI chatbot platform) in scope alongside `*.quora.com`
- Identified 3 Tier 2 targets: Shopify (Sidekick AI, Inbox chat), Automattic (Jetpack AI, WordPress AI), Grab (AI-powered backend)
- Wrote full analysis to `docs/STRATEGY.md` — AI Target Scouting section with tiered recommendations
- Updated Cycle 1 queue: added Notion and Quora/Poe as scan targets after GitHub
- Rotated Cycle 3 queue: moved scouting to bottom

**Key insight:** Programs with explicit AI assets in scope (GitHub Copilot, Notion AI, Poe) are far more valuable than programs using AI internally. Explicit scope = expected reports, clear attack surface, less competition.

**Queued for next session:**
- Cycle 4 (Docs): CI pipeline setup (first item in Cycle 4 queue)
- Then Cycle 1 (Scanning): Deriv remaining targets, then GitHub Copilot scan
- Then Cycle 2 (R&D): AI Data Exfiltration module

---

## Session 14 — 2026-09-28 (R&D — Cycle 2)

**Cycle step:** Scanner R&D & Buildout — MCP Security module

**What was done:**
- Built MCP Security module (15th scanner) — second AI-specific detection capability
  - MCP endpoint discovery: 25+ path probes (JSON-RPC, SSE, REST, .well-known config)
  - Auth bypass testing: unauthenticated JSON-RPC `tools/list` and `initialize` requests
  - Dangerous tool detection: 15+ patterns for file/shell/DB/credential/code access
  - Tool poisoning detection: 7 patterns for malicious instructions in tool descriptions
  - Path traversal via MCP file tools: safe read-only payloads through JSON-RPC `tools/call`
- Full integration: pipeline scan loop, 5 report templates (CWE-306/250/94/22/200), reporting dispatch, 15 new tests (125 total)
- Updated vulnerability-detection.md with Section 15 explainer
- Updated README, CLAUDE.md, ROADMAP.md — all counts updated to 15 modules, 31 templates, 125 tests

**Queued for next session:**
- Cycle 1 (Scanning): Test both AI modules against real targets — GitHub (Copilot in scope), or scan remaining Deriv targets
- Cycle 2 (R&D): AI Data Exfiltration module next in queue
- Cycle 4 (Docs): Consider CI pipeline setup (first item in Cycle 4 queue)

---

## Session 13 — 2026-09-28 (Scanning — Cycle 1)

**Cycle step:** Scanning & Operations — Deep scan CLEAR and Deriv with new checks + AI module

**What was done:**
- Deep scanned CLEAR corpsupport.clearme.com with IDOR, path traversal, GraphQL, JS analysis, AI prompt injection (1m 46s)
  - 13 JS secret findings — all JWT tokens embedded in Filestack CDN image URLs (false positives)
  - No IDOR, path traversal, GraphQL, or AI endpoints found
- Deep scanned Deriv in 2 batches (6 targets total, 11m 42s total):
  - Batch 1 (ct, secure-dfadmin, home): 5 findings — internal URL localhost references in JS (false positives)
  - Batch 2 (api, api.derivws, staging-api.derivws): 4 findings — AI module discovered `/ai-hub/` on api.deriv.com (redirects to developer portal, not exploitable)
- Scouted 74 programs — identified GitHub (Copilot in scope), Spotify, PayPal as AI-rich targets
- Fixed reporting bug: `Finding` object missing `hostname` attribute — added `finding.hostname = target.hostname` in report generation
- Fixed 2 JS analysis false positive patterns:
  1. JWT tokens in CDN URL query parameters (`?token=eyJ...`) — not standalone credentials
  2. `http://localhost` references — standard JS URL-parsing fallbacks, not real internal endpoints

**Findings:** 0 new exploitable findings. CLEAR and Deriv are well-secured for these check classes.

**False positives caught:**
- CDN signed URL tokens (Filestack) flagged as JWT exposure — 8 instances on CLEAR
- `http://localhost` in URL constructors flagged as internal URL — 3 instances on Deriv
- Developer docs page flagged as AI endpoint — `/ai-hub/` is a docs redirect, not a chat API

**Queued for next session:**
- Cycle 1: Scan remaining Deriv targets (cashier, app, smarttrader, deriv.partners, api-core), then move to fresh programs
- Cycle 1: GitHub has Copilot, Copilot Chat, Copilot Coding Agent, Copilot Spaces all in scope — prime AI security target
- Cycle 2 (R&D): MCP security testing module next
- Consider: Programs scanned so far are well-secured. Fresh programs or AI-specific targets may yield more.

---

## Session 12 — 2026-09-28 (R&D — Cycle 2 + Strategic Analysis)

**Cycle step:** Scanner R&D & Buildout — AI/LLM Prompt Injection module

**What was done:**
- Built AI Prompt Injection module (14th scanner) — Wintermute's first AI-specific detection capability
  - AI endpoint discovery: 30+ path probes (chat APIs, MCP servers, LLM proxies, AI search), HTML analysis for AI feature indicators
  - Prompt injection testing: 3 safe canary prompts (instruction override, role escape, delimiter injection)
  - System prompt extraction: 4 extraction prompts, 8 leak detection patterns
  - Multi-format API probing: tries 6 JSON body formats to find working format, supports OpenAI-compatible and custom formats
  - AI response parsing: handles OpenAI, Anthropic, and custom response formats
- Full integration: pipeline scan loop, 3 report templates (CWE-77/CWE-200), reporting pipeline dispatch, 15 new tests (110 total)
- Updated ETHICS.md with AI-specific testing rules (safe canaries only, no destructive AI instructions, no data exfiltration)
- Updated vulnerability-detection.md with Section 14 explainer
- Updated README, CLAUDE.md, ROADMAP.md — all counts updated to 14 modules, 26 templates, 110 tests
- Wrote strategic differentiation analysis in STRATEGY.md — practical long-term benefits, 4-layer capability development framework, competitive landscape analysis, honest risk assessment

**Strategic analysis highlights:**
- Wintermute fills a gap no existing tool covers: combined recon + scope-gated scanning + AI security detection + automated reporting
- 4-layer development framework: Foundation (built) → AI Endpoint Intelligence (building) → Agent Behavior Analysis (planned) → Pattern Recognition (future)
- Key advantage: the AI-builds-AI-security feedback loop — building scanners deepens understanding, findings validate detection, bounties teach what triagers accept

**Queued for next session:**
- Cycle 1 (Scanning): Scout for AI-integrated programs, test prompt injection module against real targets
- Cycle 2 (R&D): MCP security testing module is next in queue

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
