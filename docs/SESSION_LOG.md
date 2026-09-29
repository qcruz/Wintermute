# Wintermute — Session Log

Track what each session accomplished, what was found, and what's queued for next time. Most recent session first.

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
