# Wintermute — Strategic Analysis

Living document tracking progress, successes, failures, trends, and research to guide project direction.

---

## Performance Summary

### Programs Scanned

| Program | Targets | Scans Run | Real Findings | Submitted | Outcome |
|---------|---------|-----------|---------------|-----------|---------|
| CLEAR | 46 | Quick + deep | CORS, SSL, JWT exposure, missing headers | 0 | Most low-value / likely dups |
| Deriv | 13 | Quick + deep | Clickjacking (2), no HTTPS redirect | 0 | Low value |
| Algolia | 4 | Quick + deep | HTTP methods (PUT/DELETE/TRACE) | 0 | SSTI was FP (Cloudflare tokens) |
| Kiwi.com | 6 | Quick + deep | CORS on tequila.kiwi.com | 0 | Not reproducible on re-verify |
| Hyatt | 291 (recon only) | Recon only | N/A | 0 | Too large, needs sliced scanning |

### Submissions: 0 sent, 0 accepted

**Why zero submissions so far:**
- Most findings are low-severity (missing headers, SSL cert expiry) — known to be heavily duplicated
- CORS finding on Kiwi.com was strong but became unreproducible before submission
- JWT finding on CLEAR needs deeper investigation
- We're still calibrating — better to hold than submit weak reports and damage Signal score

### False Positive Rate

| FP Type | Count | Fix Applied |
|---------|-------|-------------|
| Google Sites third-party redirects | 90 | Third-party detection in 3 modules |
| DB duplicate findings | 55 | Dedup check in `_store_findings()` |
| Blanket-403 content discovery | 90 | Baseline status check |
| SSTI random token ("49" in Cloudflare tokens) | 2 | Confirmation re-request |
| Open redirect on Google login redirects | ~20 | Require `location.startswith(canary)` |
| JWT tokens in CDN signed URLs (Filestack) | 8 | Skip JWTs in URL query params with /cdn, /image, /file context |
| localhost references in JS URL constructors | 3 | Skip Internal URL findings for localhost/127.0.0.1 |
| **Total FPs caught and fixed** | **~268** | |

Our false positive detection is improving with each scan. The pattern: scan a new program, discover a new FP class, fix it, move on.

---

## Lessons Learned

### What's Working
- **Scope enforcement** — zero out-of-scope incidents, the hard gate works
- **Quick scan mode** — 12-50 second scans for small programs, enables rapid scouting
- **Batch controls** — `--limit`, `--filter`, `--checks` prevent runaway scans
- **FP feedback loop** — each scan teaches us a new FP pattern to fix

### What's Not Working Yet
- **No submissions** — we haven't proven the pipeline can produce reportable findings
- **Finding quality** — most findings are informational (missing headers, cert expiry) that programs reject
- **Deep vulns now building** — IDOR, path traversal, and GraphQL modules built; need live findings to validate them
- **Timing gap** — CORS on Kiwi.com was real but went stale before we could submit. Findings need faster turnaround.
- **Large program handling** — Hyatt (291 targets) needs multi-session strategy

### Key Insight
> The bugs that pay bounties (IDOR, access control bypass, SSRF, stored XSS) require understanding application logic, not just probing headers and common paths. Our current checks are "layer 1" — surface-level. We need "layer 2" checks that understand API patterns, auth flows, and data exposure.

---

## Current Bug Bounty Meta (Research)

### What's Paying in 2026

Based on HackerOne Hacktivity, public disclosures, and bounty trends:

| Bug Class | Avg Bounty | Our Detection | Gap |
|-----------|-----------|---------------|-----|
| **IDOR / Broken Access Control** | $500-5,000 | **Built** (12 modules) | 30 API patterns, sequential ID testing, PII detection |
| **SSRF** | $1,000-10,000 | None | Need URL parameter testing with canary callbacks |
| **Stored XSS** | $500-3,000 | Reflected only | Need form submission testing (POST), DOM analysis |
| **Authentication Bypass** | $1,000-10,000 | Basic cookie/JWT checks | Need token manipulation, privilege escalation patterns |
| **Information Disclosure via API** | $200-2,000 | Partial (missing auth check) | Need response content analysis, PII detection |
| **Subdomain Takeover** | $200-1,000 | Good | Working well, but common/competitive |
| **CORS with impact** | $200-1,000 | Good | Need to verify authenticated data exposure, not just header reflection |
| **GraphQL vulnerabilities** | $500-5,000 | **Built** (12 modules) | Introspection query, mutation/query analysis, severity classification |
| **Race Conditions** | $500-5,000 | None | Complex — needs concurrent request testing |
| **Path Traversal / LFI** | $500-5,000 | **Built** (12 modules) | Traversal canaries, 5 encoding bypasses, baseline comparison |
| **Prompt Injection (AI)** | $500-15,000 | None (priority R&D) | AI vuln reports up 210%, prompt injection up 540% — fastest growing category, Anthropic pays up to $15K |
| **MCP Server Vulnerabilities** | $500-10,000 | None (priority R&D) | 30+ CVEs in 60 days, 82% have path traversal, only 8.5% use OAuth |

### AI Agent Hacking — Emerging Attack Surface

AI agents and LLM-integrated applications are a rapidly growing attack surface. Programs are increasingly listing AI features in scope.

| Attack Class | Description | Detection Approach |
|-------------|-------------|-------------------|
| **Prompt Injection** | Injecting instructions into LLM inputs via user-controlled data | Test input fields with prompt injection canaries ("Ignore previous instructions and..."), check if AI-generated responses change behavior |
| **Indirect Prompt Injection** | Poisoning data sources (emails, documents, web pages) that AI agents consume | Detect AI agent endpoints, test for data exfiltration via crafted responses |
| **Tool Use Abuse** | Tricking AI agents into calling tools with attacker-controlled parameters | Identify AI agent tool-calling patterns, test for unauthorized actions |
| **Context Window Leakage** | Extracting system prompts, other users' data, or training data from AI responses | Test AI endpoints with extraction prompts, check for information leakage |
| **Excessive Agency** | AI agents performing actions beyond their intended scope | Map agent capabilities, test boundary conditions |
| **Insecure Output Handling** | AI-generated content rendered without sanitization (XSS via AI) | Test AI response rendering for script injection |

**Opportunity:** Most automated scanners don't test for AI-specific vulnerabilities. This is a low-competition, high-value niche.

### Research Resources
- HackerOne Hacktivity — filter by bounty amount and recency
- OWASP Top 10 for LLM Applications 2026 (updated from 2025)
- PortSwigger Web Security Academy — lab-based learning
- Bug bounty write-ups on Medium, HackerOne blog
- AI vulnerability research: OWASP, NIST AI RMF, Anthropic's responsible disclosure work
- NSA/CISA MCP Security Design Guidance (June 2026)
- OX Security MCP SDK vulnerability research

---

## AI Agent Security — Deep Research (Session 11)

This section captures detailed research on the AI/LLM attack surface landscape, which is Wintermute's specialty focus area. Updated 2026-09-28.

### OWASP Top 10 for LLMs — 2026 Changes

The 2026 update incorporated real-world incident data for the first time, shifting from theoretical risks to observed attack patterns.

| Rank | 2025 | 2026 | Change |
|------|------|------|--------|
| 1 | Prompt Injection | Prompt Injection | Stable — still #1, now split into direct/indirect subtypes |
| 2 | Sensitive Info Disclosure | Sensitive Info Disclosure | Stable |
| 3 | Supply Chain Vulnerabilities | **Excessive Agency** | Rose from #6 — agents taking real-world actions are higher risk |
| 4 | Data & Model Poisoning | Data & Model Poisoning | Stable |
| 5 | Improper Output Handling | Improper Output Handling | Stable |
| 6 | Excessive Agency | **Unbounded Consumption** | Rose from #10 — cost/resource attacks on AI systems |
| 7 | System Prompt Leakage | **Hidden Context Exposure** | Broadened — not just system prompts, but all hidden context |
| 8 | Vector & Embedding Weakness | Vector & Embedding Weakness | Stable |
| 9 | Misinformation | Misinformation | Stable |
| 10 | Unbounded Consumption | Supply Chain Vulnerabilities | Dropped — better tooling has reduced this |

**Key shift:** The theme is moving from "protecting the conversation" to "containing the consequences." As AI agents gain tool-use capabilities (MCP, function calling), the blast radius of a successful attack expands from data leakage to real-world actions — file deletion, credential theft, unauthorized API calls.

**Wintermute implications:**
- Excessive Agency (#3) is directly testable — map what tools an agent has, test if it will execute out-of-scope actions
- Hidden Context Exposure (#7) broadens our attack surface — not just system prompt extraction, but any hidden context (user data, tool configurations, memory)
- Unbounded Consumption (#6) is a new class we haven't considered — AI cost attacks, infinite loops, resource exhaustion

### HackerOne AI Bounty Landscape

**Growth:**
- AI vulnerability reports increased 210% YoY on HackerOne
- Prompt injection reports specifically up **540% YoY** — fastest growing category
- HackerOne launched "Agentic Prompt Injection Testing" program in March 2026

**Notable programs with AI in scope:**
- **Anthropic** — public program on HackerOne (launched May 2026), up to $15K per finding, specifically scopes Claude, API, and agent capabilities
- Multiple programs now explicitly list AI features (chatbots, AI assistants, LLM-powered search) as in-scope assets

**Real-world incidents (2026):**
- Claude Code agent hijacked via prompt injection to exfiltrate GitHub credentials via Actions workflow
- Gemini CLI agent tricked into running malicious commands through crafted repository content
- GitHub Copilot agent manipulated via indirect prompt injection in code comments
- Pattern: attackers poison content that AI agents consume (repos, docs, web pages), then the agent executes attacker-controlled actions

**Wintermute implications:**
- Anthropic's program is a natural first target for our AI security scanners — we understand the technology
- Agent credential exfiltration via CI/CD is a high-value pattern to detect
- Indirect prompt injection via stored content (code comments, docs, web pages) is the most common real-world vector

### MCP (Model Context Protocol) Security

MCP is the emerging standard for AI agent tool use. Its security posture is poor — it was designed for functionality first, security second.

**Vulnerability landscape:**
- **30+ CVEs** filed against MCP servers in first 60 days of widespread adoption
- **CVE-2026-33032** — CVSS 9.8, actively exploited, critical MCP server vulnerability
- OX Security found command execution vulnerability in **Anthropic's official MCP SDKs** (Python, TypeScript, Java, Rust) — estimated ~200K vulnerable instances
- **82%** of MCP implementations have path traversal risks
- Only **8.5%** of MCP implementations use OAuth for authentication
- NSA and CISA published joint MCP security design guidance (June 2026)

**Key attack patterns:**
| Attack | Description | Severity | Detectability |
|--------|-------------|----------|---------------|
| **Tool Poisoning** | Malicious instructions hidden in tool metadata/descriptions that override agent behavior | Critical | Medium — requires reading tool schemas |
| **Path Traversal** | MCP file-access tools allowing reads/writes outside intended directories | High | High — standard traversal payloads work |
| **Command Injection** | Unsanitized user input passed to shell commands via MCP tools | Critical | High — standard injection patterns |
| **Auth Bypass** | MCP servers lacking authentication, allowing unauthorized tool invocation | High | High — probe without credentials |
| **Rug Pull** | Tool descriptions change after approval to include malicious instructions | Critical | Low — requires monitoring over time |
| **Token Theft** | MCP tools accessing and exfiltrating stored credentials/tokens | Critical | Medium — requires understanding agent context |

**Wintermute implications:**
- Tool poisoning is the highest-leverage attack — one poisoned tool description can hijack an entire agent session
- Path traversal in MCP is detectable with our existing path traversal module patterns
- Auth bypass on MCP servers is detectable with our existing auth check patterns
- We should build an MCP-specific scanner that probes MCP server endpoints for these patterns

### AI Attack Taxonomy for Scanner Development

Based on research, these are the attack classes we should build detection for, ordered by feasibility and bounty value:

| Priority | Attack Class | Bounty Range | Detection Feasibility | Module Status |
|----------|-------------|-------------|----------------------|---------------|
| 1 | **Direct Prompt Injection** | $500-$15K | High — send canary prompts, check responses | **Built** (14th module) |
| 2 | **System Prompt Extraction** | $500-$5K | High — well-known extraction phrases | **Built** (part of Prompt Injection module) |
| 3 | **MCP Auth Bypass** | $500-$10K | High — probe MCP endpoints without auth | Planned (Cycle 2 queue #2) |
| 4 | **MCP Path Traversal** | $500-$10K | High — reuse existing traversal patterns | Planned (Cycle 2 queue #2) |
| 5 | **Indirect Prompt Injection** | $1K-$15K | Medium — requires understanding what content the AI consumes | Planned (Cycle 2 queue #1) |
| 6 | **AI Data Exfiltration** | $1K-$10K | Medium — need to detect information leakage in AI responses | Planned (Cycle 2 queue #3) |
| 7 | **Excessive Agency Testing** | $500-$5K | Medium — need to map agent capabilities first | Planned (Cycle 2 queue #4) |
| 8 | **Tool Poisoning Detection** | $1K-$15K | Low — requires access to tool schemas, may be out of scope for external testing | Research phase |

### Programs to Target for AI Security Testing

Based on research, these programs have AI features in scope:

| Program | AI Features | Platform | Notes |
|---------|------------|----------|-------|
| Anthropic | Claude API, Claude.ai, agent capabilities | HackerOne | Up to $15K, natural fit for our expertise |
| Programs with chatbots | Customer service AI, AI assistants | Various | Scout with `--filter` for AI/chat keywords |
| Programs with AI search | AI-powered search, RAG implementations | Various | Test for prompt injection via search queries |
| Programs with MCP servers | Tool-use integrations | Various | Test for auth bypass, path traversal, tool poisoning |

**Next step:** Run `scout` with filters for programs mentioning AI, chatbot, LLM, or machine learning in their scope.

---

## Strategic Priorities

### Immediate (Next 2-3 Sessions)
1. **Get first submission** — run new deep checks (IDOR, path traversal, GraphQL, JS analysis) against all programs; verify and submit any strong findings immediately
2. **Faster turnaround** — when a strong finding appears, verify and submit in the same session before it goes stale
3. **Scan fresh programs** — scout and scan new programs where competition may be lower

### Short-term (Next 5-10 Sessions)
4. **MCP security testing** — probe MCP server endpoints for auth bypass, path traversal, command injection, tool poisoning
5. **Scan AI-integrated targets** — run the new AI prompt injection module against programs with AI features
6. **SSRF detection** — test URL parameters with callback canaries (requires callback server setup)
7. **Hyatt sliced scanning** — large attack surface, slice recon by domain subsets
8. **Scout AI-focused programs** — find HackerOne programs with chatbots, AI assistants, LLM APIs in scope

### Medium-term (10-20 Sessions)
9. **AI Data Exfiltration module** — detect AI agents leaking data through crafted inputs
10. **Insecure AI Integration module** — test for AI endpoints lacking auth, rate limiting, input validation
11. **Stored XSS** — requires POST request capability (careful: violates current GET-only safety rule, needs ethics review)
12. **Bugcrowd integration** — expand to second platform for more program coverage

### Long-term Vision
- Become a recognized specialist in AI agent security testing
- Build a portfolio of accepted AI security reports demonstrating expertise
- Contribute findings back to the security community via write-ups
- Open-source the tooling so others can learn and contribute
- Explore whether AI agents can autonomously identify novel vulnerability patterns

---

## Practical Benefits & Differentiation Framework

### Why This Project Matters Long-Term

The value of Wintermute is not just bounty income — it's the compound effect of building specialized capabilities in a fast-moving security domain. Here's what the project trajectory actually produces:

**1. Deep technical understanding of a frontier attack surface.**
AI agent security is a discipline that barely existed 18 months ago. By building detection tooling from scratch — not just using existing frameworks — we develop a first-principles understanding of how these attacks work, why they succeed, and what defenses fail. This understanding is worth more than any individual bounty because it compounds: each module built makes the next one easier and more effective.

**2. A differentiated scanner that fills a real gap.**
Existing security scanners (Nuclei, Burp Suite, ZAP, Semgrep) are excellent at traditional web vulnerabilities. None of them have meaningful AI agent vulnerability detection. Here's the landscape:

| Tool | Traditional Web | AI/LLM Security | MCP Security |
|------|----------------|-----------------|--------------|
| Nuclei | Excellent (9,000+ templates) | None | None |
| Burp Suite | Excellent | None native (some extensions) | None |
| OWASP ZAP | Good | None | None |
| Semgrep | Source code rules | Some LLM rules (static only) | None |
| Garak (NVIDIA) | None | Prompt injection probes | None |
| **Wintermute** | Good (14 modules) | **Prompt injection, endpoint discovery, system prompt extraction** | **Planned** |

Wintermute's general web scanning will never match Nuclei's 9,000 templates — and it doesn't need to. The differentiation is in the AI security layer that sits on top of the recon pipeline. No existing tool combines subdomain enumeration, scope-gated scanning, AI endpoint discovery, prompt injection testing, AND automated HackerOne report generation in a single pipeline.

**3. Educational and community value.**
The open-source, educational design means every module built is also a teaching tool. The vulnerability-detection docs explain each attack class in plain language. As AI security becomes a critical skill, this becomes a reference implementation that others can learn from.

### How Wintermute Can Develop Unique Function

Based on our R&D history and session trajectory, here's the framework for developing differentiated capabilities:

**Layer 1: Foundation (Built)**
General web security scanning that provides the recon pipeline, scope enforcement, finding storage, and reporting engine. This is the infrastructure that everything else builds on. 14 modules across XSS, SQLi, IDOR, CORS, path traversal, GraphQL, JS secrets, etc.

**Layer 2: AI Endpoint Intelligence (Building)**
The AI prompt injection module represents the beginning of this layer. It discovers AI endpoints that traditional scanners ignore entirely, then tests them with AI-specific attack patterns. Unique capabilities:
- AI endpoint discovery across 30+ path patterns (chat APIs, MCP servers, LLM proxies)
- HTML analysis for AI feature indicators (chat widgets, copilot integrations)
- Safe canary-based prompt injection testing
- System prompt extraction detection

**Layer 3: Agent Behavior Analysis (Planned)**
This is where Wintermute becomes truly differentiated. Future modules will:
- **Map agent capabilities**: discover what tools an AI agent has access to, what actions it can take, what data it can access
- **Test agency boundaries**: can the agent be instructed to exceed its intended scope? Can it call tools it shouldn't?
- **MCP security analysis**: probe MCP server endpoints for auth bypass, path traversal, tool poisoning, and the rug-pull attack pattern
- **Indirect injection via stored content**: test whether AI agents that consume web content can be poisoned through content we control within scope

**Layer 4: Pattern Recognition (Future)**
As the database of findings grows, Wintermute can start recognizing patterns that humans miss:
- Which AI integration patterns are most vulnerable?
- Which frameworks/SDKs produce the most security issues?
- What does a "typical" vulnerable AI endpoint look like in terms of response format, headers, and behavior?
- Cross-program correlation: if program A has a vulnerability pattern, do similar programs have the same issue?

### What Makes This Approach Work

**The AI-builds-AI-security feedback loop.** Wintermute is built by AI (Claude Code), scans for AI vulnerabilities, and reports them to programs that build AI. This creates a unique feedback loop where:
- Building AI security scanners deepens our understanding of AI attack surfaces
- Finding AI vulnerabilities in real programs validates and improves our detection
- Each bounty interaction teaches us what triagers consider valid vs. noise
- The tooling itself serves as a proof of concept for AI-assisted security research

**Compound specialization over breadth.** Rather than trying to match Nuclei's breadth, we're building depth in a domain where nobody else is automated yet. Every session adds either:
- A new AI detection capability (depth)
- A new program scanned with existing capabilities (breadth of testing)
- Research that informs what to build next (strategic direction)

This cycle-based approach ensures we don't get stuck on any one dimension.

**The timing advantage.** AI agent security is in its "early web security" phase — the equivalent of XSS in 2005. The attack patterns are being discovered faster than defenses are deployed. Programs are actively listing AI features in scope. The 540% growth in prompt injection reports shows demand, but the tooling hasn't caught up. Building specialized detection now — while the field is young — gives us a head start that compounds as the attack surface grows.

### Risks and Honest Assessment

- **Bounty income may be slow.** Our 0-for-10 submission record reflects calibration, not failure, but we need accepted reports to validate the approach.
- **AI features may be hard to find in scope.** Not all programs have AI endpoints. We need to specifically scout for AI-integrated targets.
- **False positives in AI testing are different.** An AI that says "I'm an assistant" isn't leaking its system prompt. The confidence thresholds need tuning against real targets.
- **The field moves fast.** Attack patterns we build for today may be mitigated in frameworks by next quarter. We need to stay current with research.

---

## Review Cadence

Update this document every 3-4 sessions or after significant events (first submission, first bounty, major FP discovery, new scanner module).

| Date | Event | Notes |
|------|-------|-------|
| 2026-09-27 | Project started | Phases 0-4 built in first session |
| 2026-09-27 | First scans (CLEAR) | Mostly low-value findings, Google Sites FPs |
| 2026-09-28 | Scouted 74 programs | Deriv, Algolia, Kiwi.com, Hyatt evaluated |
| 2026-09-28 | First submission candidate (CORS) | Not reproducible on re-verify — lesson learned |
| 2026-09-28 | Strategy doc created | Shifting focus toward higher-value bug classes |
| 2026-09-28 | Built IDOR, path traversal, GraphQL modules | 3 deep-scan modules in one session, 12 total scanners |
| 2026-09-28 | HackerOne meta research | AI vulns +210%, prompt injection +540%, broken access control +36%, XSS still #1 but declining 10%, critical bounties avg $3K-$15K |
| 2026-09-28 | MIT license added | Project now formally open-source |
| 2026-09-28 | AI agent security deep research | OWASP LLM 2026, HackerOne AI bounties, MCP vulnerabilities — specialty focus established |
| 2026-09-28 | JS Analysis module built | 13th scanner, secret detection in JS files |
| 2026-09-28 | Wealthsimple deep scan (3 batches) | 27 findings, 0 high-confidence — well-secured |
| 2026-09-28 | AI Prompt Injection module built | 14th scanner, first AI-specific detection capability, 15 new tests |
| 2026-09-28 | Differentiation framework written | Long-term strategy for unique specialization in AI agent security |
