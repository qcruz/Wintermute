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
| **Total FPs caught and fixed** | **~257** | |

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
| **Prompt Injection (AI)** | $500-10,000 | None | AI vuln reports up 210%, prompt injection up 540% — fastest growing category |

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
- OWASP Top 10 for LLM Applications (2025)
- PortSwigger Web Security Academy — lab-based learning
- Bug bounty write-ups on Medium, HackerOne blog
- AI vulnerability research: OWASP, NIST AI RMF, Anthropic's responsible disclosure work

---

## Strategic Priorities

### Immediate (Next 2-3 Sessions)
1. **Get first submission** — run new deep checks (IDOR, path traversal, GraphQL) against all programs; verify and submit any strong findings immediately
2. **Faster turnaround** — when a strong finding appears, verify and submit in the same session before it goes stale
3. **Scan fresh programs** — scout and scan new programs where competition may be lower

### Short-term (Next 5-10 Sessions)
4. **JavaScript analysis** — parse JS files for hardcoded API keys, internal URLs, cloud credentials (high ROI, many programs leak secrets in JS)
5. **SSRF detection** — test URL parameters with callback canaries (requires callback server setup)
6. **Hyatt sliced scanning** — large attack surface, slice recon by domain subsets
7. **AI/LLM prompt injection** — fastest growing category (+540%), low competition from automated scanners

### Medium-term (10-20 Sessions)
8. **AI/LLM vulnerability scanning** — build detection for prompt injection, context leakage, insecure output handling
9. **SSRF detection** — test URL parameters with callback canaries (requires setting up a callback server)
10. **Stored XSS** — requires POST request capability (careful: violates current GET-only safety rule, needs ethics review)

### Long-term Vision
- Build a portfolio of accepted reports demonstrating the pipeline works
- Contribute findings back to the security community via write-ups
- Open-source the tooling so others can learn and contribute
- Explore whether AI agents can autonomously identify novel vulnerability patterns

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
