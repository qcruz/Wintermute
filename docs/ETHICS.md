# Wintermute — Ethics & Rules of Engagement

This document defines the mandatory ethical boundaries for all Wintermute operations. These are not guidelines — they are hard rules enforced in code wherever possible.

---

## Core Principles

1. **Authorization first.** Only test targets with explicit authorization through a public bug bounty program. No exceptions.
2. **Do no harm.** Never degrade, disrupt, or destroy any system, service, or data.
3. **Respect privacy.** Never access, store, or exfiltrate real user data, even if a vulnerability makes it possible.
4. **Transparency.** All findings are disclosed through proper channels. Never use vulnerabilities for personal gain beyond the stated bounty.
5. **Proportionality.** Use the minimum interaction necessary to confirm a vulnerability exists.

---

## Mandatory Rules

### Scope Compliance
- Every target MUST be validated against the program's published scope before any interaction
- Scope checking is a hard gate in the pipeline — it cannot be bypassed or overridden
- If scope is ambiguous, the target is treated as out-of-scope
- Wildcard scopes (e.g., `*.example.com`) are respected literally — do not infer broader permission

### Prohibited Actions
- Denial of service (DoS/DDoS) attacks or resource exhaustion of any kind
- Social engineering against employees, users, or staff
- Physical security testing
- Accessing, downloading, or modifying real user data
- Pivoting from an in-scope asset to out-of-scope internal systems
- Automated exploitation that could cause data loss or corruption
- Chaining vulnerabilities in ways that produce destructive effects
- Testing against production systems when staging/sandbox is available and specified

### AI-Specific Testing Rules
- Prompt injection tests use only safe canary strings — never instruct AI to perform harmful or destructive actions
- Never attempt to exfiltrate real user data through AI agents — only test for the vulnerability's existence
- Never instruct AI to modify, delete, or corrupt data even if prompt injection succeeds
- System prompt extraction findings must redact any user data or internal secrets revealed
- MCP/tool-use testing stays within the scope of the bug bounty program — never invoke tools that could affect production systems
- AI endpoint rate limits are respected — many AI APIs have strict rate limits and cost implications

### Rate Limiting & Stewardship
- Respect all rate limits published by the program or detected via HTTP headers
- Default to conservative scan rates (no more than 5 requests/second unless program permits more)
- Back off immediately on 429 responses or WAF blocks
- Schedule intensive scans during off-peak hours when possible
- Monitor for signs of service degradation and halt immediately if detected

### Data Handling
- Never store real user credentials, PII, or sensitive business data
- Scan results containing potential PII must be flagged and redacted before storage
- All evidence for reports uses sanitized examples or screenshots with sensitive data obscured
- Local databases and scan results are excluded from version control via .gitignore

### Disclosure
- All vulnerabilities are reported exclusively through the program's designated platform
- Follow the program's disclosure timeline — never publish before authorization
- If a critical vulnerability poses immediate risk to users, escalate urgency through the platform but do not go public
- Provide clear, actionable remediation guidance with every report

---

## Enforcement in Code

These rules are not just policy — they are implemented as technical controls:

| Rule | Implementation |
|------|---------------|
| Scope validation | `ScopeChecker` module runs before every scan; pipeline halts on failure |
| Rate limiting | Global rate limiter with per-target and per-platform limits |
| Data redaction | Output sanitizer strips potential PII patterns before storage |
| Prohibited actions | Scanner configurations hardcoded to exclude destructive payloads |
| Audit logging | Every action logged with timestamp, target, and scope verification result |

---

## Incident Response

If Wintermute accidentally:
- Accesses user data: immediately delete local copies, report the access path to the program, do not include the data in the report
- Causes service disruption: halt all scanning immediately, notify the program
- Scans an out-of-scope target: halt, log the error, review scope-checking logic, notify the program if any interaction occurred

---

## Updates

This document is reviewed whenever:
- A new vulnerability class is added to the scanner
- A platform changes its terms of service
- An incident occurs that reveals a gap in these rules

Last updated: 2026-09-28
