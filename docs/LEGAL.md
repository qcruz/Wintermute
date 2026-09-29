# Wintermute — Legal Context & Safe Harbor

Understanding the legal landscape for security research. This document is educational — not legal advice. When in doubt, consult a lawyer.

---

## Why This Matters

Bug bounty hunting involves probing computer systems for vulnerabilities. Without proper authorization, this activity can violate criminal and civil laws. Wintermute operates exclusively within authorized bug bounty programs to stay on the right side of the law, but understanding the legal framework helps make informed decisions about what to test and how.

---

## Relevant Laws (United States)

### Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030

The primary US federal law governing computer intrusions. Key provisions:

- **Unauthorized access** — Accessing a computer "without authorization" or "exceeding authorized access" is a federal crime
- **Damage provisions** — Causing damage (data loss, service disruption) through unauthorized access carries penalties of up to 10 years for first offense
- **Penalties** — Fines and imprisonment; civil liability for damages

**How bug bounties interact with CFAA:**
- A bug bounty program's scope defines the boundary of authorization
- Testing within scope = authorized access
- Testing outside scope = potentially unauthorized access
- Scope ambiguity is risky — when unclear, assume out-of-scope

**2024 DOJ Policy update:** The Department of Justice issued revised guidance stating it will not prosecute "good-faith security research" — defined as accessing a computer solely for purposes of good-faith testing, investigation, or correction of a security flaw, where conducted in a manner designed to avoid harm. This does NOT create a legal safe harbor but signals prosecutorial discretion.

### Digital Millennium Copyright Act (DMCA) — 17 U.S.C. § 1201

Prohibits circumventing technological protection measures (DRM, access controls). The 2021 exemption for security research allows circumvention for good-faith security testing of lawfully acquired devices and systems — but the scope is narrow and does not cover all bug bounty scenarios.

### State Computer Crime Laws

Most US states have their own computer crime statutes, some broader than the CFAA. California's Penal Code § 502 (Comprehensive Computer Data Access and Fraud Act) is particularly relevant for researchers based in or targeting California companies.

---

## International Considerations

### EU — NIS2 Directive & Member State Laws

The EU's NIS2 Directive (2022) encourages coordinated vulnerability disclosure but leaves implementation to member states. Some countries (Netherlands, Belgium, France) have explicit safe harbor for responsible disclosure; others do not.

### UK — Computer Misuse Act 1990

No safe harbor for security research. Even authorized bug bounty testing could theoretically violate the CMA, though prosecution is unlikely when conducted within a formal program. The UK Cyber Security Centre has called for reform but no legislation has followed.

### General Principle

When testing programs run by companies in other jurisdictions, you may be subject to the laws of:
1. Your location (where the testing occurs)
2. The company's location (where the server is)
3. The server's physical location (which may differ from the company)

---

## Safe Harbor Provisions in Bug Bounty Programs

### What Safe Harbor Means

Many bug bounty programs include a "safe harbor" clause in their policy, typically stating:

- The program will not pursue legal action against researchers acting in good faith
- The program considers authorized testing under their policy to be "authorized access" under CFAA
- The program will work with researchers before involving law enforcement

### What Safe Harbor Does NOT Mean

- It is NOT a legal immunity — the program's promise not to sue doesn't prevent law enforcement from prosecuting independently
- It does NOT cover out-of-scope testing
- It does NOT protect against third-party claims (e.g., if you access a user's data, that user could potentially sue)
- It does NOT override the laws of other jurisdictions

### HackerOne's Standard Safe Harbor Language

HackerOne encourages programs to adopt the disclose.io safe harbor framework. Programs with "Gold Standard" safe harbor include explicit language that:
- Authorized testing is considered "authorized" under CFAA and similar laws
- The program will not initiate legal action for good-faith testing
- The program will advocate on the researcher's behalf if a third party initiates legal action

**Always read each program's policy individually.** Not all HackerOne programs include safe harbor.

---

## Wintermute's Legal Risk Mitigation

### Built-in Controls

| Risk | Mitigation |
|------|-----------|
| Out-of-scope testing | Hard-gated scope checker, default deny |
| Data access | GET-only scanning, no credential brute-forcing, no real data exfiltration |
| Service disruption | Conservative rate limiting, no DoS payloads, immediate backoff on errors |
| Evidence handling | No storage of real user data, PII redaction, scan results gitignored |
| Authorization proof | Programs are fetched via HackerOne API, scope is programmatically verified |

### Best Practices for Researchers

1. **Screenshot your authorization** — save the program's scope page, safe harbor clause, and terms before testing
2. **Stay strictly in scope** — if a target isn't explicitly listed, don't test it
3. **Document everything** — maintain logs of what you tested, when, and what you found
4. **Report promptly** — don't sit on vulnerabilities; report through the designated channel
5. **Don't access real data** — even if a vulnerability allows it, stop at proof-of-concept
6. **Don't discuss publicly** — until the program authorizes disclosure
7. **Respond to program communications** — if they ask you to stop or clarify, do so immediately

---

## Resources

- [EFF: Coders' Rights Project](https://www.eff.org/issues/coders) — Legal resources for security researchers
- [disclose.io](https://disclose.io/) — Open-source safe harbor framework
- [DOJ CFAA Charging Policy (2022)](https://www.justice.gov/criminal-ccips/page/file/1501791/download) — Good-faith research guidance
- [HackerOne's Legal FAQ](https://www.hackerone.com/resources/hacktivity) — Platform-specific guidance
- [Bugcrowd's Vulnerability Disclosure Policy](https://www.bugcrowd.com/resource/what-is-responsible-disclosure/) — Alternative platform's approach
- [OWASP Testing Guide — Legal](https://owasp.org/www-project-web-security-testing-guide/) — Testing methodology with legal considerations

---

## Disclaimer

This document is for educational purposes only. It is not legal advice and should not be relied upon as such. Laws vary by jurisdiction and change over time. If you have specific legal questions about security research, consult a qualified attorney.

Last updated: 2026-09-29
