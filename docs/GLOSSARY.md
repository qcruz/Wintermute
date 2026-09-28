# Wintermute — Glossary of Terms

A plain-language reference for every technical term used in this project.

---

## Bug Bounty Basics

**Bug bounty program**: A deal where a company says "try to hack us, and if you find
something real, we'll pay you." Companies post these on platforms like HackerOne.
It's legal because they explicitly authorize you to test.

**Scope**: The list of things you're allowed to test. A program might say
"you can test *.example.com but NOT support.example.com." Scope is sacred —
testing outside of it can be illegal.

**In-scope**: Targets you ARE allowed to test.

**Out-of-scope**: Targets you are NOT allowed to test. Even if you find something,
they won't pay you, and you might get banned or face legal trouble.

**Bounty**: The money paid for a valid vulnerability report. Ranges from $50 for
minor issues to $100,000+ for critical ones.

**Disclosure**: The act of telling a company about a vulnerability you found.
"Responsible disclosure" means you tell them privately and give them time to fix
it before (optionally) telling the public.

**Triage**: When the company's security team reviews your report to decide if it's
valid, a duplicate, or not applicable.

**Duplicate**: Someone else already reported the same bug. You get no bounty.
This is the most common outcome with automated scanning.

---

## Reconnaissance (Recon)

**Reconnaissance**: Gathering information about a target before testing it.
Like a detective doing research before an investigation. In our case, it's
automated information gathering about websites and servers.

**Subdomain**: A prefix added to a domain. For `mail.example.com`, "mail" is the
subdomain. Companies often have dozens or hundreds of subdomains, and forgotten
ones are common targets.

**Subdomain enumeration**: The process of discovering all subdomains for a domain.
We do this passively (no direct contact with the target) by checking public records.

**Certificate Transparency (CT) logs**: Public logs of every SSL/TLS certificate
ever issued. When a company gets a certificate for `secret-staging.example.com`,
that name becomes public record. We query crt.sh to find these.

**DNS (Domain Name System)**: The internet's phone book. Translates domain names
(like hackerone.com) to IP addresses (like 104.18.36.214). When we "resolve" a
hostname, we're looking up its IP address to see if it's still active.

**DNS resolution**: Looking up a hostname to get its IP address. If it resolves,
the host is "alive." If it doesn't, the subdomain exists in records but the
server is gone (which can sometimes be a vulnerability — see subdomain takeover).

**CIDR notation**: A way to write IP address ranges. `10.0.0.0/24` means
"all 256 IP addresses from 10.0.0.0 to 10.0.0.255." The /24 tells you how
many addresses are in the range.

---

## HTTP & Web Concepts

**HTTP headers**: Metadata sent with every web request and response. When your
browser loads a page, the server sends back headers like "I'm running nginx"
or "this page should only be loaded over HTTPS." These reveal a lot about
a server's configuration and technology.

**Security headers**: Special HTTP headers that protect users:
- **HSTS** (Strict-Transport-Security): Forces HTTPS, prevents downgrade attacks
- **CSP** (Content-Security-Policy): Controls what scripts/resources can load,
  prevents XSS attacks
- **X-Content-Type-Options**: Prevents browsers from guessing file types (MIME sniffing)
- **X-Frame-Options**: Prevents your site from being embedded in an iframe
  (prevents clickjacking)
- **Referrer-Policy**: Controls what URL info is sent when clicking links
- **Permissions-Policy**: Controls which browser features (camera, mic, etc.)
  the page can use

**Fingerprinting**: Identifying what software a server runs by analyzing its
responses. Headers like `Server: nginx` or `X-Powered-By: PHP/8.1` reveal the
tech stack. This matters because specific versions have specific known vulnerabilities.

**WAF (Web Application Firewall)**: A security layer that sits in front of a
website and blocks suspicious requests. Cloudflare is a common one. If your
scanner hits a WAF, you'll get blocked — which is why we respect rate limits.

**Rate limiting**: Restricting how many requests you send per second. Sending too
many requests too fast is rude (it can slow down the service for real users),
can get you blocked, and might violate the program's rules.

---

## Vulnerability Types

**Vulnerability (vuln)**: A weakness in a system that could be exploited.
Not all weaknesses are exploitable, and not all exploitable ones are worth
reporting — severity and impact matter.

**CVE (Common Vulnerabilities and Exposures)**: A unique ID for a known
vulnerability. CVE-2021-44228 is "Log4Shell." When software has a known CVE,
anyone running that version is potentially vulnerable.

**CVSS (Common Vulnerability Scoring System)**: A 0-10 score rating how severe
a vulnerability is. 0-3.9 = Low, 4.0-6.9 = Medium, 7.0-8.9 = High, 9.0-10.0 = Critical.

**CWE (Common Weakness Enumeration)**: Categories of vulnerability types.
CWE-79 is "Cross-site Scripting (XSS)." Programs list which CWEs they accept.

**Subdomain takeover**: When a company's subdomain (like old-app.example.com)
points to an external service (like Heroku or S3) that the company no longer
controls. An attacker could claim that external resource and serve content on
the company's domain. This is often an easy, automatable finding.

**CORS misconfiguration**: CORS (Cross-Origin Resource Sharing) controls which
websites can make requests to your API. A misconfiguration might let any
website read data from your API, which could expose user information.

**Open redirect**: When a website has a URL parameter that redirects users
somewhere, and an attacker can make it redirect to a malicious site.
Example: `example.com/redirect?url=evil.com`

**IDOR (Insecure Direct Object Reference)**: When you can access someone else's
data by changing an ID in a URL. Example: changing `/api/user/123/profile`
to `/api/user/124/profile` and seeing another user's data.

**XSS (Cross-Site Scripting)**: Injecting malicious JavaScript into a website
that other users will see. Hard to automate safely.

**SQL Injection (SQLi)**: Inserting database commands into input fields.
Hard to automate safely — we don't do this.

---

## Infrastructure & Tools

**API (Application Programming Interface)**: A way for programs to talk to
each other. HackerOne's API lets our code list programs and submit reports
without using a web browser.

**REST API**: The most common API style. Uses URLs and HTTP methods (GET, POST)
to access resources. `GET /programs` = list programs. `POST /reports` = submit
a report.

**Basic auth**: A simple authentication method where you send your username and
password (or token) with every request. HackerOne uses this.

**SQLite**: A lightweight database stored in a single file. We use it to store
all our recon results locally. No server needed.

**Virtual environment (venv)**: An isolated Python installation for our project.
Keeps our dependencies separate from the rest of your system.

**CI/CD (Continuous Integration/Continuous Deployment)**: Automated testing and
deployment. GitHub Actions runs our tests every time we push code.

**Nuclei**: An open-source vulnerability scanner. It uses "templates" — small
files that describe how to detect specific vulnerabilities. Community-maintained,
with thousands of templates.

---

## Wintermute-Specific Terms

**Scope checker**: Our safety gate. Every target must pass through it before
any scanning happens. If the scope checker says no, the pipeline stops.
This is the most important safety component in the entire project.

**Hard gate**: A check that cannot be bypassed. Not a warning, not optional —
the code physically cannot proceed without passing the gate.

**Default deny**: If we're not sure whether something is in scope, we treat it
as out of scope. Better to miss a bounty than to test something we shouldn't.

**Recon pipeline**: Our automated chain: discover subdomains → validate with
DNS → filter through scope checker → fingerprint with HTTP headers → store
in database.

**Finding**: A potential vulnerability we've detected. Has a confidence score
(how sure we are it's real) and a severity rating (how bad it would be).

**Audit log**: A record of every scope check we perform. If anyone asks
"did you test X?", we have a timestamped log proving what was checked and
what the result was.

---

*Last updated: 2026-09-27*
