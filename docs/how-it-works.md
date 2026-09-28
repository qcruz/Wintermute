# Wintermute — How It Works

A step-by-step explanation of what Wintermute does and why, written for
someone with no security background.

---

## The Big Picture

Wintermute is a pipeline — a series of automated steps that flow into each other:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  1. Discover │───▶│  2. Map the  │───▶│  3. Check    │───▶│  4. Report   │
│   Programs   │    │   Surface    │    │   for Vulns  │    │   Findings   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
   HackerOne          Subdomains          Known CVEs           Generate
   API fetch          DNS lookups         Misconfigs           Submit
                      Headers             Takeovers            Track
```

Every step has a SCOPE CHECK gate between it and the next. Nothing gets
scanned without authorization.

---

## Step 1: Discover Programs

**What happens:** We ask HackerOne "what bug bounty programs exist?"

**How:** We call the HackerOne API (`GET /hackers/programs`) with our API
credentials. The API returns a list of companies that want hackers to test
their systems.

**What we get back:** For each program:
- Name and handle (e.g., "HackerOne" / "security")
- Whether it's open for submissions
- Response time metrics (how fast they triage reports)
- Bounty ranges (how much they pay)

**Code:** `src/platforms/hackerone.py` → `list_programs()`

**Why it matters:** Not all programs are equal. Some pay well and respond
fast. Others take months and reject everything. We use this info to
prioritize where to focus.

---

## Step 2: Understand the Scope

**What happens:** For each program, we fetch the detailed rules of what
we're allowed to test.

**How:** We call `GET /hackers/programs/{handle}/structured_scopes` which
returns a structured list of assets.

**What we get back:**
```
In-scope:
  *.example.com          (URL, bounty eligible)
  api.example.com        (URL, bounty eligible)
  10.0.0.0/24           (CIDR range, bounty eligible)

Out-of-scope:
  support.example.com    (URL, do not test)
  staging.example.com    (URL, do not test)
```

**Code:** `src/platforms/hackerone.py` → `get_structured_scopes()` and `parse_scope()`

**The Scope Checker:** This is Wintermute's most critical component
(`src/core/scope.py`). Before ANY interaction with a target, the scope
checker validates it:

1. Is it explicitly excluded? → DENIED
2. Does it match an in-scope entry? → ALLOWED
3. Neither? → DENIED (default deny)

The scope checker handles:
- Exact matches: `api.example.com` matches `api.example.com`
- Wildcards: `sub.example.com` matches `*.example.com`
- Subdomains: `api.example.com` matches domain entry `example.com`
- IP ranges: `10.0.0.50` matches CIDR `10.0.0.0/24`
- Exclusion priority: `support.example.com` is denied even though
  `*.example.com` is in scope

Every check is logged with a timestamp for accountability.

---

## Step 3: Map the Attack Surface (Recon)

**What happens:** We discover as many hosts and services as possible
within the allowed scope.

### 3a. Subdomain Enumeration

**Goal:** Find all subdomains of in-scope domains.

**How:** We query Certificate Transparency (CT) logs via crt.sh.

**Why CT logs work:** When a company gets an SSL certificate for
`secret-staging.example.com`, that name is recorded in a public log.
Even if they later delete the subdomain, the record persists. This is
completely passive — we never contact the target.

**Example:** Querying CT logs for `hackerone.com` revealed:
- `api.hackerone.com`
- `docs.hackerone.com`
- `gslink.hackerone.com`
- `websockets.hackerone.com`
- ... and many more

**Code:** `src/recon/subdomain.py` → `enumerate_subdomains()`

### 3b. DNS Validation

**Goal:** Check which discovered subdomains are actually alive.

**How:** For each subdomain, we do a DNS lookup (A and AAAA records).
If it resolves to an IP address, it's alive. If not, the subdomain
exists in records but no server is listening.

**Why it matters:** Dead subdomains that still have DNS records pointing
to third-party services (like Heroku, AWS, GitHub Pages) might be
vulnerable to subdomain takeover.

**Code:** `src/recon/subdomain.py` → `_resolve_hostname()`

### 3c. Scope Filtering

**Goal:** Remove any discovered hosts that are out of scope.

**Example from our HackerOne test run:**
- 37 subdomains discovered
- 26 resolved (alive)
- `support.hackerone.com` was filtered out (explicitly out-of-scope)
- 25 passed the scope check

### 3d. HTTP Header Fingerprinting

**Goal:** Learn what software each server runs and how it's configured.

**How:** We send a single GET request to each alive target and analyze
the response headers.

**What we learn:**
- **Technology stack**: "This server runs nginx behind Cloudflare, with
  a Drupal CMS"
- **Security posture**: "This server is missing HSTS, CSP, and
  X-Frame-Options headers" (potential findings)
- **Infrastructure**: "This is hosted on AWS S3 behind CloudFront"

**Code:** `src/recon/headers.py` → `analyze_headers()`

### 3e. Storage

**Goal:** Save everything for analysis and tracking over time.

**How:** All results go into a local SQLite database (`wintermute.db`).
The database tracks:
- Programs and their scopes
- Discovered targets with IPs and sources
- Services running on each target
- Findings (vulnerabilities) with confidence and severity

**Why track over time:** If we scan a program today and again next week,
we can detect changes — new subdomains added, old ones removed, services
changed. Changes often mean new attack surface.

**Code:** `src/core/db.py`

---

## Step 4: Check for Vulnerabilities (Phase 3 — Current)

**What happens:** We run specific checks against each discovered target
looking for known security issues.

This is what we're building now. See `docs/vulnerability-detection.md`
for details on each check type.

---

## Step 5: Report Findings (Phase 4 — Future)

**What will happen:** For validated vulnerabilities, we generate
professional reports and submit them through HackerOne's API.

---

## Safety at Every Step

```
                     ┌─────────────┐
 Discover targets ──▶│ SCOPE CHECK │──▶ Scan? Only if ALLOWED
                     └─────┬───────┘
                           │
                    ┌──────▼──────┐
                    │ RATE LIMIT  │──▶ Max 5 req/sec
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ AUDIT LOG   │──▶ Everything recorded
                    └─────────────┘
```

- **Scope check**: Hard gate, cannot be bypassed
- **Rate limiting**: Respect target servers, avoid detection/blocking
- **Audit logging**: Every action timestamped for accountability
- **Passive first**: CT logs and DNS are public data — no target contact
- **Minimal interaction**: One GET request for headers, not aggressive scanning
- **Default deny**: When in doubt, don't scan

---

*Last updated: 2026-09-27*
