# Wintermute — Reporting Engine Guide

How Wintermute turns raw vulnerability findings into professional reports
and submits them through HackerOne's API.

---

## Why Reports Matter

Finding a vulnerability is only half the job. If your report is unclear,
missing evidence, or poorly written, it will be rejected — even if the
bug is real. Triage teams review hundreds of reports. Yours needs to be:

- **Clear**: Anyone reading it should understand the issue in 30 seconds
- **Reproducible**: Step-by-step instructions to verify the bug
- **Impactful**: Explain WHY this matters, not just WHAT it is
- **Actionable**: Tell them how to fix it

---

## Report Structure

Every Wintermute report follows this template:

```
Title: [Vuln Type] on [hostname]

## Summary
One paragraph explaining what was found, where, and why it matters.

## Severity
[Critical/High/Medium/Low] — with CVSS score if applicable.

## Steps to Reproduce
1. Step one (with exact commands or URLs)
2. Step two
3. Step three

## Impact
What an attacker could do with this vulnerability.
Who is affected (users, admins, the company).

## Evidence
HTTP requests/responses, screenshots, DNS records — proof it's real.

## Remediation
Specific, actionable steps to fix the issue.

## References
Links to relevant CWEs, blog posts, or documentation.
```

---

## The Reporting Pipeline

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Finding  │───▶│ Dedup    │───▶│ Generate │───▶│ Review / │
│ from DB  │    │ Check    │    │ Report   │    │ Submit   │
└──────────┘    └────┬─────┘    └──────────┘    └──────────┘
                     │
              Already reported?
              Skip if likely dup
```

### Step 1: Load Findings
Pull findings from the database that have status "new" and confidence
above our threshold (default: 0.7 = 70%).

### Step 2: Duplicate Check
Before generating a report, we check:
- **Internal dedup**: Have we already submitted this exact finding?
- **Platform dedup**: Query our previous reports via the API
- **Heuristic**: Is this a common finding on a heavily-tested program?
  (e.g., missing headers on HackerOne's own program — certainly reported)

### Step 3: Generate Report
Using templates specific to each vulnerability type, we generate a
complete report with:
- Descriptive title
- Clear summary
- Reproduction steps with evidence
- Impact assessment
- Remediation advice

### Step 4: Review Queue
Findings are placed in a review queue:
- **Auto-submit**: High confidence (≥0.9) + high severity → can be
  auto-submitted (but we default to human review for safety)
- **Human review**: Everything else goes to a queue where you review
  the generated report before submission
- **Skip**: Low-value findings (info-level, known duplicates) are
  marked as skipped

### Step 5: Submit
When you approve a report, it's submitted via HackerOne's API with
proper formatting. The submission status is tracked in our database.

---

## Severity to CVSS Mapping

CVSS (Common Vulnerability Scoring System) is a standardized way to
rate how severe a vulnerability is. HackerOne uses these ratings:

| Rating | CVSS Range | Example |
|--------|-----------|---------|
| Critical | 9.0 - 10.0 | Remote code execution, exposed database with user data |
| High | 7.0 - 8.9 | Subdomain takeover, account takeover |
| Medium | 4.0 - 6.9 | CORS misconfiguration leaking data, missing HSTS |
| Low | 0.1 - 3.9 | Information disclosure, missing non-critical headers |
| None | 0.0 | Informational, best practice recommendations |

---

## What Makes a Good vs Bad Report

### Good Report
```
Title: Subdomain takeover via dangling CNAME on staging.example.com

Summary: staging.example.com has a CNAME record pointing to
staging-app.herokuapp.com, which is not claimed on Heroku. An attacker
can create a Heroku app with this name and serve arbitrary content on
staging.example.com, potentially stealing cookies scoped to *.example.com.

Steps to Reproduce:
1. Run: dig staging.example.com CNAME
   Result: staging.example.com CNAME staging-app.herokuapp.com
2. Visit https://staging.example.com
   Result: Heroku "No such app" page displayed
3. The Heroku app "staging-app" is unclaimed and can be registered

Impact: An attacker controlling this subdomain could:
- Host phishing pages on example.com's domain
- Steal session cookies if they're scoped to *.example.com
- Damage brand reputation

Remediation: Remove the CNAME record for staging.example.com
```

### Bad Report
```
Title: Bug found

I found a vulnerability on your website. The subdomain
staging.example.com seems to have some issue. Please fix it.
```

The first report gets triaged in minutes. The second gets closed as
"Needs more info" or "Not Applicable."

---

## Report Statuses (HackerOne)

After submission, your report goes through these stages:

| Status | Meaning | What happens next |
|--------|---------|------------------|
| New | Just submitted, waiting for triage | Wait |
| Triaged | Team confirmed it's valid | They're working on a fix |
| Duplicate | Someone reported this before you | No bounty, learn from it |
| Informative | Valid but not a security issue | No bounty |
| Not Applicable | Not a real vulnerability | No bounty, review your methodology |
| Resolved | Fixed! | Bounty may be awarded |

---

## Duplicate Avoidance Strategy

Duplicates are the biggest frustration in bug bounties. Our approach:

1. **Check our own history**: Never submit the same finding twice
2. **Assess competition**: Popular programs (HackerOne, Google, etc.)
   have been scanned by thousands of hunters. Common findings are
   almost certainly already reported.
3. **Prioritize novel findings**: Focus on recently added scope,
   newly discovered subdomains, or less-tested programs
4. **When in doubt, submit**: A duplicate report costs you nothing
   (except time). A valid unreported vulnerability costs the company.

---

*Last updated: 2026-09-27*
