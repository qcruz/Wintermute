# Wintermute — Report Submission Guide

When to submit, when to hold back, and what happens if you get it wrong.

---

## The Decision: Should I Submit This?

Not every finding deserves a report. Submitting weak or duplicate reports wastes everyone's time and can hurt your reputation. Use this framework:

### Submit If (All Must Be True)

1. **Real vulnerability** — You can prove it exists, not just suspect it
2. **In scope** — The asset is explicitly listed in the program's scope
3. **Security impact** — An attacker could actually harm users or the company
4. **Not a duplicate** — You've checked the dedup system and it passed
5. **Clear reproduction** — Someone else could verify it from your report alone

### Do NOT Submit If (Any of These)

- **Informational only** — "I noticed you're running nginx 1.25" with no exploit path
- **Best practice gap** — Missing headers without demonstrated impact (most programs reject these)
- **Out of scope** — Even slightly. Programs are strict about this
- **Theoretical only** — "This *could* be vulnerable if..." without proof
- **Scanner noise** — Automated tool output pasted without verification
- **Already public knowledge** — Known CVE that's already patched or acknowledged

---

## Severity Calibration

Getting severity right is critical. Over-rating makes you look inexperienced. Under-rating means a smaller bounty. Be honest.

| Rating | When to use | Examples |
|--------|-------------|---------|
| **Critical** | Immediate, direct impact on data or systems. No user interaction needed. | RCE, SQL injection with data access, exposed database, leaked production credentials |
| **High** | Significant impact, may require minimal user interaction | Subdomain takeover, stored XSS, IDOR exposing user data, SSRF to internal services |
| **Medium** | Real security issue but limited impact or requires specific conditions | Reflected XSS, CORS with credential reflection, CSRF on sensitive actions, expiring SSL on auth endpoints |
| **Low** | Minor issue, defense-in-depth concern, hard to exploit | Missing security headers, version disclosure, clickjacking on non-sensitive pages, information leakage |
| **None** | Best practice suggestion, no security impact | Missing `X-Content-Type-Options`, informational findings |

### Common Mistakes

- **CORS without credentials is usually Medium, not High** — Without `Access-Control-Allow-Credentials: true`, the attacker can't steal authenticated data
- **Missing headers are usually Low or None** — Unless you can show a specific attack path (e.g., missing CSP enables a working XSS chain)
- **SSL cert issues are usually Low** — Expiring certs and hostname mismatches are operational issues, not security bugs, unless on login/payment pages
- **Subdomain takeover is High** — But only if you can actually claim the resource. A dangling CNAME with no proof of claimability is Medium at best

---

## The Submission Process

### Step 1: Review in Wintermute

```bash
python -m scripts.run_reports <handle>
```

This shows each finding with its generated report. For each:
- **Preview** the full report text
- **Evaluate** using the criteria above
- **Submit** (s), **Skip** (n), or **Quit** (q)

### Step 2: What Happens After Submission

```
You submit → HackerOne team receives it → Triage analyst reviews
                                                    │
                    ┌───────────────────────────────┤
                    │               │               │
                 Triaged      Duplicate      Not Applicable
                    │               │               │
              Team fixes      No bounty      No bounty
                    │          Learn from it   Review your method
                 Resolved
                    │
              Bounty paid
```

Typical timeline:
- **Triage**: 1-7 days for responsive programs, weeks for slower ones
- **Resolution**: Weeks to months depending on the fix
- **Bounty**: Usually paid at resolution, sometimes at triage

### Step 3: Track Outcomes

After submitting, monitor on HackerOne:
- Was it triaged? → Great, the system works
- Was it a duplicate? → Note what was already known, refine dedup
- Was it "Not Applicable"? → Understand why, adjust scan criteria
- Was it "Informative"? → Valid finding but not considered a security issue by this program

---

## Risks of Oversubmitting

This is the most important section. There are real consequences to submitting too many weak reports.

### Reputation Damage

HackerOne tracks your **Signal** and **Impact** scores:

- **Signal** = (Triaged + Resolved reports) / Total reports
  - If you submit 10 reports and 8 are duplicates or N/A, your Signal drops
  - Low Signal = programs may ignore your future reports or ban you
- **Impact** = Weighted score based on severity of resolved reports
  - High-severity accepted reports boost this
  - Volume of rejected reports drags it down

**A researcher with 5 reports (4 accepted) looks far better than one with 50 reports (5 accepted).**

### Program Bans

Some programs will:
- **Restrict you** from submitting if your signal is too low
- **Ban you** from their program if you repeatedly submit noise
- **Report you** to HackerOne for abuse if submissions are automated spam

### Triage Team Burnout

Programs have real humans reading reports. If you flood them with:
- Missing header reports they've seen 100 times
- Scanner output without verification
- Low-confidence findings marked as Critical

...they'll start ignoring your reports entirely, even the good ones.

### The Duplicate Tax

Every duplicate costs you:
- **Time** writing the report
- **Signal score** points
- **Credibility** with that program's triage team

Duplicates are inevitable (you can't know what others have reported), but you can minimize them by:
- Focusing on **newly added scope** (less competition)
- Targeting **unique bug classes** (not just missing headers)
- Using the **dedup heuristic** (our system flags likely dupes)

---

## Wintermute's Decision Framework

The pipeline applies these filters automatically:

```
Finding
  │
  ├── Confidence < 0.7? → Skip (too uncertain)
  │
  ├── Severity = info/low? → Skip (not reportable on most programs)
  │
  ├── Internal dedup match? → Skip (we already reported this)
  │
  ├── Platform dedup match? → Skip (we submitted this before)
  │
  ├── Heuristic says 80%+ duplicate? → Flag as LIKELY DUP
  │   (still shown for review, but marked with warning)
  │
  └── Passes all checks → REPORT CANDIDATE
      (human reviews before submit)
```

### When to Override the System

**Submit despite "LIKELY DUP" warning if:**
- The finding is on a newly added asset (just came into scope)
- You have unusually strong evidence (e.g., actual data exposed)
- The program is small/new with few researchers

**Skip despite "REPORT CANDIDATE" if:**
- The program explicitly says they don't want this type of report
- The impact is purely theoretical
- You can't write clear reproduction steps
- Your gut says "this is noise" — trust that instinct

---

## Quality Checklist Before Submitting

Before approving any report in the review queue, mentally check:

- [ ] Can I explain this vulnerability in one sentence?
- [ ] Could a triage analyst verify this in under 5 minutes?
- [ ] Is the severity rating honest (not inflated)?
- [ ] Does the impact section describe real-world harm?
- [ ] Are the reproduction steps specific and complete?
- [ ] Have I checked the program's policy for exclusions?
- [ ] Am I confident this isn't a false positive?
- [ ] Would I be comfortable defending this report if questioned?

If you can't check all of these, don't submit. Hold it, investigate more, or mark it as skipped.

---

## Learning from Outcomes

Every response from HackerOne is data:

| Outcome | Lesson |
|---------|--------|
| **Triaged** | The finding type and severity were calibrated correctly. Note what worked. |
| **Duplicate** | Someone beat us. Focus on less-tested programs or more unique bug classes. |
| **Informative** | Real but not a security issue to this program. Check their policy more carefully. |
| **Not Applicable** | Our detection was wrong or the impact assessment was off. Review the scanner logic. |
| **Needs More Info** | Report quality needs work. Add more evidence and clearer steps. |

Track these in the database and feed them back into the scanning priorities. Over time, this feedback loop will sharpen what we look for and where.

---

*Last updated: 2026-09-27*
