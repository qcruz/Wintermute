"""Report templates for each vulnerability type.

Each template takes a finding and produces a structured report with
title, summary, reproduction steps, impact, evidence, and remediation.

These templates aim to produce reports that are clear enough for a
triage analyst to verify in under 5 minutes.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Report:
    """A structured vulnerability report ready for submission."""

    title: str
    severity_rating: str  # none, low, medium, high, critical
    vulnerability_information: str  # main body (markdown)
    impact: str
    weakness_id: int | None = None  # CWE ID if applicable
    structured_scope_id: str | None = None

    def preview(self) -> str:
        """Human-readable preview of the report."""
        lines = [
            f"{'=' * 60}",
            f"TITLE: {self.title}",
            f"SEVERITY: {self.severity_rating.upper()}",
            f"{'=' * 60}",
            "",
            self.vulnerability_information,
            "",
            "## Impact",
            self.impact,
            f"{'=' * 60}",
        ]
        return "\n".join(lines)


# ── Template functions ───────────────────────────────────────────────
# Each function takes finding data and returns a Report.


def subdomain_takeover_report(
    hostname: str,
    cname: str,
    service: str,
    evidence: str,
) -> Report:
    """Generate a report for a subdomain takeover finding."""
    return Report(
        title=f"Subdomain takeover via dangling CNAME on {hostname}",
        severity_rating="high",
        vulnerability_information=f"""## Summary

`{hostname}` has a CNAME DNS record pointing to `{cname}` ({service}), which appears to be unclaimed. An attacker could register this resource on {service} and serve arbitrary content on `{hostname}`.

## Steps to Reproduce

1. Query the CNAME record for `{hostname}`:
   ```
   dig {hostname} CNAME
   ```
   **Result:** `{hostname}` → `{cname}`

2. Visit `https://{hostname}` in a browser.
   **Result:** {service} displays an error page indicating the resource is not claimed.

3. The {service} resource at `{cname}` is available for registration by anyone.

## Evidence

{evidence}

## Remediation

- **Option A:** Remove the CNAME DNS record for `{hostname}` if the subdomain is no longer needed.
- **Option B:** Reclaim the {service} resource at `{cname}` to prevent unauthorized takeover.

## References

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [OWASP: Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)""",
        impact=f"""An attacker who claims the {service} resource at `{cname}` would gain full control over content served on `{hostname}`. This could be used to:

- **Phishing:** Host convincing phishing pages on a trusted domain
- **Cookie theft:** Steal cookies scoped to the parent domain
- **Reputation damage:** Serve malicious or inappropriate content under the organization's domain
- **Man-in-the-middle:** Intercept traffic intended for the legitimate service""",
    )


def cors_misconfiguration_report(
    hostname: str,
    issue: str,
    details: dict,
) -> Report:
    """Generate a report for a CORS misconfiguration finding."""
    acao = details.get("access-control-allow-origin", "")
    acac = details.get("access-control-allow-credentials", "")

    severity = "high" if acac == "true" else "medium"

    return Report(
        title=f"CORS misconfiguration on {hostname} — {issue}",
        severity_rating=severity,
        vulnerability_information=f"""## Summary

`{hostname}` has a misconfigured CORS (Cross-Origin Resource Sharing) policy that {issue.lower()}. This allows unauthorized websites to make cross-origin requests and potentially read responses containing sensitive data.

## Steps to Reproduce

1. Send a request with an arbitrary Origin header:
   ```
   curl -s -D - -H "Origin: https://attacker.example.com" https://{hostname}/
   ```

2. Observe the response headers:
   ```
   Access-Control-Allow-Origin: {acao}
   Access-Control-Allow-Credentials: {acac}
   ```

3. The server reflects the attacker-controlled origin, meaning any website can read responses from this endpoint.

## Proof of Concept

An attacker could host the following JavaScript on their site to read data from `{hostname}`:

```javascript
// This is a proof-of-concept — do NOT use maliciously
fetch('https://{hostname}/', {{
  credentials: 'include'
}})
.then(response => response.text())
.then(data => console.log('Stolen data:', data));
```

## Remediation

- Do not reflect the `Origin` header back in `Access-Control-Allow-Origin`
- Maintain an explicit allowlist of trusted origins
- Never combine `Access-Control-Allow-Credentials: true` with a permissive origin policy

## References

- [CWE-942: Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
- [PortSwigger: Exploiting CORS Misconfigurations](https://portswigger.net/web-security/cors)""",
        impact=f"""A malicious website can make authenticated cross-origin requests to `{hostname}` and read the responses. If this endpoint returns sensitive data (user profiles, API keys, internal information), an attacker can steal it by luring a victim to their website.

The severity depends on what data is accessible through `{hostname}` — if it serves authenticated API responses, this is a high-severity issue.""",
    )


def exposed_file_report(
    hostname: str,
    path: str,
    description: str,
    evidence: str,
    severity: str,
) -> Report:
    """Generate a report for an exposed sensitive file."""
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "none",
    }

    return Report(
        title=f"Exposed {description} at {hostname}{path}",
        severity_rating=severity_map.get(severity, "medium"),
        vulnerability_information=f"""## Summary

The file at `https://{hostname}{path}` is publicly accessible and exposes {description.lower()}. This file should not be reachable from the public internet.

## Steps to Reproduce

1. Navigate to the following URL:
   ```
   https://{hostname}{path}
   ```

2. The server responds with HTTP 200 and returns the file contents.

## Evidence

{evidence}

## Remediation

- Configure the web server to deny access to `{path}` and similar sensitive paths
- For nginx: `location {path} {{ deny all; return 404; }}`
- For Apache: Use `.htaccess` to restrict access
- Review deployment processes to prevent sensitive files from being deployed to production
- If credentials were exposed, rotate them immediately

## References

- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File](https://cwe.mitre.org/data/definitions/538.html)""",
        impact=f"""The exposed file at `{path}` could reveal sensitive information including internal configuration, credentials, source code structure, or deployment details. An attacker could use this information to:

- Gain unauthorized access using leaked credentials
- Map internal infrastructure for further attacks
- Understand the application's technology stack to find additional vulnerabilities""",
    )


def missing_security_header_report(
    hostname: str,
    header: str,
    header_description: str,
    remediation: str,
) -> Report:
    """Generate a report for a missing security header."""
    return Report(
        title=f"Missing {header} header on {hostname}",
        severity_rating="low",
        vulnerability_information=f"""## Summary

`{hostname}` does not set the `{header}` HTTP response header. {header_description}

## Steps to Reproduce

1. Send a request to the server:
   ```
   curl -s -D - https://{hostname}/ | grep -i "{header}"
   ```

2. The header is not present in the response.

## Remediation

{remediation}

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)""",
        impact=f"""Without the `{header}` header, users of `{hostname}` have reduced protection against certain attack classes. While this is not directly exploitable on its own, it weakens the defense-in-depth posture and may facilitate other attacks.""",
    )


def ssl_tls_report(
    hostname: str,
    issue: str,
    tls_version: str,
    cert_info: str,
) -> Report:
    """Generate a report for an SSL/TLS issue."""
    if "expired" in issue.lower():
        severity = "medium"
    elif "deprecated" in issue.lower():
        severity = "low"
    else:
        severity = "low"

    return Report(
        title=f"SSL/TLS issue on {hostname}: {issue}",
        severity_rating=severity,
        vulnerability_information=f"""## Summary

`{hostname}` has an SSL/TLS configuration issue: {issue}.

## Steps to Reproduce

1. Test the SSL/TLS configuration:
   ```
   openssl s_client -connect {hostname}:443
   ```

2. Or use an online tool:
   ```
   https://www.ssllabs.com/ssltest/analyze.html?d={hostname}
   ```

## Technical Details

- TLS Version: {tls_version}
- Certificate: {cert_info}
- Issue: {issue}

## Remediation

- Ensure certificates are renewed before expiration
- Disable TLS 1.0 and TLS 1.1 — only allow TLS 1.2 and TLS 1.3
- Use certificates from a trusted Certificate Authority

## References

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)""",
        impact=f"""The SSL/TLS misconfiguration on `{hostname}` could allow an attacker to intercept or downgrade encrypted communications, depending on the specific issue. Users connecting to this service may have reduced confidentiality protections.""",
    )


# ── Template dispatcher ─────────────────────────────────────────────

TEMPLATE_MAP = {
    "subdomain_takeover": subdomain_takeover_report,
    "cors_misconfiguration": cors_misconfiguration_report,
    "exposed_file": exposed_file_report,
    "missing_security_header": missing_security_header_report,
    "ssl_tls": ssl_tls_report,
}
