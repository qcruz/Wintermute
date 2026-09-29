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


def content_discovery_report(
    hostname: str,
    path: str,
    description: str,
    category: str,
    evidence: str,
    severity: str,
) -> Report:
    """Generate a report for a discovered endpoint."""
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

Active content discovery found `{description}` publicly accessible at `https://{hostname}{path}`. This endpoint (category: {category}) should typically not be exposed to the public internet.

## Steps to Reproduce

1. Navigate to:
   ```
   https://{hostname}{path}
   ```

2. The endpoint responds with content confirming its presence.

## Evidence

{evidence}

## Remediation

- Restrict access to `{path}` using authentication or IP allowlisting
- Remove development, debug, and documentation endpoints from production
- Use a web application firewall (WAF) to block access to sensitive paths
- Review deployment configuration to prevent accidental exposure

## References

- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP: Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)""",
        impact=f"""The exposed endpoint at `{path}` may reveal sensitive information about the application's internal structure, API surface, or configuration. Depending on the endpoint type ({category}), this could enable:

- **API abuse:** Discovering undocumented API endpoints for unauthorized access
- **Information gathering:** Learning internal architecture to plan further attacks
- **Direct exploitation:** Accessing debug or admin interfaces without authentication""",
    )


def injection_report(
    hostname: str,
    vuln_type: str,
    parameter: str,
    description: str,
    evidence: str,
    payload: str,
) -> Report:
    """Generate a report for an injection vulnerability."""
    type_info = {
        "xss": {
            "title": f"Reflected Cross-Site Scripting (XSS) via '{parameter}' parameter on {hostname}",
            "severity": "high",
            "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
            "cwe_url": "https://cwe.mitre.org/data/definitions/79.html",
            "impact": (
                "An attacker can execute arbitrary JavaScript in the context of a victim's browser session. "
                "This enables session hijacking, credential theft, defacement, and phishing attacks "
                "that appear to originate from the trusted domain."
            ),
        },
        "sqli": {
            "title": f"SQL Injection via '{parameter}' parameter on {hostname}",
            "severity": "critical",
            "cwe": "CWE-89: SQL Injection",
            "cwe_url": "https://cwe.mitre.org/data/definitions/89.html",
            "impact": (
                "An attacker can manipulate database queries to extract, modify, or delete data. "
                "In severe cases, this can lead to full database compromise, authentication bypass, "
                "or remote code execution on the database server."
            ),
        },
        "open_redirect": {
            "title": f"Open Redirect via '{parameter}' parameter on {hostname}",
            "severity": "medium",
            "cwe": "CWE-601: URL Redirection to Untrusted Site",
            "cwe_url": "https://cwe.mitre.org/data/definitions/601.html",
            "impact": (
                "An attacker can craft URLs that redirect users to malicious websites while appearing "
                "to link to the trusted domain. This facilitates phishing attacks and credential theft."
            ),
        },
        "ssti": {
            "title": f"Server-Side Template Injection via '{parameter}' parameter on {hostname}",
            "severity": "critical",
            "cwe": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
            "cwe_url": "https://cwe.mitre.org/data/definitions/1336.html",
            "impact": (
                "An attacker can inject template directives that are executed server-side, potentially "
                "leading to remote code execution, file system access, and full server compromise."
            ),
        },
    }

    info = type_info.get(vuln_type, type_info["xss"])

    return Report(
        title=info["title"],
        severity_rating=info["severity"],
        vulnerability_information=f"""## Summary

{description}

## Steps to Reproduce

1. Send the following request:
   ```
   curl -s "https://{hostname}/?{parameter}={payload}"
   ```

2. Observe the response for evidence of the vulnerability.

## Evidence

{evidence}

## Remediation

- Validate and sanitize all user-supplied input
- Use parameterized queries for database operations
- Encode output according to context (HTML, JavaScript, URL)
- Implement Content-Security-Policy headers

## References

- [{info['cwe']}]({info['cwe_url']})
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)""",
        impact=info["impact"],
    )


def auth_finding_report(
    hostname: str,
    vuln_type: str,
    title: str,
    description: str,
    evidence: str,
) -> Report:
    """Generate a report for an auth-related finding."""
    severity_map = {
        "insecure_cookie": "medium",
        "missing_auth": "high",
        "jwt_issue": "high",
        "session_issue": "medium",
    }

    cwe_map = {
        "insecure_cookie": ("CWE-614", "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
        "missing_auth": ("CWE-306", "Missing Authentication for Critical Function"),
        "jwt_issue": ("CWE-347", "Improper Verification of Cryptographic Signature"),
        "session_issue": ("CWE-352", "Cross-Site Request Forgery"),
    }

    cwe_id, cwe_name = cwe_map.get(vuln_type, ("CWE-287", "Improper Authentication"))

    return Report(
        title=title,
        severity_rating=severity_map.get(vuln_type, "medium"),
        vulnerability_information=f"""## Summary

{description}

## Evidence

{evidence}

## Remediation

- Implement proper authentication and session management
- Set Secure, HttpOnly, and SameSite flags on all session cookies
- Use CSRF tokens on all state-changing forms
- Validate JWT tokens with strong algorithms (RS256/ES256)

## References

- [{cwe_id}: {cwe_name}](https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)""",
        impact=f"""Authentication and session management vulnerabilities can allow attackers to impersonate legitimate users, access protected data, or perform unauthorized actions. The specific impact depends on the application's functionality and the data it handles.""",
    )


def business_logic_report(
    hostname: str,
    vuln_type: str,
    title: str,
    description: str,
    evidence: str,
) -> Report:
    """Generate a report for a business logic finding."""
    severity_map = {
        "info_disclosure": "low",
        "error_leak": "medium",
        "method_allowed": "low",
        "clickjack": "medium",
        "cache_issue": "low",
    }

    return Report(
        title=title,
        severity_rating=severity_map.get(vuln_type, "low"),
        vulnerability_information=f"""## Summary

{description}

## Evidence

{evidence}

## Remediation

- Remove version information from response headers
- Configure custom error pages without stack traces
- Disable unnecessary HTTP methods
- Set proper security headers (X-Frame-Options, Cache-Control)

## References

- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/)""",
        impact=f"""Information disclosure and business logic issues can provide attackers with intelligence to plan more targeted attacks. While not directly exploitable in most cases, these findings weaken the overall security posture and may enable escalation to higher-severity vulnerabilities.""",
    )


def idor_report(finding) -> Report:
    """Generate a report for an IDOR finding."""
    return Report(
        title=finding.title,
        severity_rating=finding.severity,
        weakness_id=639,  # CWE-639: Authorization Bypass Through User-Controlled Key
        vulnerability_information=f"""## Summary

An Insecure Direct Object Reference (IDOR) vulnerability was identified on `{finding.hostname}`.

## Description

{finding.description}

## Steps to Reproduce

1. Navigate to: `https://{finding.hostname}{finding.evidence.split(chr(10))[0].replace('Endpoint: ', '')}`
2. Observe that the endpoint returns data without requiring authentication
3. Change the ID parameter to a different value (e.g., increment by 1)
4. Observe that different data objects are returned for different IDs

## Evidence

```
{finding.evidence}
```

## Remediation

- Implement server-side authorization checks on every API endpoint
- Verify the authenticated user has permission to access the requested object
- Return 401/403 for unauthenticated requests to sensitive endpoints
- Use UUIDs instead of sequential integers for object identifiers (defense in depth)
- Implement rate limiting on API endpoints to slow enumeration attempts

## References

- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)""",
        impact=f"""An attacker can enumerate object IDs to access data belonging to other users without authentication. Depending on the data exposed, this could lead to mass data theft, privacy violations, or account compromise. IDOR is consistently ranked in the OWASP Top 10 under Broken Access Control (A01:2021).""",
    )


def path_traversal_report(finding) -> Report:
    """Generate a report for a path traversal / LFI finding."""
    return Report(
        title=finding.title,
        severity_rating=finding.severity,
        weakness_id=22,  # CWE-22: Improper Limitation of a Pathname to a Restricted Directory
        vulnerability_information=f"""## Summary

A path traversal (Local File Inclusion) vulnerability was identified on `{finding.hostname}`.

## Description

{finding.description}

## Steps to Reproduce

1. Send the following request:
   ```
   curl -s "{finding.evidence.split(chr(10))[0].replace('Parameter: ', '')}"
   ```

2. Observe that the response contains contents of a system file that should not be accessible.

## Evidence

```
{finding.evidence}
```

## Remediation

- Never construct file paths from user input directly
- Use an allowlist of permitted file names or identifiers
- Resolve paths with `realpath()` and verify they remain within the intended directory
- Strip or reject traversal sequences (`../`, `..\\\\`, URL-encoded variants)
- Run the application with minimal filesystem permissions

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Testing for Path Traversal](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)""",
        impact=f"""An attacker can read arbitrary files from the server filesystem by manipulating file path parameters. This can expose sensitive configuration files, source code, credentials, and system information. In severe cases, path traversal can be chained with other vulnerabilities for remote code execution.""",
    )


def graphql_introspection_report(finding) -> Report:
    """Generate a report for a GraphQL introspection finding."""
    return Report(
        title=finding.title,
        severity_rating=finding.severity,
        weakness_id=200,  # CWE-200: Exposure of Sensitive Information
        vulnerability_information=f"""## Summary

GraphQL introspection is enabled in production on `{finding.hostname}`, exposing the complete API schema to unauthenticated users.

## Description

{finding.description}

## Steps to Reproduce

1. Send a POST request to the GraphQL endpoint:
   ```
   curl -s -X POST https://{finding.hostname}/graphql \\
     -H "Content-Type: application/json" \\
     -d '{{"query": "{{ __schema {{ queryType {{ name }} mutationType {{ name }} types {{ name kind fields {{ name }} }} }} }}"}}'
   ```

2. Observe that the full schema is returned, including all types, queries, and mutations.

## Evidence

```
{finding.evidence}
```

## Remediation

- Disable introspection in production (most GraphQL frameworks support this)
- Implement authentication on the GraphQL endpoint
- Add authorization checks to all queries and mutations
- Consider query depth and complexity limits
- Use a schema allowlist (persisted queries) in production

## References

- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Introspection Security](https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/)""",
        impact=f"""Exposing the full GraphQL schema gives attackers a complete map of the API, including internal types, admin mutations, and sensitive data queries. This information accelerates attack planning and can reveal operations that were not intended to be publicly known. If sensitive mutations lack proper authorization, this finding enables direct exploitation.""",
    )


def js_secret_report(finding) -> Report:
    """Generate a report for a JavaScript secret exposure finding."""
    return Report(
        title=finding.title,
        severity_rating=finding.severity,
        weakness_id=798,  # CWE-798: Use of Hard-coded Credentials
        vulnerability_information=f"""## Summary

A hardcoded secret was found in a publicly accessible JavaScript file on `{finding.hostname}`.

## Description

{finding.description}

## Steps to Reproduce

1. Visit `{finding.hostname}` in a browser
2. Open Developer Tools → Sources tab
3. Locate the JavaScript file containing the secret
4. Search for the exposed credential

## Evidence

```
{finding.evidence}
```

## Remediation

- Remove all hardcoded secrets from client-side JavaScript
- Use environment variables or a secrets management service
- Rotate the exposed credential immediately — it should be considered compromised
- Add secret scanning to your CI/CD pipeline (e.g., git-secrets, trufflehog)
- Review git history for previously committed secrets

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)""",
        impact=f"""Exposed secrets in JavaScript files are accessible to any visitor. Depending on the type of secret, an attacker could gain unauthorized access to cloud infrastructure, payment systems, email services, or internal APIs. Hardcoded credentials are a critical security risk because they cannot be rotated without deploying new code.""",
    )


def mcp_security_report(finding) -> Report:
    """Generate a report for an MCP security finding."""
    severity_map = {
        "mcp_auth_bypass": "high",
        "mcp_dangerous_tools": "high",
        "mcp_tool_poisoning": "critical",
        "mcp_path_traversal": "critical",
        "mcp_exposed": "low",
    }

    cwe_map = {
        "mcp_auth_bypass": (306, "CWE-306: Missing Authentication for Critical Function", "Unauthenticated access to MCP tool listings allows attackers to discover all available tools and their capabilities, enabling targeted attacks against the AI agent's tool-use interface. Combined with prompt injection, an attacker could invoke arbitrary tools."),
        "mcp_dangerous_tools": (250, "CWE-250: Execution with Unnecessary Privileges", "MCP servers exposing dangerous tools (file system access, command execution, database queries) without proper access controls allow AI agents — and by extension, prompt injection attackers — to perform privileged operations on the server."),
        "mcp_tool_poisoning": (94, "CWE-94: Improper Control of Generation of Code", "Tool poisoning is the highest-leverage attack on AI agent systems. Malicious instructions hidden in tool descriptions override agent behavior, causing the agent to perform attacker-controlled actions whenever it reads the tool schema."),
        "mcp_path_traversal": (22, "CWE-22: Improper Limitation of a Pathname to a Restricted Directory", "Path traversal in MCP file tools allows reading arbitrary files from the server filesystem through the AI agent interface, exposing credentials, configuration, and source code."),
        "mcp_exposed": (200, "CWE-200: Exposure of Sensitive Information", "Exposed MCP endpoints reveal the AI agent's tool-use infrastructure."),
    }

    cwe_id, cwe_name, impact = cwe_map.get(
        finding.vuln_type,
        (306, "CWE-306: Missing Authentication", "MCP security vulnerability detected."),
    )

    return Report(
        title=finding.title,
        severity_rating=severity_map.get(finding.vuln_type, "medium"),
        weakness_id=cwe_id,
        vulnerability_information=f"""## Summary

{finding.description}

## Steps to Reproduce

{finding.evidence}

## Remediation

- Implement OAuth 2.0 or mutual TLS authentication on MCP endpoints
- Apply least-privilege to tool capabilities (restrict file paths, commands)
- Validate all tool input parameters server-side
- Audit tool descriptions for hidden instructions (tool poisoning)
- Follow NSA/CISA MCP Security Design Guidance (June 2026)
- Monitor for unauthorized tool invocations

## References

- [{cwe_name}](https://cwe.mitre.org/data/definitions/{cwe_id}.html)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NSA/CISA MCP Security Guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/)""",
        impact=impact,
    )


def prompt_injection_report(finding) -> Report:
    """Generate a report for an AI prompt injection finding."""
    severity_map = {
        "prompt_injection": "high",
        "system_prompt_leak": "medium",
        "ai_endpoint_exposed": "low",
    }

    cwe_map = {
        "prompt_injection": (77, "CWE-77: Command Injection", "Prompt injection allows attackers to override AI system instructions, potentially causing the AI to perform unauthorized actions, leak sensitive data, or bypass safety controls. This is analogous to command injection but targets the AI's instruction-following mechanism rather than a shell."),
        "system_prompt_leak": (200, "CWE-200: Exposure of Sensitive Information", "System prompt leakage reveals the AI's configuration, instructions, and operational boundaries. Attackers can use this information to craft more targeted prompt injection attacks, understand safety controls to bypass them, or extract proprietary business logic embedded in prompts."),
        "ai_endpoint_exposed": (200, "CWE-200: Exposure of Sensitive Information", "Exposed AI endpoints without proper authentication allow unauthorized access to AI capabilities, which may include access to internal data, tool-use permissions, or privileged operations."),
    }

    cwe_id, cwe_name, impact = cwe_map.get(
        finding.vuln_type,
        (77, "CWE-77: Command Injection", "AI security vulnerability detected."),
    )

    return Report(
        title=finding.title,
        severity_rating=severity_map.get(finding.vuln_type, "medium"),
        weakness_id=cwe_id,
        vulnerability_information=f"""## Summary

{finding.description}

## Steps to Reproduce

{finding.evidence}

## Remediation

- Implement input sanitization and prompt injection detection
- Use system prompt hardening (clear delimiters, instruction hierarchy)
- Add output validation to prevent sensitive data leakage
- Require authentication on all AI endpoints
- Implement rate limiting and abuse detection
- Follow OWASP Top 10 for LLM Applications guidelines

## References

- [{cwe_name}](https://cwe.mitre.org/data/definitions/{cwe_id}.html)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)""",
        impact=impact,
    )


# ── Template dispatcher ─────────────────────────────────────────────

TEMPLATE_MAP = {
    "subdomain_takeover": subdomain_takeover_report,
    "cors_misconfiguration": cors_misconfiguration_report,
    "exposed_file": exposed_file_report,
    "missing_security_header": missing_security_header_report,
    "ssl_tls": ssl_tls_report,
    "content_discovery": content_discovery_report,
    "xss": injection_report,
    "sqli": injection_report,
    "open_redirect": injection_report,
    "ssti": injection_report,
    "insecure_cookie": auth_finding_report,
    "missing_auth": auth_finding_report,
    "jwt_issue": auth_finding_report,
    "session_issue": auth_finding_report,
    "info_disclosure": business_logic_report,
    "error_leak": business_logic_report,
    "method_allowed": business_logic_report,
    "clickjack": business_logic_report,
    "cache_issue": business_logic_report,
    "idor": idor_report,
    "path_traversal": path_traversal_report,
    "graphql_introspection": graphql_introspection_report,
    "js_secret": js_secret_report,
    "prompt_injection": prompt_injection_report,
    "system_prompt_leak": prompt_injection_report,
    "ai_endpoint_exposed": prompt_injection_report,
    "mcp_auth_bypass": mcp_security_report,
    "mcp_dangerous_tools": mcp_security_report,
    "mcp_tool_poisoning": mcp_security_report,
    "mcp_path_traversal": mcp_security_report,
    "mcp_exposed": mcp_security_report,
}
