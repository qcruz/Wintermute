"""Business logic and information disclosure analysis.

Checks for misconfigurations and information leaks that don't fit neatly
into other vulnerability categories but are still valuable findings.

What we check:
  - Verbose error messages / stack traces
  - Version disclosure in headers and responses
  - HTTP method testing (PUT, DELETE, PATCH allowed unexpectedly)
  - Information disclosure in error responses
  - Cache control issues on sensitive pages
  - HTTP to HTTPS redirect missing
  - Clickjacking protection (X-Frame-Options)

Safety:
  - Uses GET, HEAD, and OPTIONS only (no state-changing methods sent)
  - No data modification attempted
  - Analyzes only publicly visible information
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class BusinessFinding:
    """A business logic or information disclosure finding."""

    hostname: str
    vuln_type: str  # info_disclosure, method_allowed, cache_issue, error_leak, clickjack
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str


@dataclass
class BusinessResult:
    """Results of business logic analysis for a hostname."""

    hostname: str
    findings: list[BusinessFinding] = field(default_factory=list)


# Patterns that indicate verbose error messages or stack traces
ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace", "high"),
    (r"at [\w.$]+\([\w.]+:\d+\)", "Java stack trace", "high"),
    (r"Exception in thread", "Java exception", "high"),
    (r"System\.(\w+\.)+\w+Exception", ".NET exception", "high"),
    (r"Stack Trace:.*?at ", ".NET stack trace", "high"),
    (r"Fatal error:.*?in /\w+", "PHP fatal error with path", "high"),
    (r"Warning:.*?in /\w+/\w+\.php on line \d+", "PHP warning with path", "medium"),
    (r"Parse error:.*?in /\w+", "PHP parse error with path", "high"),
    (r"node_modules/", "Node.js stack trace", "medium"),
    (r"TypeError:.*?\n\s+at ", "JavaScript error", "medium"),
    (r"SQLSTATE\[", "Database error", "high"),
    (r"mysql_connect\(\)", "MySQL connection error", "high"),
    (r"pg_connect\(\)", "PostgreSQL connection error", "high"),
    (r"DEBUG\s*=\s*True", "Django debug mode enabled", "high"),
    (r"<div id=\"traceback\"", "Django debug page", "critical"),
]

# Headers that disclose server/technology versions
VERSION_HEADERS = [
    ("server", "Server version"),
    ("x-powered-by", "Technology stack"),
    ("x-aspnet-version", "ASP.NET version"),
    ("x-aspnetmvc-version", "ASP.NET MVC version"),
    ("x-generator", "Site generator"),
    ("x-drupal-cache", "Drupal cache"),
    ("x-varnish", "Varnish cache"),
    ("x-debug-token", "Debug token (Symfony)"),
    ("x-debug-token-link", "Debug link (Symfony)"),
]


def analyze_business_logic(hostname: str) -> BusinessResult:
    """Run business logic and information disclosure checks.

    Safe: uses GET, HEAD, and OPTIONS only.
    """
    result = BusinessResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # Step 1: Version disclosure in headers
    _check_version_disclosure(base_url, result)

    # Step 2: Error page information leakage
    _check_error_disclosure(base_url, result)

    # Step 3: HTTP methods allowed (via OPTIONS)
    _check_http_methods(base_url, result)

    # Step 4: Missing HTTP → HTTPS redirect
    _check_https_redirect(hostname, result)

    # Step 5: Clickjacking protection
    _check_clickjacking(base_url, result)

    # Step 6: Cache control on sensitive pages
    _check_cache_headers(base_url, result)

    # Step 7: TRACE method (XST)
    _check_trace_method(base_url, result)

    if result.findings:
        logger.info(
            "Business logic analysis on %s: %d findings",
            hostname, len(result.findings),
        )

    return result


def _check_version_disclosure(base_url: str, result: BusinessResult) -> None:
    """Check response headers for version information disclosure."""
    hostname = base_url.split("//")[1]

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        for header_name, description in VERSION_HEADERS:
            value = resp.headers.get(header_name, "")
            if not value:
                continue

            # Check if it contains version numbers
            has_version = bool(re.search(r'\d+\.\d+', value))
            is_debug = "debug" in header_name.lower()

            if is_debug:
                result.findings.append(BusinessFinding(
                    hostname=hostname,
                    vuln_type="info_disclosure",
                    severity="high",
                    confidence=0.9,
                    title=f"Debug information exposed on {hostname}",
                    description=(
                        f"The server exposes debug information via the "
                        f"'{header_name}' header. This indicates debug mode "
                        f"may be enabled in production."
                    ),
                    evidence=f"{header_name}: {value}",
                ))
            elif has_version:
                # Detailed version info is more interesting than just "nginx"
                severity = "low"
                if any(kw in header_name.lower() for kw in ("aspnet", "powered")):
                    severity = "low"

                result.findings.append(BusinessFinding(
                    hostname=hostname,
                    vuln_type="info_disclosure",
                    severity=severity,
                    confidence=0.9,
                    title=f"{description} disclosed on {hostname}",
                    description=(
                        f"The '{header_name}' header reveals: {value}. "
                        f"Attackers can use version information to find known "
                        f"vulnerabilities specific to this software version."
                    ),
                    evidence=f"{header_name}: {value}",
                ))

    except Exception as e:
        logger.debug("Version disclosure check failed for %s: %s", base_url, e)


def _check_error_disclosure(base_url: str, result: BusinessResult) -> None:
    """Check error pages for stack traces and sensitive information."""
    hostname = base_url.split("//")[1]

    # Trigger error responses with various methods
    error_triggers = [
        f"{base_url}/%00",                    # Null byte
        f"{base_url}/{{{{}}}}",               # Template chars
        f"{base_url}/?id=1'",                 # Quote (may trigger SQL error)
        f"{base_url}/a" * 50,                 # Long path
        f"{base_url}/../../../etc/passwd",    # Path traversal (safe — just testing error response)
    ]

    for trigger_url in error_triggers:
        try:
            resp = httpx.get(
                trigger_url,
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            body = resp.text

            for pattern, description, severity in ERROR_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
                if match:
                    # Extract a snippet around the match
                    start = max(0, match.start() - 50)
                    end = min(len(body), match.end() + 100)
                    snippet = body[start:end].strip()
                    # Sanitize for safe display
                    snippet = re.sub(r'\s+', ' ', snippet)[:200]

                    result.findings.append(BusinessFinding(
                        hostname=hostname,
                        vuln_type="error_leak",
                        severity=severity,
                        confidence=0.85,
                        title=f"{description} exposed on {hostname}",
                        description=(
                            f"The server exposes a {description.lower()} in its error response. "
                            f"This reveals internal implementation details, file paths, "
                            f"and potentially sensitive configuration."
                        ),
                        evidence=f"URL: {trigger_url[:100]}\nSnippet: {snippet}",
                    ))
                    # One finding per error type is enough
                    return

        except Exception:
            continue


def _check_http_methods(base_url: str, result: BusinessResult) -> None:
    """Check which HTTP methods are allowed via OPTIONS request."""
    hostname = base_url.split("//")[1]

    try:
        resp = httpx.options(
            base_url,
            timeout=10.0,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        allow = resp.headers.get("allow", "")
        if not allow:
            allow = resp.headers.get("access-control-allow-methods", "")

        if not allow:
            return

        methods = [m.strip().upper() for m in allow.split(",")]
        dangerous = {"PUT", "DELETE", "PATCH", "TRACE"}
        found_dangerous = dangerous.intersection(methods)

        if found_dangerous:
            result.findings.append(BusinessFinding(
                hostname=hostname,
                vuln_type="method_allowed",
                severity="medium",
                confidence=0.7,
                title=f"Potentially dangerous HTTP methods allowed on {hostname}",
                description=(
                    f"The server allows the following HTTP methods: {', '.join(sorted(methods))}. "
                    f"Methods {', '.join(sorted(found_dangerous))} could allow unauthorized "
                    f"data modification if not properly protected."
                ),
                evidence=f"Allow: {allow}",
            ))

    except Exception as e:
        logger.debug("HTTP methods check failed for %s: %s", base_url, e)


def _check_https_redirect(hostname: str, result: BusinessResult) -> None:
    """Check if HTTP requests are redirected to HTTPS."""
    try:
        resp = httpx.get(
            f"http://{hostname}",
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        if resp.status_code == 200:
            # HTTP serves content without redirecting to HTTPS
            result.findings.append(BusinessFinding(
                hostname=hostname,
                vuln_type="info_disclosure",
                severity="medium",
                confidence=0.9,
                title=f"No HTTP to HTTPS redirect on {hostname}",
                description=(
                    f"The server serves content over unencrypted HTTP without "
                    f"redirecting to HTTPS. User connections can be intercepted."
                ),
                evidence=f"HTTP request to {hostname} returned status {resp.status_code}",
            ))
        elif resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location and not location.startswith("https://"):
                result.findings.append(BusinessFinding(
                    hostname=hostname,
                    vuln_type="info_disclosure",
                    severity="low",
                    confidence=0.8,
                    title=f"HTTP redirect does not point to HTTPS on {hostname}",
                    description=(
                        f"HTTP requests redirect to {location} instead of HTTPS."
                    ),
                    evidence=f"Location: {location}",
                ))

    except Exception:
        pass  # Connection refused on port 80 is fine


def _check_clickjacking(base_url: str, result: BusinessResult) -> None:
    """Check for clickjacking protection."""
    hostname = base_url.split("//")[1]

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        xfo = resp.headers.get("x-frame-options", "")
        csp = resp.headers.get("content-security-policy", "")

        has_xfo = bool(xfo)
        has_csp_frame = "frame-ancestors" in csp.lower() if csp else False

        if not has_xfo and not has_csp_frame:
            # Only report if the page has interactive content (forms, etc.)
            body = resp.text.lower()
            has_forms = "<form" in body
            has_inputs = "<input" in body
            has_buttons = "<button" in body

            if has_forms or has_inputs or has_buttons:
                result.findings.append(BusinessFinding(
                    hostname=hostname,
                    vuln_type="clickjack",
                    severity="medium",
                    confidence=0.8,
                    title=f"Clickjacking possible on {hostname}",
                    description=(
                        f"The page at {hostname} contains interactive elements "
                        f"(forms/inputs) but does not set X-Frame-Options or "
                        f"Content-Security-Policy frame-ancestors. An attacker "
                        f"could embed this page in an iframe to trick users."
                    ),
                    evidence="Missing X-Frame-Options and CSP frame-ancestors headers",
                ))

    except Exception as e:
        logger.debug("Clickjacking check failed for %s: %s", base_url, e)


def _check_cache_headers(base_url: str, result: BusinessResult) -> None:
    """Check for proper cache control on potentially sensitive pages."""
    hostname = base_url.split("//")[1]

    # Check common sensitive page paths
    sensitive_paths = ["/login", "/signin", "/account", "/profile", "/settings"]

    for path in sensitive_paths:
        try:
            resp = httpx.get(
                f"{base_url}{path}",
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            if resp.status_code != 200:
                continue

            cache_control = resp.headers.get("cache-control", "").lower()
            pragma = resp.headers.get("pragma", "").lower()

            # Check if sensitive page allows caching
            if not cache_control or (
                "no-store" not in cache_control and "no-cache" not in cache_control
            ):
                body = resp.text.lower()
                # Only flag if the page has login/sensitive content
                if any(kw in body for kw in ("password", "login", "sign in", "account")):
                    result.findings.append(BusinessFinding(
                        hostname=hostname,
                        vuln_type="cache_issue",
                        severity="low",
                        confidence=0.7,
                        title=f"Sensitive page cacheable on {hostname}{path}",
                        description=(
                            f"The page at {path} appears to contain sensitive content "
                            f"(login form/account data) but does not set proper "
                            f"cache-control headers. Shared caches or browsers may "
                            f"store this page."
                        ),
                        evidence=f"Cache-Control: {cache_control or '(not set)'}",
                    ))
                    break  # One finding is enough

        except Exception:
            continue


def _check_trace_method(base_url: str, result: BusinessResult) -> None:
    """Check if TRACE method is enabled (Cross-Site Tracing risk)."""
    hostname = base_url.split("//")[1]

    try:
        resp = httpx.request(
            "TRACE",
            base_url,
            timeout=10.0,
            headers={
                "User-Agent": "Wintermute/0.1 (Security Research)",
                "X-Custom-Header": "wintermute-trace-test",
            },
        )

        if resp.status_code == 200:
            body = resp.text.lower()
            if "wintermute-trace-test" in body or "trace /" in body:
                result.findings.append(BusinessFinding(
                    hostname=hostname,
                    vuln_type="method_allowed",
                    severity="medium",
                    confidence=0.9,
                    title=f"TRACE method enabled on {hostname}",
                    description=(
                        f"The server supports the HTTP TRACE method, which echoes "
                        f"back the request including headers. This enables "
                        f"Cross-Site Tracing (XST) attacks that can steal "
                        f"authentication cookies even with HttpOnly flag set."
                    ),
                    evidence=f"TRACE response: {resp.text[:200]}",
                ))

    except Exception:
        pass
