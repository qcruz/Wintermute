"""Parameter fuzzing for injection vulnerabilities.

Tests URL parameters for common injection flaws using safe, non-destructive
canary values. We never send payloads that could modify data or cause damage.

How it works:
  1. Discover URL parameters by crawling the target's homepage and forms
  2. Inject harmless canary strings into each parameter
  3. Check responses for reflection (XSS), error signatures (SQLi),
     redirects (open redirect), and template evaluation (SSTI)

Safety:
  - All payloads are designed to detect, not exploit
  - No POST/PUT/DELETE requests — GET only
  - No authentication bypass attempts
  - No destructive SQL (DROP, DELETE, UPDATE)
"""

from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class InjectionFinding:
    """A potential injection vulnerability."""

    url: str
    parameter: str
    vuln_type: str  # xss, sqli, open_redirect, ssti
    severity: str
    confidence: float
    description: str
    evidence: str
    payload_used: str


@dataclass
class InjectionResult:
    """Results of injection testing for a hostname."""

    hostname: str
    parameters_tested: int = 0
    findings: list[InjectionFinding] = field(default_factory=list)


# ── Canary Payloads ────────────────────────────────────────────────
# Harmless strings designed to detect reflection/evaluation without damage.

# XSS: if this string appears unescaped in the response, input is reflected
XSS_CANARY = "wm7x<script>wm7x</script>"
XSS_CANARY_TAG = "wm7x<img src=x>"
XSS_SIMPLE = "wm7x\">'<"

# SQLi: strings that trigger SQL syntax errors in vulnerable apps
SQLI_CANARIES = [
    "' OR '1'='1",        # Classic — triggers syntax changes
    "1' AND '1'='2",      # Blind: should return different result than normal
    "1; SELECT 1--",      # Statement termination attempt
]

# SQL error signatures in responses
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sql syntax.*?mysql",
    r"warning.*?\bmysqli?\b",
    r"valid mysql result",
    r"postgresql.*?error",
    r"pg_query\(\).*?failed",
    r"ora-\d{5}",
    r"microsoft.*?odbc.*?sql",
    r"microsoft.*?sql.*?server",
    r"sqlite.*?error",
    r"sqlite3\.operational",
    r"sqlstate\[",
    r"syntax error.*?near",
    r"unrecognized token",
]

# Open redirect: if the app redirects to this URL, it's vulnerable
REDIRECT_CANARY = "https://wintermute-redirect-test.example.com"

# SSTI: if the app evaluates this, we'll see "49" in the response
SSTI_CANARY = "{{7*7}}"
SSTI_RESULT = "49"

# Common parameter names worth testing (when we can't discover them from forms)
COMMON_PARAMS = [
    "q", "search", "query", "s", "keyword",    # Search
    "url", "next", "redirect", "return",        # Redirect
    "returnUrl", "return_url", "redirect_uri",  # Redirect (cont.)
    "callback", "continue", "dest", "go",       # Redirect (cont.)
    "page", "id", "cat", "category",            # Data retrieval
    "name", "user", "username", "email",        # User input
    "lang", "language", "locale",               # Locale
    "template", "view", "layout",               # Template
    "file", "path", "doc",                      # Path
    "action", "type", "sort", "order",          # Control
    "debug", "test", "verbose",                 # Debug
]


def test_injection(hostname: str) -> InjectionResult:
    """Test a hostname for injection vulnerabilities.

    Safe: only sends GET requests with canary values.
    """
    result = InjectionResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # Step 1: Discover parameters from the homepage and linked pages
    discovered_params = _discover_parameters(base_url)

    # Merge with common params (deduplicated)
    all_params = list(set(discovered_params + COMMON_PARAMS))

    # Step 2: Test each parameter
    for param in all_params:
        result.parameters_tested += 1

        # Test reflected XSS
        xss_finding = _test_xss(base_url, param)
        if xss_finding:
            result.findings.append(xss_finding)

        # Test SQL injection
        sqli_finding = _test_sqli(base_url, param)
        if sqli_finding:
            result.findings.append(sqli_finding)

        # Test open redirect (only for redirect-like params)
        if any(kw in param.lower() for kw in (
            "url", "redirect", "return", "next", "continue",
            "dest", "go", "callback", "forward", "uri",
        )):
            redirect_finding = _test_open_redirect(base_url, param)
            if redirect_finding:
                result.findings.append(redirect_finding)

        # Test SSTI (only for template-like params)
        if any(kw in param.lower() for kw in (
            "template", "view", "layout", "name", "search",
            "q", "query", "s", "keyword", "lang",
        )):
            ssti_finding = _test_ssti(base_url, param)
            if ssti_finding:
                result.findings.append(ssti_finding)

    if result.findings:
        logger.info(
            "Injection testing on %s: %d findings from %d parameters",
            hostname, len(result.findings), result.parameters_tested,
        )

    return result


def _discover_parameters(base_url: str) -> list[str]:
    """Discover URL parameters by parsing the homepage for links and forms."""
    params = set()

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        body = resp.text

        # Extract parameters from href links
        hrefs = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body, re.IGNORECASE)
        for href in hrefs:
            parsed = urlparse(href)
            qs = parse_qs(parsed.query)
            params.update(qs.keys())

        # Extract parameters from form inputs
        inputs = re.findall(
            r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE
        )
        params.update(inputs)

        # Extract from action URLs
        actions = re.findall(
            r'action=["\']([^"\']*\?[^"\']*)["\']', body, re.IGNORECASE
        )
        for action in actions:
            parsed = urlparse(action)
            qs = parse_qs(parsed.query)
            params.update(qs.keys())

    except Exception as e:
        logger.debug("Parameter discovery failed for %s: %s", base_url, e)

    return list(params)


def _test_xss(base_url: str, param: str) -> InjectionFinding | None:
    """Test a parameter for reflected XSS."""
    url = f"{base_url}/?{urlencode({param: XSS_SIMPLE})}"

    try:
        resp = httpx.get(
            url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        body = resp.text

        # Check if our special characters are reflected unescaped
        if XSS_SIMPLE in body:
            # The characters "<>'" are reflected without encoding
            # Now test with an actual tag to confirm
            tag_url = f"{base_url}/?{urlencode({param: XSS_CANARY})}"
            tag_resp = httpx.get(
                tag_url,
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            if "<script>wm7x</script>" in tag_resp.text:
                # Full script tag reflected — high confidence XSS
                return InjectionFinding(
                    url=url,
                    parameter=param,
                    vuln_type="xss",
                    severity="high",
                    confidence=0.9,
                    description=(
                        f"Reflected XSS in parameter '{param}' — "
                        f"script tags are reflected unescaped in the response"
                    ),
                    evidence=f"Injected: {XSS_CANARY}, reflected in response body",
                    payload_used=XSS_CANARY,
                )

            if XSS_CANARY_TAG.split(">")[0] in tag_resp.text:
                # img tag reflected — still XSS
                return InjectionFinding(
                    url=url,
                    parameter=param,
                    vuln_type="xss",
                    severity="high",
                    confidence=0.85,
                    description=(
                        f"Reflected XSS in parameter '{param}' — "
                        f"HTML tags are reflected unescaped"
                    ),
                    evidence=f"HTML special chars reflected without encoding",
                    payload_used=XSS_SIMPLE,
                )

            # Special chars reflected but tags might be stripped
            return InjectionFinding(
                url=url,
                parameter=param,
                vuln_type="xss",
                severity="medium",
                confidence=0.6,
                description=(
                    f"Potential reflected XSS in parameter '{param}' — "
                    f"special characters (<, >, ', \") are reflected without encoding"
                ),
                evidence=f"Characters {XSS_SIMPLE} reflected in response",
                payload_used=XSS_SIMPLE,
            )

    except Exception as e:
        logger.debug("XSS test failed for %s param=%s: %s", base_url, param, e)

    return None


def _test_sqli(base_url: str, param: str) -> InjectionFinding | None:
    """Test a parameter for SQL injection via error-based detection."""
    for canary in SQLI_CANARIES:
        url = f"{base_url}/?{urlencode({param: canary})}"

        try:
            resp = httpx.get(
                url,
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            body = resp.text.lower()

            # Check for SQL error signatures
            for pattern in SQLI_ERROR_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return InjectionFinding(
                        url=url,
                        parameter=param,
                        vuln_type="sqli",
                        severity="critical",
                        confidence=0.85,
                        description=(
                            f"SQL injection in parameter '{param}' — "
                            f"database error message exposed: {match.group(0)}"
                        ),
                        evidence=f"Error pattern '{match.group(0)}' found in response",
                        payload_used=canary,
                    )

        except Exception as e:
            logger.debug("SQLi test failed for %s param=%s: %s", base_url, param, e)

    return None


def _test_open_redirect(base_url: str, param: str) -> InjectionFinding | None:
    """Test a parameter for open redirect vulnerability."""
    url = f"{base_url}/?{urlencode({param: REDIRECT_CANARY})}"

    try:
        resp = httpx.get(
            url,
            timeout=10.0,
            follow_redirects=False,  # Don't follow — we want to see the redirect
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if REDIRECT_CANARY in location:
                return InjectionFinding(
                    url=url,
                    parameter=param,
                    vuln_type="open_redirect",
                    severity="medium",
                    confidence=0.9,
                    description=(
                        f"Open redirect via parameter '{param}' — "
                        f"server redirects to attacker-controlled URL"
                    ),
                    evidence=f"Redirect Location: {location}",
                    payload_used=REDIRECT_CANARY,
                )

        # Also check for meta refresh or javascript redirect in body
        if resp.status_code == 200:
            body = resp.text.lower()
            if REDIRECT_CANARY.lower() in body:
                # Check for meta refresh
                if "http-equiv" in body and "refresh" in body:
                    return InjectionFinding(
                        url=url,
                        parameter=param,
                        vuln_type="open_redirect",
                        severity="medium",
                        confidence=0.7,
                        description=(
                            f"Potential open redirect via meta refresh in parameter '{param}'"
                        ),
                        evidence="Redirect URL found in meta refresh tag",
                        payload_used=REDIRECT_CANARY,
                    )

    except Exception as e:
        logger.debug("Redirect test failed for %s param=%s: %s", base_url, param, e)

    return None


def _test_ssti(base_url: str, param: str) -> InjectionFinding | None:
    """Test a parameter for Server-Side Template Injection."""
    url = f"{base_url}/?{urlencode({param: SSTI_CANARY})}"

    try:
        resp = httpx.get(
            url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        body = resp.text

        # If {{7*7}} was evaluated to 49, template injection exists
        # But we need to make sure "49" isn't just coincidental
        if SSTI_RESULT in body and SSTI_CANARY not in body:
            # The expression was evaluated (canary gone, result present)
            # Verify by checking if "49" appears near where our input would be
            # This reduces false positives from pages that naturally contain "49"

            # Get baseline: request without the canary
            baseline = httpx.get(
                f"{base_url}/?{urlencode({param: 'wintermute_test'})}",
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            # If "49" appears in baseline too, it's not from our injection
            if SSTI_RESULT not in baseline.text:
                return InjectionFinding(
                    url=url,
                    parameter=param,
                    vuln_type="ssti",
                    severity="critical",
                    confidence=0.85,
                    description=(
                        f"Server-Side Template Injection in parameter '{param}' — "
                        f"expression {{{{7*7}}}} was evaluated to 49"
                    ),
                    evidence=f"Template expression evaluated: {SSTI_CANARY} → {SSTI_RESULT}",
                    payload_used=SSTI_CANARY,
                )

    except Exception as e:
        logger.debug("SSTI test failed for %s param=%s: %s", base_url, param, e)

    return None
