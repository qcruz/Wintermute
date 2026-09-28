"""Security header analysis — converting header gaps into findings.

Takes the raw header analysis from recon and generates structured
findings with severity ratings and remediation advice.

This is different from src/recon/headers.py which just collects data.
This module interprets that data and creates actionable findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HeaderFinding:
    """A security finding from header analysis."""

    header: str
    severity: str  # info, low, medium, high
    title: str
    description: str
    remediation: str
    confidence: float = 0.9  # Header findings are very reliable


# What each missing header means and how to fix it
HEADER_FINDINGS = {
    "strict-transport-security": HeaderFinding(
        header="strict-transport-security",
        severity="medium",
        title="Missing HSTS Header (Strict-Transport-Security)",
        description=(
            "The server does not set the Strict-Transport-Security header. "
            "This means browsers will not enforce HTTPS connections, leaving "
            "users vulnerable to protocol downgrade attacks and cookie hijacking "
            "on insecure networks (like public WiFi)."
        ),
        remediation=(
            "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "This tells browsers to always use HTTPS for this domain for the next year."
        ),
    ),
    "content-security-policy": HeaderFinding(
        header="content-security-policy",
        severity="low",
        title="Missing Content Security Policy (CSP)",
        description=(
            "The server does not set a Content-Security-Policy header. "
            "CSP is a defense-in-depth measure against cross-site scripting (XSS) "
            "attacks. Without it, if an XSS vulnerability exists, there's no "
            "browser-side mitigation."
        ),
        remediation=(
            "Add a Content-Security-Policy header that restricts script sources. "
            "Start with: Content-Security-Policy: default-src 'self'\n"
            "Then adjust as needed for your application's requirements."
        ),
    ),
    "x-content-type-options": HeaderFinding(
        header="x-content-type-options",
        severity="low",
        title="Missing X-Content-Type-Options Header",
        description=(
            "The server does not set X-Content-Type-Options: nosniff. "
            "Without this, browsers may try to guess the content type of "
            "responses, which can be exploited to execute malicious content "
            "disguised as a harmless file type."
        ),
        remediation="Add the header: X-Content-Type-Options: nosniff",
    ),
    "x-frame-options": HeaderFinding(
        header="x-frame-options",
        severity="low",
        title="Missing X-Frame-Options Header",
        description=(
            "The server does not set X-Frame-Options. This means the site can "
            "be embedded in an iframe on another site, potentially enabling "
            "clickjacking attacks where users are tricked into clicking hidden "
            "buttons or links."
        ),
        remediation=(
            "Add the header: X-Frame-Options: DENY\n"
            "Or if the site needs to be framed by the same origin: "
            "X-Frame-Options: SAMEORIGIN"
        ),
    ),
    "referrer-policy": HeaderFinding(
        header="referrer-policy",
        severity="info",
        title="Missing Referrer-Policy Header",
        description=(
            "The server does not set a Referrer-Policy. By default, browsers "
            "send the full URL as the Referer header when navigating to other "
            "sites, which may leak sensitive information in URL parameters."
        ),
        remediation="Add the header: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "permissions-policy": HeaderFinding(
        header="permissions-policy",
        severity="info",
        title="Missing Permissions-Policy Header",
        description=(
            "The server does not set a Permissions-Policy (formerly "
            "Feature-Policy). This header controls which browser features "
            "(camera, microphone, geolocation, etc.) the page can use."
        ),
        remediation=(
            "Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
            "This disables sensitive features unless explicitly needed."
        ),
    ),
}


@dataclass
class HeaderAnalysisResult:
    """Aggregated security header findings for a hostname."""

    hostname: str
    findings: list[HeaderFinding] = field(default_factory=list)
    total_missing: int = 0
    worst_severity: str = "info"

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def analyze_missing_headers(
    hostname: str, missing_headers: list[str]
) -> HeaderAnalysisResult:
    """Generate findings from a list of missing security headers.

    Args:
        hostname: The target hostname
        missing_headers: List of missing header names (lowercase)
            from src/recon/headers.py analysis
    """
    result = HeaderAnalysisResult(hostname=hostname)
    result.total_missing = len(missing_headers)

    for header in missing_headers:
        header_lower = header.lower()
        if header_lower in HEADER_FINDINGS:
            finding = HEADER_FINDINGS[header_lower]
            result.findings.append(finding)

            if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(
                result.worst_severity, 0
            ):
                result.worst_severity = finding.severity

    return result
