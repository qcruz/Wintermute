"""HTTP header analysis and technology fingerprinting."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class HeaderAnalysis:
    hostname: str
    status_code: int = 0
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    interesting_headers: dict[str, str] = field(default_factory=dict)
    error: str = ""


# Security headers we expect to see on well-configured sites
EXPECTED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

# Headers that reveal technology choices
TECH_HEADERS = {
    "x-powered-by": None,
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": None,
    "x-shopify-stage": "Shopify",
    "x-wix-request-id": "Wix",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-request-id": "AWS S3",
    "x-vercel-id": "Vercel",
    "x-netlify-request-id": "Netlify",
    "cf-ray": "Cloudflare",
    "x-cache": None,
}


def analyze_headers(hostname: str, timeout: float = 10.0) -> HeaderAnalysis:
    """Fetch HTTP headers from a host and analyze them.

    Tries HTTPS first, falls back to HTTP.
    """
    result = HeaderAnalysis(hostname=hostname)

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            response = httpx.get(
                url,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )
            headers = {k.lower(): v for k, v in response.headers.items()}
            result.status_code = response.status_code

            # Server header
            result.server = headers.get("server", "")

            # Security headers
            for header in EXPECTED_SECURITY_HEADERS:
                if header in headers:
                    result.security_headers[header] = headers[header]
                else:
                    result.missing_security_headers.append(header)

            # Technology detection
            for header, tech_name in TECH_HEADERS.items():
                if header in headers:
                    value = headers[header]
                    tech = tech_name or value
                    result.technologies.append(f"{header}: {tech}")
                    result.interesting_headers[header] = value

            if result.server:
                result.technologies.insert(0, f"server: {result.server}")

            return result

        except Exception as e:
            if scheme == "http":
                result.error = str(e)
                logger.debug("Header fetch failed for %s: %s", hostname, e)

    return result
