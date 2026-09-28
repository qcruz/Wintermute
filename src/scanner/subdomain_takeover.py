"""Subdomain takeover detection.

Checks for dangling CNAME records pointing to unclaimed third-party services.
This is one of the most reliable, automatable vulnerability classes.

How it works:
  1. Resolve the CNAME chain for a hostname
  2. Check if the CNAME target matches a known vulnerable service
  3. Fetch the HTTP response and check for the service's "unclaimed" fingerprint
  4. If both match, the subdomain is likely takeover-able
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import dns.resolver
import httpx

logger = logging.getLogger(__name__)


@dataclass
class TakeoverCheck:
    """Result of a subdomain takeover check."""

    hostname: str
    vulnerable: bool = False
    cname: str = ""
    service: str = ""
    fingerprint_matched: bool = False
    confidence: float = 0.0
    evidence: str = ""


# Known services vulnerable to subdomain takeover.
# Each entry: (cname_pattern, service_name, http_fingerprints)
# Fingerprints are strings we look for in the HTTP response body.
VULNERABLE_SERVICES = [
    # Cloud platforms
    (
        ".herokuapp.com",
        "Heroku",
        ["no such app", "there is no app configured at that hostname"],
    ),
    (
        ".herokudns.com",
        "Heroku",
        ["no such app", "there is no app configured at that hostname"],
    ),
    (
        ".ghost.io",
        "Ghost",
        ["the thing you were looking for is no longer here"],
    ),
    # AWS
    (
        ".s3.amazonaws.com",
        "AWS S3",
        ["nosuchbucket", "the specified bucket does not exist"],
    ),
    (
        ".s3-website",
        "AWS S3",
        ["nosuchbucket", "the specified bucket does not exist"],
    ),
    (
        ".elasticbeanstalk.com",
        "AWS Elastic Beanstalk",
        ["404 not found"],
    ),
    # Azure
    (
        ".azurewebsites.net",
        "Azure",
        ["404 web site not found", "azure web app - error 404"],
    ),
    (
        ".cloudapp.net",
        "Azure",
        [],
    ),
    (
        ".trafficmanager.net",
        "Azure Traffic Manager",
        [],
    ),
    (
        ".blob.core.windows.net",
        "Azure Blob",
        ["the specified container does not exist", "blobnotfound"],
    ),
    # GitHub
    (
        ".github.io",
        "GitHub Pages",
        ["there isn't a github pages site here", "for root urls"],
    ),
    # Shopify
    (
        ".myshopify.com",
        "Shopify",
        ["sorry, this shop is currently unavailable", "only one step left"],
    ),
    # Zendesk
    (
        ".zendesk.com",
        "Zendesk",
        ["help center closed"],
    ),
    # Tumblr
    (
        ".tumblr.com",
        "Tumblr",
        ["there's nothing here", "whatever you were looking for"],
    ),
    # Fastly
    (
        ".fastly.net",
        "Fastly",
        ["fastly error: unknown domain"],
    ),
    # Pantheon
    (
        ".pantheonsite.io",
        "Pantheon",
        ["404 unknown site", "the gods are wise"],
    ),
    # Surge
    (
        ".surge.sh",
        "Surge",
        ["project not found"],
    ),
    # Fly.io
    (
        ".fly.dev",
        "Fly.io",
        ["404 not found"],
    ),
    # Netlify
    (
        ".netlify.app",
        "Netlify",
        ["not found - request id"],
    ),
    # Vercel
    (
        ".vercel.app",
        "Vercel",
        ["deployment not found"],
    ),
]


def check_takeover(hostname: str) -> TakeoverCheck:
    """Check a single hostname for subdomain takeover vulnerability.

    Steps:
        1. Resolve CNAME records
        2. Match CNAME against known vulnerable services
        3. If matched, fetch HTTP response and check fingerprint
    """
    result = TakeoverCheck(hostname=hostname)

    # Step 1: Get CNAME records
    cname = _get_cname(hostname)
    if not cname:
        return result  # No CNAME = no takeover risk via this method

    result.cname = cname

    # Step 2: Match against known vulnerable services
    service, fingerprints = _match_service(cname)
    if not service:
        return result  # CNAME doesn't point to a known vulnerable service

    result.service = service

    # Step 3: Check HTTP response for unclaimed fingerprint
    if fingerprints:
        matched, evidence = _check_fingerprint(hostname, fingerprints)
        result.fingerprint_matched = matched
        result.evidence = evidence

        if matched:
            result.vulnerable = True
            result.confidence = 0.9  # High confidence: CNAME + fingerprint
            logger.warning(
                "POTENTIAL TAKEOVER: %s → %s (%s) — fingerprint matched",
                hostname, cname, service,
            )
        else:
            # CNAME matches but fingerprint doesn't — might still be vulnerable
            # but lower confidence
            result.confidence = 0.4
    else:
        # Service is known vulnerable but we don't have fingerprints to verify
        # Could be a DNS-only takeover (e.g., Azure cloudapp)
        nxdomain = _check_nxdomain(cname)
        if nxdomain:
            result.vulnerable = True
            result.confidence = 0.7
            result.evidence = f"CNAME target {cname} returns NXDOMAIN"
            logger.warning(
                "POTENTIAL TAKEOVER: %s → %s (%s) — NXDOMAIN",
                hostname, cname, service,
            )

    return result


def check_many(hostnames: list[str]) -> list[TakeoverCheck]:
    """Check multiple hostnames for subdomain takeover."""
    results = []
    for hostname in hostnames:
        result = check_takeover(hostname)
        results.append(result)
        if result.cname:
            logger.info(
                "Takeover check: %s → %s (%s) vulnerable=%s",
                hostname, result.cname, result.service or "unknown",
                result.vulnerable,
            )
    return results


def _get_cname(hostname: str) -> str:
    """Resolve the CNAME record for a hostname.

    Returns the CNAME target, or empty string if no CNAME exists.
    A CNAME (Canonical Name) record is like an alias — it says
    "this hostname is actually served by that other hostname."
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        answers = resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".").lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        pass
    except Exception as e:
        logger.debug("CNAME lookup failed for %s: %s", hostname, e)

    return ""


def _match_service(cname: str) -> tuple[str, list[str]]:
    """Check if a CNAME target matches a known vulnerable service.

    Returns (service_name, fingerprints) or ("", []) if no match.
    """
    cname_lower = cname.lower()
    for pattern, service, fingerprints in VULNERABLE_SERVICES:
        if cname_lower.endswith(pattern):
            return service, fingerprints
    return "", []


def _check_fingerprint(hostname: str, fingerprints: list[str]) -> tuple[bool, str]:
    """Fetch the HTTP response and check for unclaimed service fingerprints.

    Returns (matched, evidence).
    """
    for scheme in ("https", "http"):
        try:
            response = httpx.get(
                f"{scheme}://{hostname}",
                timeout=10.0,
                follow_redirects=False,  # Don't follow — we want the raw response
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )
            body = response.text.lower()

            for fp in fingerprints:
                if fp.lower() in body:
                    return True, f"HTTP {response.status_code}: body contains '{fp}'"

        except Exception:
            continue

    return False, ""


def _check_nxdomain(cname: str) -> bool:
    """Check if a CNAME target returns NXDOMAIN (doesn't exist in DNS).

    If the CNAME target itself doesn't resolve, the service has been
    deleted and the subdomain may be claimable.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        resolver.resolve(cname, "A")
        return False  # Resolves — not NXDOMAIN
    except dns.resolver.NXDOMAIN:
        return True  # NXDOMAIN — target doesn't exist
    except Exception:
        return False
