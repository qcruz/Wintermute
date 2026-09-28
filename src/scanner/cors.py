"""CORS misconfiguration detection.

CORS (Cross-Origin Resource Sharing) controls which websites can make
requests to your API from a browser. A misconfigured CORS policy can
let any website read private data from an authenticated API.

How it works:
  We send requests with different Origin headers and check what the
  server reflects back. If it reflects an attacker-controlled origin
  with credentials allowed, that's a vulnerability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# The origin we use to test reflection — obviously not a real attack domain
TEST_ORIGIN = "https://wintermute-cors-test.example.com"


@dataclass
class CORSCheck:
    """Result of a CORS misconfiguration check."""

    hostname: str
    url: str = ""
    vulnerable: bool = False
    issue: str = ""
    confidence: float = 0.0
    details: dict = field(default_factory=dict)


def check_cors(hostname: str) -> CORSCheck:
    """Check a hostname for CORS misconfigurations.

    Tests:
      1. Arbitrary origin reflection — does the server echo back any origin?
      2. Null origin acceptance — does the server accept Origin: null?
      3. Credentials with wildcard — both Access-Control-Allow-Credentials
         and a permissive Allow-Origin?

    We only send HEAD/GET requests with an Origin header. This is completely
    safe — we're just reading response headers, not sending payloads.
    """
    result = CORSCheck(hostname=hostname)
    url = f"https://{hostname}"
    result.url = url

    # Test 1: Arbitrary origin reflection
    try:
        response = httpx.get(
            url,
            headers={
                "Origin": TEST_ORIGIN,
                "User-Agent": "Wintermute/0.1 (Security Research)",
            },
            timeout=10.0,
            follow_redirects=True,
        )
        headers = {k.lower(): v for k, v in response.headers.items()}

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        result.details = {
            "access-control-allow-origin": acao,
            "access-control-allow-credentials": acac,
            "status_code": response.status_code,
        }

        # Check 1: Origin reflected back (most dangerous)
        if acao == TEST_ORIGIN:
            if acac == "true":
                # Critical: reflects arbitrary origin WITH credentials
                result.vulnerable = True
                result.issue = "Reflects arbitrary origin with credentials"
                result.confidence = 0.95
                logger.warning("CORS vuln: %s reflects origin with credentials", hostname)
                return result
            else:
                # Medium: reflects origin but no credentials
                result.vulnerable = True
                result.issue = "Reflects arbitrary origin (no credentials)"
                result.confidence = 0.7
                logger.warning("CORS vuln: %s reflects arbitrary origin", hostname)
                return result

        # Check 2: Wildcard with credentials (browsers block this, but still bad config)
        if acao == "*" and acac == "true":
            result.vulnerable = True
            result.issue = "Wildcard origin with credentials (browser-blocked but misconfigured)"
            result.confidence = 0.5
            return result

    except Exception as e:
        logger.debug("CORS check failed for %s: %s", hostname, e)
        return result

    # Test 2: Null origin
    try:
        response = httpx.get(
            url,
            headers={
                "Origin": "null",
                "User-Agent": "Wintermute/0.1 (Security Research)",
            },
            timeout=10.0,
            follow_redirects=True,
        )
        headers = {k.lower(): v for k, v in response.headers.items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao == "null":
            result.vulnerable = True
            result.details["null_origin_accepted"] = True
            if acac == "true":
                result.issue = "Accepts null origin with credentials"
                result.confidence = 0.85
            else:
                result.issue = "Accepts null origin"
                result.confidence = 0.6
            logger.warning("CORS vuln: %s accepts null origin", hostname)
            return result

    except Exception as e:
        logger.debug("CORS null origin check failed for %s: %s", hostname, e)

    return result


def check_many(hostnames: list[str]) -> list[CORSCheck]:
    """Check multiple hostnames for CORS issues."""
    return [check_cors(h) for h in hostnames]
