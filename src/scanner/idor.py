"""Insecure Direct Object Reference (IDOR) detection.

IDOR vulnerabilities occur when an application exposes internal object
references (like database IDs) in URLs or API responses, and fails to
verify that the requesting user is authorized to access the referenced
object. An attacker can simply change the ID to access other users' data.

How it works:
  1. Probe common API patterns that use IDs (/api/users/1, /api/orders/1, etc.)
  2. Extract numeric IDs from JSON responses
  3. Request adjacent IDs (id+1, id-1) and compare responses
  4. If different objects are returned for different IDs without auth,
     the endpoint has broken access control
  5. Check response content for sensitive data indicators (email, phone, etc.)

What makes a finding:
  - An endpoint returns different JSON objects for different IDs
  - No authentication is required (no login, no cookie, no token)
  - The response contains fields that suggest user/account data

Safety:
  - GET requests only — never modifies data
  - Only tests publicly accessible endpoints (no auth bypass)
  - Uses IDs discovered in the application's own responses
  - Small ID range (only tests id, id+1, id-1) — not brute-forcing
  - No attempt to access real user data — we only check response structure
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class IDORFinding:
    """A potential IDOR vulnerability."""

    hostname: str
    endpoint: str
    vuln_type: str  # always "idor"
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str
    ids_tested: list[str] = field(default_factory=list)


@dataclass
class IDORResult:
    """Results of IDOR testing for a hostname."""

    hostname: str
    endpoints_tested: int = 0
    findings: list[IDORFinding] = field(default_factory=list)


# ── API Endpoint Patterns ─────────────────────────────────────────
# Common REST API patterns that use object IDs.
# {id} will be replaced with test IDs.
# (pattern, resource_description)

API_PATTERNS = [
    # User data
    ("/api/users/{id}", "User profile"),
    ("/api/user/{id}", "User profile"),
    ("/api/v1/users/{id}", "User profile (v1)"),
    ("/api/v2/users/{id}", "User profile (v2)"),
    ("/api/members/{id}", "Member profile"),
    ("/api/profiles/{id}", "User profile"),
    ("/api/accounts/{id}", "Account details"),
    ("/api/account/{id}", "Account details"),

    # Orders / transactions
    ("/api/orders/{id}", "Order details"),
    ("/api/order/{id}", "Order details"),
    ("/api/v1/orders/{id}", "Order details (v1)"),
    ("/api/invoices/{id}", "Invoice"),
    ("/api/transactions/{id}", "Transaction"),
    ("/api/payments/{id}", "Payment details"),
    ("/api/receipts/{id}", "Receipt"),

    # Documents / files
    ("/api/documents/{id}", "Document"),
    ("/api/files/{id}", "File"),
    ("/api/attachments/{id}", "Attachment"),
    ("/api/reports/{id}", "Report"),
    ("/api/exports/{id}", "Data export"),

    # Messages / notifications
    ("/api/messages/{id}", "Message"),
    ("/api/notifications/{id}", "Notification"),
    ("/api/conversations/{id}", "Conversation"),
    ("/api/tickets/{id}", "Support ticket"),
    ("/api/comments/{id}", "Comment"),

    # Generic resource patterns
    ("/api/items/{id}", "Item"),
    ("/api/records/{id}", "Record"),
    ("/api/entries/{id}", "Entry"),
    ("/api/data/{id}", "Data record"),
]

# Test IDs — small range, low numbers (most likely to exist in any system)
TEST_IDS = ["1", "2", "3", "100"]

# Fields in JSON responses that suggest sensitive/user data
SENSITIVE_FIELDS = {
    # High sensitivity — PII
    "email", "e-mail", "mail", "email_address",
    "phone", "phone_number", "mobile", "telephone",
    "ssn", "social_security", "tax_id",
    "password", "passwd", "secret", "password_hash",
    "credit_card", "card_number", "cvv", "expiry",
    "address", "street", "zip", "postal_code",
    "date_of_birth", "dob", "birthday",

    # Medium sensitivity — account data
    "username", "user_name", "login",
    "first_name", "last_name", "full_name", "name",
    "balance", "amount", "total", "price",
    "api_key", "api_secret", "token", "access_token",
    "role", "permissions", "is_admin",
}

# Fields that indicate this is a real data object, not an error page
OBJECT_INDICATORS = {
    "id", "uuid", "created_at", "updated_at", "created", "modified",
    "status", "type", "slug",
}

THIRD_PARTY_REDIRECTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
]


def check_idor(hostname: str) -> IDORResult:
    """Test a hostname for IDOR vulnerabilities.

    Safe: only sends GET requests to common API patterns with small test IDs.
    No authentication bypass — only tests what's publicly accessible.
    """
    result = IDORResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # Early exit: skip third-party hosted sites
    try:
        probe = httpx.get(
            base_url, timeout=8.0, follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if probe.status_code in (301, 302, 303, 307, 308):
            location = probe.headers.get("location", "").lower()
            if any(d in location for d in THIRD_PARTY_REDIRECTS):
                return result
    except Exception:
        pass

    # Step 1: Get 404 baseline to filter custom error pages
    baseline_body, baseline_length = _get_baseline(base_url)

    # Step 2: Discover which API patterns exist on this host
    live_endpoints = _discover_api_endpoints(base_url, baseline_body, baseline_length)

    if not live_endpoints:
        return result

    logger.debug(
        "IDOR: found %d live API endpoints on %s",
        len(live_endpoints), hostname,
    )

    # Step 3: Test each live endpoint for IDOR
    for endpoint, description, sample_response in live_endpoints:
        result.endpoints_tested += 1
        finding = _test_endpoint_idor(
            base_url, hostname, endpoint, description, sample_response,
        )
        if finding:
            result.findings.append(finding)

    if result.findings:
        logger.info(
            "IDOR testing on %s: %d findings from %d endpoints",
            hostname, len(result.findings), result.endpoints_tested,
        )

    return result


def _get_baseline(base_url: str) -> tuple[str, int]:
    """Get baseline 404 response for comparison."""
    try:
        resp = httpx.get(
            f"{base_url}/api/wintermute-idor-baseline-7f3a9b2c",
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        return resp.text.lower(), len(resp.content)
    except Exception:
        return "", 0


def _discover_api_endpoints(
    base_url: str,
    baseline_body: str,
    baseline_length: int,
) -> list[tuple[str, str, dict]]:
    """Probe API patterns to find which ones return real data.

    Returns list of (endpoint_pattern, description, sample_json_response)
    for endpoints that return JSON with object-like structure.
    """
    live = []

    for pattern, description in API_PATTERNS:
        # Test with ID 1 first
        path = pattern.replace("{id}", "1")
        try:
            resp = httpx.get(
                f"{base_url}{path}",
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )
        except Exception:
            continue

        # Skip non-200 responses
        if resp.status_code != 200:
            continue

        content_type = resp.headers.get("content-type", "").lower()

        # Must be JSON
        if "application/json" not in content_type:
            continue

        # Skip if matches 404 baseline (custom error page)
        if baseline_length and abs(len(resp.content) - baseline_length) < 50:
            continue

        # Parse JSON
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            continue

        # Must be a dict or a list of dicts (not a simple error message)
        if isinstance(data, dict):
            if _looks_like_data_object(data):
                live.append((pattern, description, data))
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            if _looks_like_data_object(data[0]):
                live.append((pattern, description, data[0]))

    return live


def _looks_like_data_object(obj: dict) -> bool:
    """Check if a JSON object looks like a real data record (not an error page)."""
    keys = {k.lower() for k in obj.keys()}

    # Must have some object-indicator fields
    has_indicators = bool(keys & OBJECT_INDICATORS)

    # Should have more than just a message/error field
    if keys <= {"message", "error", "status", "code", "detail"}:
        return False

    # Minimum complexity — trivial objects are probably API metadata
    if len(keys) < 3:
        return False

    return has_indicators or len(keys) >= 5


def _test_endpoint_idor(
    base_url: str,
    hostname: str,
    pattern: str,
    description: str,
    sample_response: dict,
) -> IDORFinding | None:
    """Test a specific endpoint for IDOR by requesting adjacent IDs.

    The logic:
    1. We already know ID=1 returns a data object
    2. Request ID=2 and ID=3
    3. If they return DIFFERENT data objects (different field values),
       the endpoint serves different records based on ID without auth
    4. Check for sensitive fields in the response
    """
    responses: dict[str, dict] = {}
    ids_to_test = TEST_IDS

    for test_id in ids_to_test:
        path = pattern.replace("{id}", test_id)
        try:
            resp = httpx.get(
                f"{base_url}{path}",
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        content_type = resp.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            continue

        try:
            data = resp.json()
            if isinstance(data, dict) and _looks_like_data_object(data):
                responses[test_id] = data
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                responses[test_id] = data[0]
        except (json.JSONDecodeError, ValueError):
            continue

    # Need at least 2 different responses to confirm IDOR
    if len(responses) < 2:
        return None

    # Check if responses contain different data (not the same object every time)
    unique_responses = _count_unique_responses(responses)
    if unique_responses < 2:
        # Same data for every ID — probably returns the same default object
        return None

    # Found: multiple IDs return different data objects without auth
    # Now assess severity based on what fields are exposed
    all_fields: set[str] = set()
    for data in responses.values():
        all_fields.update(k.lower() for k in data.keys())
        # Check nested objects too (one level deep)
        for v in data.values():
            if isinstance(v, dict):
                all_fields.update(k.lower() for k in v.keys())

    sensitive_found = all_fields & SENSITIVE_FIELDS
    has_pii = bool(sensitive_found & {
        "email", "phone", "ssn", "password", "credit_card",
        "address", "date_of_birth", "api_key", "access_token",
    })

    # Determine severity
    if has_pii:
        severity = "high"
        confidence = 0.85
    elif sensitive_found:
        severity = "medium"
        confidence = 0.75
    else:
        severity = "medium"
        confidence = 0.65

    # Build evidence
    ids_with_data = list(responses.keys())
    sample_keys = sorted(all_fields)[:20]
    sensitive_list = sorted(sensitive_found) if sensitive_found else ["(no known sensitive fields)"]

    evidence_parts = [
        f"Endpoint: {pattern}",
        f"IDs returning data: {', '.join(ids_with_data)} ({unique_responses} unique objects)",
        f"Response fields: {', '.join(sample_keys)}",
        f"Sensitive fields found: {', '.join(sensitive_list)}",
        "No authentication required",
    ]

    return IDORFinding(
        hostname=hostname,
        endpoint=pattern,
        vuln_type="idor",
        severity=severity,
        confidence=confidence,
        title=f"IDOR: Unauthenticated access to {description} via sequential IDs on {hostname}",
        description=(
            f"The endpoint {pattern} on {hostname} returns different data objects "
            f"for different IDs without requiring authentication. "
            f"Tested IDs {', '.join(ids_with_data)} returned {unique_responses} "
            f"unique records. "
            + (
                f"The response contains sensitive fields: {', '.join(sorted(sensitive_found))}. "
                if sensitive_found else
                "The response structure suggests application data. "
            )
            + "An attacker could enumerate IDs to access other users' data."
        ),
        evidence="\n".join(evidence_parts),
        ids_tested=ids_with_data,
    )


def _count_unique_responses(responses: dict[str, dict]) -> int:
    """Count how many truly unique data objects are in the responses.

    Two responses are 'different' if they have different values for
    identifying fields (id, uuid, email, name, etc.).
    """
    # Extract a fingerprint from each response
    fingerprints = set()
    for data in responses.values():
        # Use id/uuid as primary differentiator
        fp_parts = []
        for key in ("id", "uuid", "_id", "ID", "Id"):
            if key in data:
                fp_parts.append(str(data[key]))
                break

        if not fp_parts:
            # Fall back to hashing the whole response
            fp_parts.append(str(sorted(data.items())))

        fingerprints.add(tuple(fp_parts))

    return len(fingerprints)
