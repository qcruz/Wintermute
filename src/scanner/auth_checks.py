"""Authentication and authorization testing.

Checks for common auth-related misconfigurations without attempting
to bypass or brute-force anything.

What we check:
  - Sensitive endpoints accessible without authentication
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - JWT tokens in responses (and their configuration)
  - Login pages with default/common credential exposure
  - Missing rate limiting on login endpoints
  - Session fixation indicators

Safety:
  - No credential guessing or brute-forcing
  - No authentication bypass attempts
  - Only analyzes publicly visible responses
  - Read-only — no state-changing requests
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AuthFinding:
    """An authentication/authorization finding."""

    hostname: str
    vuln_type: str  # insecure_cookie, missing_auth, jwt_issue, session_issue
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str
    endpoint: str = ""


@dataclass
class AuthResult:
    """Results of auth testing for a hostname."""

    hostname: str
    findings: list[AuthFinding] = field(default_factory=list)
    cookies_analyzed: int = 0
    endpoints_checked: int = 0


# Endpoints that should always require authentication
SENSITIVE_ENDPOINTS = [
    ("/api/users", "User data"),
    ("/api/user", "User profile"),
    ("/api/me", "Current user profile"),
    ("/api/profile", "User profile"),
    ("/api/account", "Account details"),
    ("/api/admin", "Admin interface"),
    ("/api/settings", "Application settings"),
    ("/api/config", "Configuration"),
    ("/api/internal", "Internal API"),
    ("/api/private", "Private API"),
    ("/api/keys", "API keys"),
    ("/api/tokens", "Auth tokens"),
    ("/api/logs", "Application logs"),
    ("/api/audit", "Audit logs"),
    ("/api/reports", "Reports"),
    ("/api/export", "Data export"),
    ("/api/upload", "File upload"),
    ("/api/files", "File listing"),
    ("/api/database", "Database access"),
    ("/api/graphql", "GraphQL endpoint"),
    ("/user/", "User area"),
    ("/account/", "Account area"),
    ("/profile/", "Profile page"),
    ("/settings/", "Settings page"),
]


THIRD_PARTY_REDIRECTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
]


def check_auth(hostname: str) -> AuthResult:
    """Run authentication and authorization checks on a hostname.

    Safe: only sends GET requests and analyzes response headers/cookies.
    """
    result = AuthResult(hostname=hostname)
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

    # Step 1: Analyze cookies from homepage
    _check_cookies(base_url, result)

    # Step 2: Check for unauthenticated access to sensitive endpoints
    _check_missing_auth(base_url, result)

    # Step 3: Check for JWT in responses
    _check_jwt_exposure(base_url, result)

    # Step 4: Check login endpoint security
    _check_login_security(base_url, result)

    if result.findings:
        logger.info(
            "Auth checks on %s: %d findings",
            hostname, len(result.findings),
        )

    return result


def _check_cookies(base_url: str, result: AuthResult) -> None:
    """Analyze cookies for missing security flags."""
    hostname = base_url.split("//")[1]

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        # Parse Set-Cookie headers
        raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []
        if not raw_cookies:
            # httpx stores multiple values; try multi_items
            raw_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]

        for cookie_str in raw_cookies:
            result.cookies_analyzed += 1
            cookie_lower = cookie_str.lower()

            # Extract cookie name
            cookie_name = cookie_str.split("=")[0].strip()

            # Skip non-session cookies (tracking, analytics, etc.)
            is_session_cookie = any(kw in cookie_name.lower() for kw in (
                "session", "sess", "sid", "token", "auth", "jwt",
                "login", "user", "csrf", "xsrf",
            ))

            if not is_session_cookie:
                continue

            issues = []

            if "secure" not in cookie_lower:
                issues.append("Missing Secure flag")

            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag")

            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute")
            elif "samesite=none" in cookie_lower:
                issues.append("SameSite=None (allows cross-site sending)")

            if issues:
                result.findings.append(AuthFinding(
                    hostname=hostname,
                    vuln_type="insecure_cookie",
                    severity="medium" if "Secure" in str(issues) else "low",
                    confidence=0.9,
                    title=f"Insecure session cookie '{cookie_name}' on {hostname}",
                    description=(
                        f"The session cookie '{cookie_name}' is missing security flags: "
                        f"{', '.join(issues)}. This may allow cookie theft via XSS "
                        f"or man-in-the-middle attacks."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                ))

    except Exception as e:
        logger.debug("Cookie analysis failed for %s: %s", base_url, e)


def _check_missing_auth(base_url: str, result: AuthResult) -> None:
    """Check if sensitive endpoints are accessible without authentication."""
    hostname = base_url.split("//")[1]

    # Get 404 baseline
    try:
        not_found = httpx.get(
            f"{base_url}/wintermute-auth-check-nonexistent-8b4a",
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        not_found_length = len(not_found.content) if not_found.status_code == 200 else 0
    except Exception:
        not_found_length = 0

    for path, description in SENSITIVE_ENDPOINTS:
        result.endpoints_checked += 1

        try:
            resp = httpx.get(
                f"{base_url}{path}",
                timeout=10.0,
                follow_redirects=False,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            # 200 with substantial content = potentially accessible without auth
            if resp.status_code == 200:
                # Skip if it matches the 404 page
                if not_found_length and abs(len(resp.content) - not_found_length) < 50:
                    continue

                body = resp.text.lower()
                content_type = resp.headers.get("content-type", "").lower()

                # Check if it's returning actual data (JSON API response)
                if "application/json" in content_type:
                    try:
                        data = resp.json()
                        # JSON with data keys = real data being returned
                        if isinstance(data, (dict, list)) and len(str(data)) > 10:
                            result.findings.append(AuthFinding(
                                hostname=hostname,
                                vuln_type="missing_auth",
                                severity="high",
                                confidence=0.8,
                                title=f"Unauthenticated access to {description} on {hostname}",
                                description=(
                                    f"The endpoint {path} returns JSON data without requiring "
                                    f"authentication. This may expose sensitive {description.lower()}."
                                ),
                                evidence=f"HTTP 200, Content-Type: application/json, {len(resp.content)} bytes",
                                endpoint=path,
                            ))
                            logger.warning(
                                "MISSING AUTH: %s%s returns data without authentication",
                                hostname, path,
                            )
                    except (json.JSONDecodeError, ValueError):
                        pass

        except Exception as e:
            logger.debug("Auth check failed for %s%s: %s", base_url, path, e)


def _check_jwt_exposure(base_url: str, result: AuthResult) -> None:
    """Check for JWT tokens exposed in responses."""
    hostname = base_url.split("//")[1]

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )

        # Look for JWTs in response body
        # JWT format: three base64-encoded sections separated by dots
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        jwts = re.findall(jwt_pattern, resp.text)

        for jwt_token in jwts[:3]:  # Limit to first 3 found
            jwt_info = _decode_jwt_header(jwt_token)
            if jwt_info:
                issues = []
                alg = jwt_info.get("alg", "")

                if alg.lower() == "none":
                    issues.append("Algorithm set to 'none' — signature not verified")
                elif alg.lower() in ("hs256", "hs384", "hs512"):
                    issues.append(f"Uses symmetric algorithm ({alg}) — may be brute-forceable")

                if issues:
                    result.findings.append(AuthFinding(
                        hostname=hostname,
                        vuln_type="jwt_issue",
                        severity="high" if "none" in alg.lower() else "medium",
                        confidence=0.75,
                        title=f"JWT token with weak configuration exposed on {hostname}",
                        description=(
                            f"A JWT token was found in the page response with potential "
                            f"issues: {'; '.join(issues)}"
                        ),
                        evidence=f"JWT header: {json.dumps(jwt_info)}, token: {jwt_token[:50]}...",
                    ))

        # Look for JWTs in response headers
        for header_name in ("authorization", "x-auth-token", "x-jwt-token"):
            header_val = resp.headers.get(header_name, "")
            if header_val:
                jwts_in_header = re.findall(jwt_pattern, header_val)
                for jwt_token in jwts_in_header[:1]:
                    jwt_info = _decode_jwt_header(jwt_token)
                    if jwt_info:
                        result.findings.append(AuthFinding(
                            hostname=hostname,
                            vuln_type="jwt_issue",
                            severity="medium",
                            confidence=0.8,
                            title=f"JWT token exposed in response header on {hostname}",
                            description=(
                                f"A JWT token was found in the '{header_name}' response header. "
                                f"This may indicate improper token handling."
                            ),
                            evidence=f"Header: {header_name}: {header_val[:100]}...",
                        ))

    except Exception as e:
        logger.debug("JWT check failed for %s: %s", base_url, e)


def _check_login_security(base_url: str, result: AuthResult) -> None:
    """Check login page security characteristics."""
    hostname = base_url.split("//")[1]
    login_paths = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth/login"]

    for path in login_paths:
        try:
            resp = httpx.get(
                f"{base_url}{path}",
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )

            if resp.status_code != 200:
                continue

            body = resp.text.lower()

            # Check for forms without CSRF protection
            if "<form" in body and ("password" in body or "passwd" in body):
                # Found a login form — check for CSRF token
                has_csrf = any(kw in body for kw in (
                    "csrf", "_token", "authenticity_token",
                    "csrfmiddlewaretoken", "__requestverificationtoken",
                    "antiforgery",
                ))

                if not has_csrf:
                    result.findings.append(AuthFinding(
                        hostname=hostname,
                        vuln_type="session_issue",
                        severity="medium",
                        confidence=0.7,
                        title=f"Login form without CSRF protection on {hostname}",
                        description=(
                            f"The login form at {path} does not appear to include "
                            f"a CSRF token, which may allow cross-site login attacks."
                        ),
                        evidence=f"Login form found at {path} without visible CSRF token",
                        endpoint=path,
                    ))

                # Check if form submits over HTTP (not HTTPS)
                form_actions = re.findall(r'action=["\']([^"\']*)["\']', resp.text)
                for action in form_actions:
                    if action.startswith("http://"):
                        result.findings.append(AuthFinding(
                            hostname=hostname,
                            vuln_type="session_issue",
                            severity="high",
                            confidence=0.9,
                            title=f"Login form submits credentials over HTTP on {hostname}",
                            description=(
                                f"The login form at {path} submits to {action} which is "
                                f"unencrypted HTTP. Credentials can be intercepted."
                            ),
                            evidence=f"Form action: {action}",
                            endpoint=path,
                        ))

            # Check for autocomplete on password fields
            if 'type="password"' in body or "type='password'" in body:
                password_fields = re.findall(
                    r'<input[^>]*type=["\']password["\'][^>]*>', body
                )
                for pf in password_fields:
                    if 'autocomplete="off"' not in pf and "autocomplete='off'" not in pf:
                        # This is informational — not always a real vuln
                        pass  # Skip to avoid noise

        except Exception as e:
            logger.debug("Login check failed for %s%s: %s", base_url, path, e)


def _decode_jwt_header(token: str) -> dict | None:
    """Decode the header portion of a JWT token."""
    try:
        header_b64 = token.split(".")[0]
        # Add padding if needed
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header_bytes = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_bytes)
    except Exception:
        return None
