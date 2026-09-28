"""Active content discovery — find hidden endpoints, API paths, and admin panels.

Instead of just checking a small list of known files (like exposed_files.py does),
this module actively probes for:
  - API documentation endpoints (Swagger, GraphQL, OpenAPI)
  - Common API path patterns (/api/v1/, /api/v2/, etc.)
  - Admin and management interfaces
  - Development/staging artifacts
  - Interesting paths revealed by robots.txt

How it works:
  1. Parse robots.txt Disallow entries for path leads
  2. Probe a curated wordlist of high-value paths
  3. Fingerprint responses to distinguish real pages from custom 404s
  4. Classify findings by type and severity
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint worth investigating."""

    path: str
    status_code: int = 0
    content_length: int = 0
    category: str = ""  # api, admin, debug, docs, config, dev
    description: str = ""
    severity: str = "info"
    evidence: str = ""
    redirect_url: str = ""


@dataclass
class ContentDiscoveryResult:
    """Results of active content discovery for a hostname."""

    hostname: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    robots_paths: list[str] = field(default_factory=list)

    @property
    def interesting_count(self) -> int:
        return len(self.endpoints)


# High-value paths organized by category.
# Each: (path, category, description, fingerprints, severity)
# fingerprints: if non-empty, body must contain at least one to confirm
DISCOVERY_PATHS = [
    # ── API Documentation ──────────────────────────────────────────
    ("/swagger-ui.html", "api_docs", "Swagger UI", ["swagger-ui"], "medium"),
    ("/swagger-ui/", "api_docs", "Swagger UI", ["swagger-ui"], "medium"),
    ("/swagger.json", "api_docs", "Swagger/OpenAPI spec", ['"swagger"', '"openapi"'], "medium"),
    ("/api-docs", "api_docs", "API documentation", ["api", "endpoint"], "medium"),
    ("/api-docs/swagger.json", "api_docs", "Swagger spec", ['"swagger"', '"openapi"'], "medium"),
    ("/openapi.json", "api_docs", "OpenAPI specification", ['"openapi"'], "medium"),
    ("/openapi.yaml", "api_docs", "OpenAPI specification", ["openapi"], "medium"),
    ("/v2/api-docs", "api_docs", "Spring Boot API docs v2", ['"swagger"'], "medium"),
    ("/v3/api-docs", "api_docs", "Spring Boot API docs v3", ['"openapi"'], "medium"),
    ("/redoc", "api_docs", "ReDoc API documentation", ["redoc"], "medium"),
    ("/docs", "api_docs", "API documentation", [], "info"),
    ("/docs/api", "api_docs", "API documentation", [], "info"),

    # ── GraphQL ────────────────────────────────────────────────────
    ("/graphql", "api", "GraphQL endpoint", [], "medium"),
    ("/graphiql", "api_docs", "GraphiQL IDE", ["graphiql"], "high"),
    ("/graphql/console", "api_docs", "GraphQL console", ["graphql"], "high"),
    ("/playground", "api_docs", "GraphQL Playground", ["playground", "graphql"], "high"),
    ("/altair", "api_docs", "Altair GraphQL client", ["altair"], "high"),

    # ── Common API Paths ───────────────────────────────────────────
    ("/api/", "api", "API root", [], "info"),
    ("/api/v1/", "api", "API v1 root", [], "info"),
    ("/api/v2/", "api", "API v2 root", [], "info"),
    ("/api/v3/", "api", "API v3 root", [], "info"),
    ("/api/health", "api", "Health check endpoint", ["status", "ok", "healthy"], "info"),
    ("/api/healthz", "api", "Health check endpoint", ["ok", "healthy"], "info"),
    ("/api/status", "api", "Status endpoint", ["status"], "info"),
    ("/api/version", "api", "Version endpoint", ["version"], "low"),
    ("/api/config", "api", "Config endpoint", ["config"], "high"),
    ("/api/debug", "api", "Debug endpoint", ["debug"], "high"),
    ("/api/users", "api", "Users endpoint", [], "medium"),
    ("/api/admin", "api", "Admin API", [], "high"),
    ("/api/internal", "api", "Internal API", [], "high"),

    # ── Admin / Management ─────────────────────────────────────────
    ("/admin/", "admin", "Admin panel", [], "medium"),
    ("/admin/login", "admin", "Admin login page", ["login", "password", "sign in"], "medium"),
    ("/dashboard/", "admin", "Dashboard", ["dashboard"], "medium"),
    ("/manage/", "admin", "Management interface", [], "medium"),
    ("/manager/html", "admin", "Tomcat Manager", ["tomcat", "manager"], "high"),
    ("/console/", "admin", "Web console", ["console"], "medium"),
    ("/portal/", "admin", "Portal interface", [], "info"),
    ("/cpanel/", "admin", "cPanel interface", ["cpanel"], "high"),
    ("/phpmyadmin/", "admin", "phpMyAdmin", ["phpmyadmin"], "critical"),
    ("/adminer.php", "admin", "Adminer DB manager", ["adminer", "login"], "critical"),
    ("/wp-admin/", "admin", "WordPress admin", ["wordpress", "wp-admin"], "info"),

    # ── Development / Debug ────────────────────────────────────────
    ("/actuator", "debug", "Spring Boot Actuator", ["actuator", "_links"], "high"),
    ("/actuator/env", "debug", "Spring Boot env vars", ["property"], "critical"),
    ("/actuator/health", "debug", "Spring Boot health", ["status"], "low"),
    ("/actuator/info", "debug", "Spring Boot info", [], "medium"),
    ("/actuator/mappings", "debug", "Spring Boot URL mappings", ["mappings"], "high"),
    ("/actuator/configprops", "debug", "Spring Boot config", ["properties"], "critical"),
    ("/actuator/beans", "debug", "Spring Boot beans", ["beans"], "medium"),
    ("/_debug/", "debug", "Debug interface", [], "high"),
    ("/__debug__/", "debug", "Debug toolbar", ["debug"], "high"),
    ("/trace", "debug", "Trace endpoint", ["trace"], "medium"),
    ("/metrics", "debug", "Metrics endpoint", ["metric"], "low"),
    ("/prometheus", "debug", "Prometheus metrics", ["# HELP", "# TYPE"], "medium"),
    ("/metrics/prometheus", "debug", "Prometheus metrics", ["# HELP", "# TYPE"], "medium"),
    ("/.debug/", "debug", "Debug directory", [], "high"),
    ("/debug/vars", "debug", "Go debug variables", ["cmdline", "memstats"], "high"),
    ("/debug/pprof/", "debug", "Go pprof profiling", ["pprof"], "high"),
    ("/elmah.axd", "debug", "ELMAH error log (.NET)", ["elmah", "error"], "high"),

    # ── Configuration & Metadata ───────────────────────────────────
    ("/sitemap.xml", "config", "Sitemap", ["<urlset", "<sitemapindex"], "info"),
    ("/.well-known/openid-configuration", "config", "OpenID config", ["issuer", "authorization_endpoint"], "low"),
    ("/.well-known/jwks.json", "config", "JSON Web Key Set", ['"keys"', '"kty"'], "low"),
    ("/manifest.json", "config", "Web app manifest", ["name", "start_url"], "info"),
    ("/package.json", "config", "Node.js package file", ['"name"', '"version"', '"dependencies"'], "medium"),
    ("/composer.json", "config", "PHP Composer file", ['"require"'], "medium"),
    ("/Gemfile", "config", "Ruby Gemfile", ["gem ", "source"], "medium"),
    ("/requirements.txt", "config", "Python requirements", ["=="], "low"),
    ("/wp-json/wp/v2/users", "config", "WordPress user enumeration", ['"id"', '"name"', '"slug"'], "medium"),
    ("/feed/", "config", "RSS/Atom feed", ["<rss", "<feed", "<channel"], "info"),

    # ── Staging / Dev artifacts ────────────────────────────────────
    ("/staging/", "dev", "Staging environment", [], "medium"),
    ("/test/", "dev", "Test environment", [], "low"),
    ("/beta/", "dev", "Beta environment", [], "info"),
    ("/dev/", "dev", "Development environment", [], "medium"),
    ("/.well-known/change-password", "config", "Password change endpoint", [], "info"),

    # ── Source Maps & Build artifacts ──────────────────────────────
    ("/main.js.map", "dev", "JavaScript source map", ['"sources"', '"mappings"'], "medium"),
    ("/app.js.map", "dev", "JavaScript source map", ['"sources"', '"mappings"'], "medium"),
    ("/bundle.js.map", "dev", "JavaScript source map", ['"sources"', '"mappings"'], "medium"),
]


def discover_content(hostname: str, max_paths: int = 30) -> ContentDiscoveryResult:
    """Actively discover hidden endpoints and API paths on a hostname.

    Safe: only sends GET requests with standard headers.

    Args:
        max_paths: Maximum number of paths to probe (default 30 for speed).
                   High-value paths are checked first.
    """
    result = ContentDiscoveryResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # Step 1: Get custom 404 baseline
    not_found_body, not_found_length, baseline_status = _get_404_baseline(base_url)

    # Early exit: blanket-403 hosts return Forbidden for every path
    if baseline_status == 403:
        logger.debug("Skipping content discovery on %s — blanket 403 on all paths", hostname)
        return result

    # Step 2: Early exit — detect third-party hosted sites
    # If the first probe redirects to a known third-party login, skip this host
    third_party = _detect_third_party(base_url)
    if third_party:
        logger.debug("Skipping content discovery on %s — third-party hosted (%s)", hostname, third_party)
        return result

    # Step 3: Parse robots.txt for additional paths
    robots_paths = _parse_robots_disallow(base_url)
    result.robots_paths = robots_paths

    # Step 4: Build prioritized path list (high-severity first)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_checks = sorted(DISCOVERY_PATHS, key=lambda p: severity_rank.get(p[4], 5))

    # Add robots.txt paths at the end
    for rpath in robots_paths:
        if rpath not in {p[0] for p in DISCOVERY_PATHS}:
            all_checks.append(
                (rpath, "robots_hidden", f"Path hidden in robots.txt: {rpath}", [], "low")
            )

    # Step 5: Probe paths (capped at max_paths for speed)
    for path, category, description, fingerprints, severity in all_checks[:max_paths]:
        endpoint = _probe_path(
            base_url, path, category, description, fingerprints, severity,
            not_found_body, not_found_length,
        )
        if endpoint:
            result.endpoints.append(endpoint)

    if result.endpoints:
        logger.info(
            "Content discovery on %s: found %d interesting endpoints",
            hostname, len(result.endpoints),
        )

    return result


THIRD_PARTY_REDIRECTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
    "idp.secureworks.com",
]


def _detect_third_party(base_url: str) -> str:
    """Check if this host redirects everything to a third-party login.

    If so, content discovery is pointless — every path will just redirect.
    Returns the third-party domain name, or empty string if not detected.
    """
    try:
        resp = httpx.get(
            f"{base_url}/wintermute-third-party-check",
            timeout=8.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "").lower()
            for domain in THIRD_PARTY_REDIRECTS:
                if domain in location:
                    return domain
    except Exception:
        pass
    return ""


def _get_404_baseline(base_url: str) -> tuple[str, int, int]:
    """Get the custom 404 response for comparison.

    Returns (body, content_length, status_code). The status_code is used to
    detect blanket-403 hosts where every path returns Forbidden.
    """
    try:
        resp = httpx.get(
            f"{base_url}/wintermute-nonexistent-path-7f3a9b2c",
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if resp.status_code == 200:
            return resp.text.lower(), len(resp.content), 200
        return "", 0, resp.status_code
    except Exception:
        pass
    return "", 0, 0


def _parse_robots_disallow(base_url: str) -> list[str]:
    """Parse robots.txt for Disallow entries that might reveal hidden paths."""
    paths = []
    try:
        resp = httpx.get(
            f"{base_url}/robots.txt",
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if resp.status_code != 200:
            return paths

        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                # Skip wildcards and empty paths
                if path and "*" not in path and path != "/":
                    paths.append(path)

    except Exception:
        pass

    return paths


def _probe_path(
    base_url: str,
    path: str,
    category: str,
    description: str,
    fingerprints: list[str],
    severity: str,
    not_found_body: str,
    not_found_length: int,
) -> DiscoveredEndpoint | None:
    """Probe a single path and determine if it's interesting."""
    try:
        resp = httpx.get(
            f"{base_url}{path}",
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
    except Exception:
        return None

    endpoint = DiscoveredEndpoint(
        path=path,
        status_code=resp.status_code,
        content_length=len(resp.content),
        category=category,
        description=description,
        severity=severity,
    )

    # Handle redirects — interesting if redirecting to a login page
    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("location", "")
        if location:
            endpoint.redirect_url = location
            # Admin/API paths that redirect to login are confirmed to exist
            if any(kw in location.lower() for kw in ("login", "signin", "auth", "sso")):
                endpoint.evidence = f"Redirects to login: {location}"
                if category in ("admin", "api", "debug"):
                    logger.warning(
                        "CONTENT DISCOVERY: %s%s → redirects to login (%s)",
                        base_url.split("//")[1], path, location,
                    )
                    return endpoint
        return None

    if resp.status_code == 403:
        # 403 = path exists but is protected — notable for admin/debug paths
        if category in ("admin", "api", "debug", "api_docs"):
            endpoint.evidence = f"HTTP 403 Forbidden — endpoint exists but is access-restricted"
            endpoint.severity = "low"  # Downgrade since it's protected
            return endpoint
        return None

    if resp.status_code != 200:
        return None

    body = resp.text.lower()

    # Skip if matches custom 404
    if not_found_body and body == not_found_body:
        return None
    if not_found_length and abs(endpoint.content_length - not_found_length) < 50:
        return None

    # Fingerprint check
    if fingerprints:
        matched = [fp for fp in fingerprints if fp.lower() in body]
        if matched:
            endpoint.evidence = f"Content fingerprint matched: {', '.join(matched)}"
            logger.warning(
                "CONTENT DISCOVERY: %s%s (%s)",
                base_url.split("//")[1], path, description,
            )
            return endpoint
        # Had fingerprints but none matched — likely false positive
        return None

    # No fingerprints — for high-value categories, a 200 response is notable
    if category in ("api", "admin", "debug", "api_docs") and endpoint.content_length > 0:
        endpoint.evidence = f"HTTP 200, {endpoint.content_length} bytes"
        # Lower confidence without fingerprint match
        endpoint.severity = "low" if endpoint.severity in ("info", "low") else "low"
        return endpoint

    return None
