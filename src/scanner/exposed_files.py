"""Exposed sensitive file detection.

Checks for files that should never be publicly accessible: version
control directories, environment files, backups, admin panels, etc.

How it works:
  We request a list of known sensitive paths and check if they return
  content that matches expected patterns. A simple 200 status isn't
  enough — many sites return custom 404 pages with 200 status codes,
  so we verify the actual content.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ExposedFileCheck:
    """Result of checking for a single exposed file."""

    path: str
    found: bool = False
    status_code: int = 0
    content_length: int = 0
    evidence: str = ""
    severity: str = "info"


@dataclass
class ExposedFilesResult:
    """Results of checking all sensitive paths for a hostname."""

    hostname: str
    findings: list[ExposedFileCheck] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return sum(1 for f in self.findings if f.found)


# Sensitive paths to check.
# Each: (path, description, content_fingerprints, severity)
# content_fingerprints: strings that MUST be in the response body to confirm.
# If empty, we just check for 200 status (higher false positive rate).
SENSITIVE_PATHS = [
    # Version control
    (
        "/.git/config",
        "Git repository configuration",
        ["[core]", "[remote", "repositoryformatversion"],
        "high",
    ),
    (
        "/.git/HEAD",
        "Git HEAD reference",
        ["ref: refs/"],
        "high",
    ),
    (
        "/.svn/entries",
        "SVN repository metadata",
        ["dir", "svn"],
        "high",
    ),
    # Environment and config
    (
        "/.env",
        "Environment variables (may contain secrets)",
        # Look for common .env patterns, not just "=" which matches everything
        ["db_", "api_key", "secret", "password", "token", "database_url", "app_key"],
        "critical",
    ),
    (
        "/.env.backup",
        "Environment file backup",
        ["db_", "api_key", "secret", "password", "token", "database_url", "app_key"],
        "critical",
    ),
    (
        "/config.php.bak",
        "PHP config backup",
        ["<?php", "config"],
        "critical",
    ),
    # macOS artifacts
    (
        "/.DS_Store",
        "macOS directory metadata (reveals file listing)",
        [],  # Binary file, just check status + content type
        "low",
    ),
    # Server status
    (
        "/server-status",
        "Apache server status page",
        ["apache", "server status"],
        "medium",
    ),
    (
        "/server-info",
        "Apache server info page",
        ["apache", "server information"],
        "medium",
    ),
    # Debug and info pages
    (
        "/phpinfo.php",
        "PHP info page (reveals server config)",
        ["phpinfo", "php version"],
        "medium",
    ),
    (
        "/info.php",
        "PHP info page",
        ["phpinfo", "php version"],
        "medium",
    ),
    (
        "/debug",
        "Debug endpoint",
        [],
        "medium",
    ),
    # Backups
    (
        "/backup.zip",
        "Site backup archive",
        [],
        "critical",
    ),
    (
        "/backup.tar.gz",
        "Site backup archive",
        [],
        "critical",
    ),
    (
        "/database.sql",
        "Database dump",
        ["create table", "insert into"],
        "critical",
    ),
    (
        "/db.sql",
        "Database dump",
        ["create table", "insert into"],
        "critical",
    ),
    # Metadata
    (
        "/robots.txt",
        "Robots.txt (may reveal hidden paths)",
        ["user-agent", "disallow"],
        "info",
    ),
    (
        "/.well-known/security.txt",
        "Security contact information",
        ["contact:"],
        "info",
    ),
    (
        "/crossdomain.xml",
        "Flash crossdomain policy",
        ["cross-domain-policy"],
        "low",
    ),
    # Admin panels
    (
        "/wp-login.php",
        "WordPress login page",
        ["wp-login", "wordpress"],
        "info",
    ),
    (
        "/administrator/",
        "Joomla admin panel",
        ["joomla", "administrator"],
        "info",
    ),
]


def check_exposed_files(hostname: str) -> ExposedFilesResult:
    """Check a hostname for exposed sensitive files.

    Sends one GET request per path. Uses content fingerprinting to
    reduce false positives from custom 404 pages.
    """
    result = ExposedFilesResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # First, get the custom 404 response to compare against
    not_found_body, not_found_length = _get_404_body(base_url)

    for path, description, fingerprints, severity in SENSITIVE_PATHS:
        check = ExposedFileCheck(path=path, severity=severity)

        try:
            response = httpx.get(
                f"{base_url}{path}",
                timeout=10.0,
                follow_redirects=False,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )
            check.status_code = response.status_code
            check.content_length = len(response.content)

            if response.status_code == 200:
                body = response.text.lower()

                # Skip if response is identical to custom 404
                if not_found_body and body == not_found_body:
                    continue

                # Skip if content length matches the 404 page (soft match
                # for sites that include dynamic elements like timestamps)
                if not_found_length and abs(check.content_length - not_found_length) < 50:
                    continue

                if fingerprints:
                    # Check for content fingerprints
                    matched = [fp for fp in fingerprints if fp.lower() in body]
                    if matched:
                        check.found = True
                        check.evidence = (
                            f"{description} — matched: {', '.join(matched)}"
                        )
                        logger.warning(
                            "EXPOSED FILE: %s%s (%s)", hostname, path, description
                        )
                else:
                    # No fingerprints — check for non-trivial content
                    if check.content_length > 0:
                        check.found = True
                        check.evidence = f"{description} — {check.content_length} bytes"

            elif response.status_code == 403:
                # 403 Forbidden — file exists but is protected (not a finding,
                # but interesting to note)
                pass

        except Exception as e:
            logger.debug("File check failed for %s%s: %s", hostname, path, e)
            continue

        if check.found:
            result.findings.append(check)

    return result


def _get_404_body(base_url: str) -> tuple[str, int]:
    """Fetch a definitely-nonexistent path to identify custom 404 pages.

    Many sites return 200 status for everything with a custom "not found"
    page. We need to detect this to avoid false positives.

    Returns (body_text, content_length) for comparison.
    """
    try:
        response = httpx.get(
            f"{base_url}/wintermute-definitely-does-not-exist-abc123xyz",
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        if response.status_code == 200:
            return response.text.lower(), len(response.content)
    except Exception:
        pass
    return "", 0


def check_many(hostnames: list[str]) -> list[ExposedFilesResult]:
    """Check multiple hostnames for exposed files."""
    return [check_exposed_files(h) for h in hostnames]
