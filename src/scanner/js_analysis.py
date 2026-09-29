"""JavaScript file analysis for exposed secrets and sensitive data.

JavaScript files deployed to production often contain hardcoded secrets,
API keys, internal URLs, and cloud credentials that developers intended
to keep private. These are high-value findings because they can lead to
account takeover, data breaches, or infrastructure compromise.

How it works:
  1. Discover JS file URLs from the target's HTML pages
  2. Fetch each JS file
  3. Scan content with regex patterns for known secret formats
  4. Validate findings to reduce false positives (entropy checks, context)
  5. Classify severity based on secret type

What we look for:
  - Cloud provider keys (AWS, GCP, Azure)
  - API keys and tokens (Stripe, Twilio, SendGrid, Slack, GitHub, etc.)
  - Private keys and certificates
  - Hardcoded passwords and credentials
  - Internal/private URLs and endpoints
  - JWT tokens and session secrets

Safety:
  - GET requests only — reads publicly served JS files
  - No modification, no authentication bypass
  - Only analyzes files already served to any visitor
  - Non-intrusive — same as viewing page source
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """A potential secret found in a JavaScript file."""

    url: str
    js_file: str
    vuln_type: str  # always "js_secret"
    secret_type: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str
    matched_value: str  # redacted version of the secret


@dataclass
class JSAnalysisResult:
    """Results of JavaScript analysis for a hostname."""

    hostname: str
    js_files_analyzed: int = 0
    findings: list[SecretFinding] = field(default_factory=list)


# ── Secret Patterns ──────────────────────────────────────────────────
# Each pattern: (name, regex, severity, min_entropy, description)
# min_entropy: minimum Shannon entropy to accept (filters out placeholders)

SECRET_PATTERNS = [
    # AWS
    (
        "AWS Access Key",
        r"(?:AKIA[0-9A-Z]{16})",
        "critical",
        3.0,
        "AWS IAM access key ID — can access AWS services",
    ),
    (
        "AWS Secret Key",
        r"(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "critical",
        4.0,
        "AWS secret access key — full AWS API access",
    ),

    # Google Cloud
    (
        "Google API Key",
        r"AIza[0-9A-Za-z_-]{35}",
        "high",
        3.5,
        "Google Cloud API key — may access GCP services",
    ),
    (
        "Google OAuth Client Secret",
        r"(?:client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{24})['\"]?",
        "high",
        3.5,
        "Google OAuth client secret",
    ),

    # Stripe
    (
        "Stripe Secret Key",
        r"sk_live_[0-9a-zA-Z]{24,}",
        "critical",
        3.0,
        "Stripe live secret key — can process payments",
    ),
    (
        "Stripe Publishable Key",
        r"pk_live_[0-9a-zA-Z]{24,}",
        "low",
        3.0,
        "Stripe publishable key — intended to be public, but confirms Stripe integration",
    ),

    # GitHub
    (
        "GitHub Token",
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "critical",
        3.0,
        "GitHub personal access token or OAuth token",
    ),

    # Slack
    (
        "Slack Token",
        r"xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{10,}",
        "high",
        3.0,
        "Slack API token — can access workspace data",
    ),
    (
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
        "medium",
        3.0,
        "Slack incoming webhook URL",
    ),

    # Twilio
    (
        "Twilio API Key",
        r"SK[0-9a-fA-F]{32}",
        "high",
        3.5,
        "Twilio API key",
    ),

    # SendGrid
    (
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "high",
        3.5,
        "SendGrid API key — can send emails",
    ),

    # Generic API keys / tokens
    (
        "Generic API Key",
        r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
        "medium",
        3.5,
        "Hardcoded API key",
    ),
    (
        "Generic Secret",
        r"(?:secret|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        "high",
        4.0,
        "Hardcoded secret or client secret",
    ),
    (
        "Generic Password",
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "high",
        3.5,
        "Hardcoded password",
    ),

    # Private keys
    (
        "Private Key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "critical",
        0.0,  # No entropy check needed — this is definitive
        "Private cryptographic key exposed in JS",
    ),

    # JWT
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "high",
        3.0,
        "JSON Web Token — may contain session or auth data",
    ),

    # Azure
    (
        "Azure Storage Key",
        r"(?:AccountKey|account_key)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{44,})['\"]?",
        "critical",
        4.0,
        "Azure Storage account key",
    ),

    # Internal URLs
    (
        "Internal URL",
        r"https?://(?:(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s'\"]*)?)",
        "medium",
        0.0,
        "Internal/private network URL exposed in JS",
    ),

    # Mailgun
    (
        "Mailgun API Key",
        r"key-[0-9a-zA-Z]{32}",
        "high",
        3.0,
        "Mailgun API key — can send emails",
    ),

    # Heroku
    (
        "Heroku API Key",
        r"(?:heroku_api_key|HEROKU_API_KEY)\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "high",
        3.5,
        "Heroku API key",
    ),
]

# Common JS file paths to check even if not found in HTML
COMMON_JS_PATHS = [
    "/main.js",
    "/app.js",
    "/bundle.js",
    "/vendor.js",
    "/config.js",
    "/env.js",
    "/settings.js",
    "/static/js/main.js",
    "/static/js/app.js",
    "/assets/js/app.js",
    "/dist/main.js",
    "/build/static/js/main.js",
]

# Known false positive values (placeholders, examples, test keys)
FALSE_POSITIVE_VALUES = {
    "your-api-key-here",
    "your_api_key_here",
    "xxx",
    "XXXX",
    "placeholder",
    "example",
    "test",
    "demo",
    "changeme",
    "INSERT_KEY_HERE",
    "YOUR_KEY_HERE",
    "TODO",
    "REPLACE_ME",
    "sk_test_",  # Stripe test keys (not real)
    "pk_test_",  # Stripe test publishable keys
}

THIRD_PARTY_REDIRECTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
]


def check_js_secrets(hostname: str) -> JSAnalysisResult:
    """Analyze JavaScript files from a hostname for exposed secrets.

    Safe: only fetches publicly served JS files via GET requests.
    """
    result = JSAnalysisResult(hostname=hostname)
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

    # Step 1: Discover JS files from the homepage
    js_urls = _discover_js_files(base_url)

    # Step 2: Add common JS paths (deduplicated)
    for path in COMMON_JS_PATHS:
        url = urljoin(base_url, path)
        if url not in js_urls:
            js_urls.add(url)

    if not js_urls:
        return result

    logger.debug("JS analysis: found %d JS URLs for %s", len(js_urls), hostname)

    # Step 3: Fetch and analyze each JS file
    for js_url in js_urls:
        result.js_files_analyzed += 1
        findings = _analyze_js_file(js_url, hostname)
        result.findings.extend(findings)

    if result.findings:
        logger.info(
            "JS analysis on %s: %d secrets found in %d files",
            hostname, len(result.findings), result.js_files_analyzed,
        )

    return result


def _discover_js_files(base_url: str) -> set[str]:
    """Extract JavaScript file URLs from the homepage HTML."""
    js_urls: set[str] = set()

    try:
        resp = httpx.get(
            base_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
        body = resp.text

        # Match <script src="..."> tags
        script_srcs = re.findall(
            r'<script[^>]*\bsrc=["\']([^"\']+\.js[^"\']*)["\']',
            body, re.IGNORECASE,
        )

        for src in script_srcs:
            # Skip external CDN scripts (we only analyze first-party JS)
            parsed = urlparse(src)
            if parsed.netloc and parsed.netloc != urlparse(base_url).netloc:
                continue

            full_url = urljoin(base_url, src)
            js_urls.add(full_url)

    except Exception as e:
        logger.debug("JS discovery failed for %s: %s", base_url, e)

    return js_urls


def _analyze_js_file(js_url: str, hostname: str) -> list[SecretFinding]:
    """Fetch a JS file and scan for secrets."""
    findings: list[SecretFinding] = []

    try:
        resp = httpx.get(
            js_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "Wintermute/0.1 (Security Research)"},
        )
    except Exception:
        return findings

    # Must be a JS file (not an error page)
    if resp.status_code != 200:
        return findings

    content_type = resp.headers.get("content-type", "").lower()
    if not any(ct in content_type for ct in (
        "javascript", "application/json", "text/plain", "application/x-javascript",
    )):
        # Some servers don't set content-type for JS, check by extension
        if not js_url.rstrip("?").endswith(".js"):
            return findings

    body = resp.text

    # Skip tiny responses (probably error pages)
    if len(body) < 100:
        return findings

    # Skip very large files to avoid regex performance issues
    if len(body) > 5_000_000:  # 5MB
        body = body[:5_000_000]

    js_filename = urlparse(js_url).path.split("/")[-1] or js_url

    for name, pattern, severity, min_entropy, description in SECRET_PATTERNS:
        matches = re.finditer(pattern, body)
        seen_values: set[str] = set()

        for match in matches:
            # Get the matched value (group 1 if captured, else group 0)
            value = match.group(1) if match.lastindex else match.group(0)

            # Skip duplicates within same file
            if value in seen_values:
                continue
            seen_values.add(value)

            # Skip known false positive placeholders
            if _is_false_positive(value, name):
                continue

            # Entropy check (filters out low-entropy placeholders)
            if min_entropy > 0 and _shannon_entropy(value) < min_entropy:
                continue

            # Get surrounding context for evidence
            start = max(0, match.start() - 60)
            end = min(len(body), match.end() + 60)
            context = body[start:end].replace("\n", " ").strip()

            # Skip JWT/tokens embedded in URLs as query parameters —
            # these are typically CDN signed URLs or OAuth redirects, not leaked credentials
            if name == "JWT Token":
                pre_context = body[max(0, match.start() - 30):match.start()]
                if re.search(r'[?&]token=\s*$', pre_context) or re.search(r'[?&]\w+=\s*$', pre_context):
                    if "/cdn" in context or "/image" in context or "/file" in context:
                        continue

            # Redact the actual secret value for safety
            redacted = _redact(value)

            findings.append(SecretFinding(
                url=js_url,
                js_file=js_filename,
                vuln_type="js_secret",
                secret_type=name,
                severity=severity,
                confidence=_calculate_confidence(name, value, min_entropy),
                title=f"{name} exposed in {js_filename} on {hostname}",
                description=(
                    f"{description}. Found in publicly accessible JavaScript file "
                    f"`{js_filename}` on `{hostname}`."
                ),
                evidence=(
                    f"File: {js_url}\n"
                    f"Secret type: {name}\n"
                    f"Value (redacted): {redacted}\n"
                    f"Context: ...{context}..."
                ),
                matched_value=redacted,
            ))

    return findings


def _is_false_positive(value: str, secret_type: str) -> bool:
    """Check if a matched value is a known false positive."""
    lower = value.lower().strip()

    # Check against known placeholder values
    for fp in FALSE_POSITIVE_VALUES:
        if fp.lower() in lower:
            return True

    # Stripe test keys are not real secrets
    if secret_type == "Stripe Secret Key" and value.startswith("sk_test_"):
        return True

    # Very short values are usually not real secrets
    if len(value) < 8 and secret_type not in ("Private Key", "Internal URL"):
        return True

    # All-same characters
    if len(set(value.replace("-", "").replace("_", ""))) <= 2:
        return True

    # Common programming patterns that aren't secrets
    if value in ("undefined", "null", "true", "false", "none", "empty"):
        return True

    # Internal URLs: localhost references are almost always URL-parsing fallbacks
    # in JS code (e.g., new URL(path, "http://localhost")), not real internal endpoints
    if secret_type == "Internal URL":
        if "localhost" in lower or "127.0.0.1" in lower:
            return True

    return False


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy = more random = more likely a real secret.
    Typical thresholds:
      - English text: ~3.5-4.5
      - Hex strings: ~3.5-4.0
      - Base64/random: ~4.5-6.0
      - Placeholder text: ~2.0-3.0
    """
    if not s:
        return 0.0

    counts = Counter(s)
    length = len(s)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def _calculate_confidence(secret_type: str, value: str, min_entropy: float) -> float:
    """Calculate confidence score based on secret type and value characteristics."""
    # Start with base confidence per type
    base_confidence = {
        "AWS Access Key": 0.90,       # Very specific format (AKIA...)
        "AWS Secret Key": 0.85,
        "Stripe Secret Key": 0.90,    # Very specific format (sk_live_...)
        "GitHub Token": 0.90,         # Very specific format (ghp_...)
        "Private Key": 0.95,          # Unmistakable
        "Slack Token": 0.85,          # Specific format (xox...)
        "SendGrid API Key": 0.85,     # Specific format (SG....)
        "Google API Key": 0.85,       # Specific format (AIza...)
        "JWT Token": 0.75,            # Could be expired/test
        "Internal URL": 0.70,         # Could be intentional
    }

    confidence = base_confidence.get(secret_type, 0.70)

    # Boost for high entropy (more random = more likely real)
    entropy = _shannon_entropy(value)
    if entropy > 4.5:
        confidence = min(confidence + 0.05, 0.95)
    elif entropy < 3.0 and min_entropy > 0:
        confidence = max(confidence - 0.10, 0.50)

    return confidence


def _redact(value: str) -> str:
    """Redact a secret value, showing only enough to identify it."""
    if len(value) <= 8:
        return value[:2] + "***"
    elif len(value) <= 20:
        return value[:4] + "..." + value[-4:]
    else:
        return value[:6] + "..." + value[-4:]
