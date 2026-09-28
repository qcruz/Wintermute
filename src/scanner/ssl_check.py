"""SSL/TLS certificate and configuration analysis.

Checks for expired certificates, weak TLS versions, and hostname
mismatches. These are easy to verify and straightforward to report.

How it works:
  We connect to the server over TLS and examine the certificate it
  presents. We also check which TLS versions the server supports.
  This is the same thing your browser does — completely safe.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class SSLCheck:
    """Result of an SSL/TLS analysis."""

    hostname: str
    issues: list[str] = field(default_factory=list)
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    days_until_expiry: int | None = None
    tls_version: str = ""
    confidence: float = 0.0
    has_ssl: bool = False


def check_ssl(hostname: str, port: int = 443) -> SSLCheck:
    """Analyze SSL/TLS configuration for a hostname.

    Checks:
      1. Certificate validity and expiration
      2. Certificate hostname match
      3. TLS version in use
    """
    result = SSLCheck(hostname=hostname)

    # Step 1: Connect and get certificate info
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result.has_ssl = True
                result.tls_version = ssock.version() or ""

                cert = ssock.getpeercert()
                if not cert:
                    result.issues.append("No certificate presented")
                    result.confidence = 0.9
                    return result

                # Parse certificate details
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                result.cert_subject = subject.get("commonName", "")
                result.cert_issuer = issuer.get("organizationName", "")

                # Check expiration
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    delta = expiry - now
                    result.days_until_expiry = delta.days
                    result.cert_expiry = not_after

                    if delta.days < 0:
                        result.issues.append(
                            f"Certificate EXPIRED {abs(delta.days)} days ago"
                        )
                        result.confidence = max(result.confidence, 0.95)
                    elif delta.days < 30:
                        result.issues.append(
                            f"Certificate expires in {delta.days} days"
                        )
                        result.confidence = max(result.confidence, 0.6)

    except ssl.SSLCertVerificationError as e:
        result.has_ssl = True
        error_msg = str(e)

        if "hostname mismatch" in error_msg.lower():
            result.issues.append(f"Certificate hostname mismatch: {error_msg}")
            result.confidence = max(result.confidence, 0.9)
        elif "certificate has expired" in error_msg.lower():
            result.issues.append("Certificate has expired (SSL verification failed)")
            result.confidence = max(result.confidence, 0.95)
        elif "self-signed" in error_msg.lower() or "self signed" in error_msg.lower():
            result.issues.append("Self-signed certificate")
            result.confidence = max(result.confidence, 0.8)
        else:
            result.issues.append(f"SSL verification error: {error_msg}")
            result.confidence = max(result.confidence, 0.7)

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("SSL connection failed for %s: %s", hostname, e)
        return result

    # Step 2: Check for weak TLS versions
    for version_name, protocol in [
        ("TLSv1.0", ssl.PROTOCOL_TLS),
        ("TLSv1.1", ssl.PROTOCOL_TLS),
    ]:
        if _supports_weak_tls(hostname, port, version_name):
            result.issues.append(f"Supports deprecated {version_name}")
            result.confidence = max(result.confidence, 0.85)

    if result.issues:
        logger.info(
            "SSL issues for %s: %s", hostname, "; ".join(result.issues)
        )

    return result


def _supports_weak_tls(hostname: str, port: int, version: str) -> bool:
    """Test if a server accepts a specific weak TLS version."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if version == "TLSv1.0":
            context.maximum_version = ssl.TLSVersion.TLSv1
            context.minimum_version = ssl.TLSVersion.TLSv1
        elif version == "TLSv1.1":
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            context.minimum_version = ssl.TLSVersion.TLSv1_1

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def check_many(hostnames: list[str]) -> list[SSLCheck]:
    """Check multiple hostnames for SSL/TLS issues."""
    return [check_ssl(h) for h in hostnames]
