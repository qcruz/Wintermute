"""GraphQL introspection and schema analysis.

GraphQL APIs sometimes leave introspection enabled in production, which
exposes the entire schema — every type, query, mutation, and field. This
is valuable for attackers because it reveals internal data models, admin
operations, and potentially sensitive mutations.

How it works:
  1. Probe common GraphQL endpoint paths (GET and POST)
  2. Send the standard introspection query (__schema)
  3. If introspection succeeds, analyze the schema:
     - Count total types, queries, and mutations
     - Flag sensitive mutations (delete, admin, password, role, etc.)
     - Flag sensitive queries exposing user/account data
  4. Test whether introspection is accessible without authentication

What we test for:
  - Introspection enabled in production
  - Sensitive mutations exposed (user management, admin ops, payments)
  - Sensitive queries exposed (user data, internal records)
  - Unauthenticated schema access

Safety:
  - Only sends GET/POST requests with the standard introspection query
  - Never calls any mutations or modifies data
  - Only reads schema metadata, not actual data
  - Non-destructive — introspection is a read-only GraphQL feature
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GraphQLFinding:
    """A GraphQL security finding."""

    url: str
    vuln_type: str  # always "graphql_introspection"
    title: str
    severity: str
    confidence: float
    description: str
    evidence: str


@dataclass
class GraphQLResult:
    """Results of GraphQL introspection testing for a hostname."""

    hostname: str
    endpoints_tested: int = 0
    introspection_enabled: bool = False
    findings: list[GraphQLFinding] = field(default_factory=list)


# ── GraphQL endpoint paths to probe ────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
]

# ── Introspection query ────────────────────────────────────────────

INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
      }
    }
  }
}"""

# ── Sensitive patterns ─────────────────────────────────────────────
# Field/type names that suggest sensitive operations or data.

SENSITIVE_MUTATION_PATTERNS = [
    (r"(?i)(delete|remove|destroy).*user", "User deletion"),
    (r"(?i)(create|add|invite).*admin", "Admin creation"),
    (r"(?i)(update|change|reset).*password", "Password modification"),
    (r"(?i)(update|change|set).*role", "Role modification"),
    (r"(?i)(delete|remove|purge).*account", "Account deletion"),
    (r"(?i)(transfer|withdraw|pay|charge)", "Financial operation"),
    (r"(?i)(grant|revoke).*permission", "Permission modification"),
    (r"(?i)(disable|enable|ban|suspend).*user", "User status modification"),
    (r"(?i)(upload|import).*file", "File upload"),
    (r"(?i)(execute|run|eval)", "Code execution"),
]

SENSITIVE_QUERY_PATTERNS = [
    (r"(?i)^users?$", "User listing"),
    (r"(?i)^admin", "Admin data"),
    (r"(?i)(password|credential|secret|token)", "Credential data"),
    (r"(?i)(payment|billing|invoice|transaction)", "Financial data"),
    (r"(?i)(internal|private|debug)", "Internal data"),
    (r"(?i)^logs?$", "Log access"),
    (r"(?i)(config|setting|preference)", "Configuration data"),
]

THIRD_PARTY_REDIRECTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
]

HEADERS = {"User-Agent": "Wintermute/0.1 (Security Research)"}


def check_graphql(hostname: str) -> GraphQLResult:
    """Test a hostname for GraphQL introspection vulnerabilities.

    Safe: only sends introspection queries, never calls mutations.
    """
    result = GraphQLResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # Early exit: skip third-party hosted sites
    try:
        probe = httpx.get(
            base_url, timeout=8.0, follow_redirects=False, headers=HEADERS,
        )
        if probe.status_code in (301, 302, 303, 307, 308):
            location = probe.headers.get("location", "").lower()
            if any(d in location for d in THIRD_PARTY_REDIRECTS):
                return result
    except Exception:
        pass

    # Probe each GraphQL path
    for path in GRAPHQL_PATHS:
        result.endpoints_tested += 1
        schema = _try_introspection(base_url, path)
        if schema is None:
            continue

        result.introspection_enabled = True

        # Analyze the schema
        analysis = _analyze_schema(schema)

        # Build finding
        sensitive_items = analysis["sensitive_mutations"] + analysis["sensitive_queries"]
        severity = _determine_severity(analysis)
        confidence = _determine_confidence(analysis)

        evidence_lines = [
            f"Endpoint: {base_url}{path}",
            f"Total types: {analysis['type_count']}",
            f"Queries: {analysis['query_count']}",
            f"Mutations: {analysis['mutation_count']}",
        ]

        if analysis["sensitive_mutations"]:
            evidence_lines.append("\nSensitive mutations found:")
            for name, category in analysis["sensitive_mutations"]:
                evidence_lines.append(f"  - {name} ({category})")

        if analysis["sensitive_queries"]:
            evidence_lines.append("\nSensitive queries found:")
            for name, category in analysis["sensitive_queries"]:
                evidence_lines.append(f"  - {name} ({category})")

        description = (
            f"GraphQL introspection is enabled on {base_url}{path}, "
            f"exposing the full API schema ({analysis['type_count']} types, "
            f"{analysis['query_count']} queries, {analysis['mutation_count']} mutations). "
        )

        if sensitive_items:
            description += (
                f"The schema contains {len(sensitive_items)} sensitive "
                f"operation(s) including: "
                + ", ".join(f"{name} ({cat})" for name, cat in sensitive_items[:5])
                + ("..." if len(sensitive_items) > 5 else "")
                + "."
            )
        else:
            description += (
                "While no obviously sensitive operations were found, the exposed "
                "schema gives attackers a complete map of the API surface."
            )

        result.findings.append(GraphQLFinding(
            url=f"{base_url}{path}",
            vuln_type="graphql_introspection",
            title=f"GraphQL Introspection Enabled on {hostname}{path}",
            severity=severity,
            confidence=confidence,
            description=description,
            evidence="\n".join(evidence_lines),
        ))

        # One finding per host is enough — don't test remaining paths
        break

    if result.findings:
        logger.info(
            "GraphQL testing on %s: introspection enabled, %d finding(s)",
            hostname, len(result.findings),
        )

    return result


def _try_introspection(base_url: str, path: str) -> dict | None:
    """Attempt GraphQL introspection via POST then GET."""

    url = f"{base_url}{path}"

    # Try POST with JSON body (most common)
    try:
        resp = httpx.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            timeout=10.0,
            follow_redirects=True,
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        schema = _extract_schema(resp)
        if schema:
            return schema
    except Exception:
        pass

    # Try GET with query parameter
    try:
        get_url = f"{url}?{urlencode({'query': INTROSPECTION_QUERY})}"
        resp = httpx.get(
            get_url,
            timeout=10.0,
            follow_redirects=True,
            headers=HEADERS,
        )
        schema = _extract_schema(resp)
        if schema:
            return schema
    except Exception:
        pass

    return None


def _extract_schema(resp: httpx.Response) -> dict | None:
    """Extract __schema from a GraphQL response."""
    if resp.status_code != 200:
        return None

    content_type = resp.headers.get("content-type", "")
    if "json" not in content_type and "graphql" not in content_type:
        return None

    try:
        data = resp.json()
    except Exception:
        return None

    # Standard response: {"data": {"__schema": {...}}}
    if isinstance(data, dict):
        schema = (data.get("data") or {}).get("__schema")
        if isinstance(schema, dict) and "types" in schema:
            return schema

    return None


def _analyze_schema(schema: dict) -> dict:
    """Analyze a GraphQL schema for sensitive operations."""
    types = schema.get("types", [])

    # Filter out built-in types (prefixed with __)
    user_types = [t for t in types if not t.get("name", "").startswith("__")]
    type_count = len(user_types)

    # Find query and mutation type names
    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    # Extract queries and mutations
    queries = []
    mutations = []
    for t in types:
        name = t.get("name", "")
        fields = t.get("fields") or []
        if name == query_type_name:
            queries = [f.get("name", "") for f in fields]
        elif name == mutation_type_name:
            mutations = [f.get("name", "") for f in fields]

    # Check for sensitive operations
    sensitive_mutations = []
    for mutation_name in mutations:
        for pattern, category in SENSITIVE_MUTATION_PATTERNS:
            if re.search(pattern, mutation_name):
                sensitive_mutations.append((mutation_name, category))
                break

    sensitive_queries = []
    for query_name in queries:
        for pattern, category in SENSITIVE_QUERY_PATTERNS:
            if re.search(pattern, query_name):
                sensitive_queries.append((query_name, category))
                break

    return {
        "type_count": type_count,
        "query_count": len(queries),
        "mutation_count": len(mutations),
        "queries": queries,
        "mutations": mutations,
        "sensitive_mutations": sensitive_mutations,
        "sensitive_queries": sensitive_queries,
    }


def _determine_severity(analysis: dict) -> str:
    """Determine severity based on what the schema exposes."""
    if analysis["sensitive_mutations"]:
        return "high"
    if analysis["sensitive_queries"]:
        return "medium"
    if analysis["mutation_count"] > 0:
        return "medium"
    return "low"


def _determine_confidence(analysis: dict) -> float:
    """Determine confidence based on schema richness."""
    # Introspection working is a fact, confidence is about severity assessment
    base = 0.85

    if analysis["sensitive_mutations"]:
        base = min(0.95, base + len(analysis["sensitive_mutations"]) * 0.02)
    if analysis["sensitive_queries"]:
        base = min(0.95, base + len(analysis["sensitive_queries"]) * 0.02)

    return base
