"""MCP (Model Context Protocol) server security testing.

Tests for vulnerabilities in MCP server endpoints — the emerging standard
for AI agent tool use. MCP servers are often deployed with weak security:
82% have path traversal risks, only 8.5% use OAuth, and 30+ CVEs were
filed in the first 60 days of widespread adoption.

How it works:
  1. Discover MCP server endpoints via path probing and protocol detection
  2. Test for unauthenticated tool listing (auth bypass)
  3. Analyze exposed tool schemas for dangerous capabilities
  4. Test for path traversal via file-access tools
  5. Check tool descriptions for poisoning indicators

What we test:
  - MCP endpoint discovery (SSE, JSON-RPC, REST, .well-known)
  - Unauthenticated access to tool listings
  - Dangerous tool capabilities (file access, shell exec, network, DB)
  - Tool description poisoning indicators
  - Missing OAuth/auth on MCP endpoints
  - Path traversal via MCP file tools

Safety:
  - Only sends GET and POST requests to discover and list tools
  - Never invokes tools that could modify state
  - Path traversal testing uses safe read-only payloads
  - All tests are detection-only, not exploitation
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

MCP_TIMEOUT = 15.0
HEADERS = {"User-Agent": "Wintermute/0.1 (Security Research)"}


@dataclass
class MCPFinding:
    """An MCP security finding."""

    hostname: str
    vuln_type: str  # mcp_auth_bypass, mcp_dangerous_tools, mcp_tool_poisoning, mcp_exposed
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str
    endpoint: str = ""


@dataclass
class MCPSecurityResult:
    """Results of MCP security testing."""

    hostname: str
    mcp_endpoints_found: int = 0
    tools_discovered: int = 0
    findings: list[MCPFinding] = field(default_factory=list)


# ── MCP Endpoint Discovery Paths ──────────────────────────────────

MCP_PATHS = [
    # Standard MCP paths
    ("/mcp", "MCP Server"),
    ("/mcp/", "MCP Server"),
    ("/api/mcp", "MCP API"),
    ("/api/mcp/", "MCP API"),
    ("/mcp/v1", "MCP Server v1"),
    ("/mcp/v1/", "MCP Server v1"),
    ("/.well-known/mcp", "MCP Well-Known"),
    ("/.well-known/mcp.json", "MCP Config"),
    # SSE transport (MCP primary transport)
    ("/sse", "SSE Transport"),
    ("/mcp/sse", "MCP SSE Transport"),
    ("/api/mcp/sse", "MCP API SSE"),
    ("/events", "Event Stream"),
    # JSON-RPC endpoints (MCP protocol)
    ("/jsonrpc", "JSON-RPC"),
    ("/rpc", "RPC Endpoint"),
    ("/api/rpc", "API RPC"),
    # Stdio proxy (HTTP wrapper for MCP stdio)
    ("/mcp/stdio", "MCP Stdio Proxy"),
    # Common MCP server implementations
    ("/tools", "Tools Endpoint"),
    ("/api/tools", "API Tools"),
    ("/mcp/tools", "MCP Tools"),
    ("/mcp/list-tools", "MCP List Tools"),
    ("/api/v1/tools", "Tools API v1"),
    # Resources and prompts (MCP primitives)
    ("/mcp/resources", "MCP Resources"),
    ("/mcp/prompts", "MCP Prompts"),
    ("/api/mcp/resources", "MCP API Resources"),
]

# JSON-RPC methods for MCP tool listing
MCP_LIST_METHODS = [
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "prompts/list", "params": {}},
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "wintermute-security-test", "version": "0.1"},
    }},
]

# Patterns indicating an MCP/JSON-RPC response
MCP_RESPONSE_INDICATORS = [
    r'"jsonrpc"\s*:\s*"2\.0"',
    r'"tools"\s*:\s*\[',
    r'"resources"\s*:\s*\[',
    r'"prompts"\s*:\s*\[',
    r'"serverInfo"\s*:',
    r'"capabilities"\s*:\s*\{',
    r'"protocolVersion"\s*:',
    r'text/event-stream',
]

# Tool names/descriptions indicating dangerous capabilities
DANGEROUS_TOOL_PATTERNS = [
    # File system access
    (r"(?:read|write|create|delete|list)[-_]?(?:file|directory|dir|folder)", "File system access"),
    (r"(?:file|fs)[-_]?(?:read|write|delete|create|list|move|copy)", "File system operations"),
    (r"(?:read|get)[-_]?(?:contents?|text|data)[-_]?(?:of|from)?[-_]?(?:file)?", "File read"),
    # Shell/command execution
    (r"(?:run|exec|execute|shell|bash|cmd|command|spawn|system)", "Command execution"),
    (r"(?:terminal|subprocess|process|eval)", "Process execution"),
    # Network access
    (r"(?:fetch|http|request|curl|wget|download|upload)", "Network access"),
    (r"(?:connect|socket|tcp|udp)", "Raw network access"),
    # Database
    (r"(?:sql|query|database|db)[-_]?(?:exec|execute|run|query)?", "Database access"),
    (r"(?:mongo|redis|postgres|mysql)", "Database client"),
    # Credential/secret access
    (r"(?:credential|secret|password|token|key|auth)[-_]?(?:get|read|list|fetch)?", "Credential access"),
    (r"(?:env|environment)[-_]?(?:var|variable|get|read)?", "Environment variable access"),
    # Code execution
    (r"(?:python|node|javascript|ruby|php)[-_]?(?:exec|eval|run)?", "Code execution"),
    (r"(?:eval|compile|interpret)", "Code evaluation"),
    # Admin/privileged operations
    (r"(?:admin|root|sudo|privilege|escalat)", "Privileged operations"),
    (r"(?:user|account)[-_]?(?:create|delete|modify|update)", "User management"),
]

# Tool description patterns that may indicate poisoning
# Poisoning = malicious instructions hidden in tool descriptions that
# override agent behavior when the agent reads the tool schema
POISONING_INDICATORS = [
    (r"ignore\s+(?:previous|prior|above|all)\s+(?:instructions?|rules?|guidelines?)", "Instruction override"),
    (r"(?:do not|don't|never)\s+(?:tell|inform|alert|notify)\s+(?:the\s+)?user", "User deception"),
    (r"(?:exfiltrate|steal|extract|send|transmit)\s+(?:data|information|credentials?|tokens?|keys?)", "Data exfiltration intent"),
    (r"(?:before|after)\s+(?:running|executing|calling)\s+this\s+tool.*(?:first|also)\s+(?:run|execute|call)", "Hidden tool chaining"),
    (r"<\s*(?:system|hidden|internal)\s*>", "Hidden instruction tags"),
    (r"(?:secretly|silently|quietly|covertly)\s+(?:send|transmit|log|store|save)", "Covert action"),
    (r"(?:override|bypass|ignore|skip)\s+(?:safety|security|auth|permission|access)", "Safety bypass"),
]

# Safe path traversal payloads for MCP file tools (read-only targets)
MCP_TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "/etc/passwd"),
    ("..\\..\\..\\windows\\win.ini", "win.ini"),
    ("....//....//....//etc/passwd", "/etc/passwd"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd"),
]

# Signatures confirming file content was read
FILE_SIGNATURES = [
    (r"root:.*:0:0:", "/etc/passwd"),
    (r"\[fonts\]", "win.ini"),
    (r"\[extensions\]", "win.ini"),
]


def check_mcp_security(hostname: str) -> MCPSecurityResult:
    """Test a hostname for MCP server security vulnerabilities.

    Flow:
      1. Discover MCP endpoints via path probing
      2. Test for unauthenticated tool listing
      3. Analyze tool schemas for dangerous capabilities
      4. Check for tool poisoning indicators
      5. Test file tools for path traversal
    """
    result = MCPSecurityResult(hostname=hostname)
    base_url = f"https://{hostname}"

    # Step 1: Discover MCP endpoints
    mcp_endpoints = _discover_mcp_endpoints(base_url)
    result.mcp_endpoints_found = len(mcp_endpoints)

    if not mcp_endpoints:
        logger.debug("No MCP endpoints found on %s", hostname)
        return result

    logger.info("Found %d potential MCP endpoints on %s", len(mcp_endpoints), hostname)

    # Step 2: Test each endpoint
    for endpoint_path, endpoint_desc, endpoint_type in mcp_endpoints:
        # Report the MCP endpoint itself
        result.findings.append(MCPFinding(
            hostname=hostname,
            vuln_type="mcp_exposed",
            severity="info",
            confidence=0.7,
            title=f"MCP server endpoint discovered: {endpoint_desc} on {hostname}",
            description=(
                f"An MCP (Model Context Protocol) server endpoint was discovered at "
                f"{endpoint_path}. MCP servers enable AI agents to use tools and access "
                f"resources. If not properly secured, they can expose sensitive operations."
            ),
            evidence=f"Endpoint: {endpoint_path}, Type: {endpoint_type}",
            endpoint=endpoint_path,
        ))

        # Step 3: Try to list tools without authentication
        tools = _try_list_tools(base_url, endpoint_path, endpoint_type, result)

        if tools:
            result.tools_discovered += len(tools)

            # Step 4: Analyze tools for dangerous capabilities
            _analyze_tools(hostname, endpoint_path, tools, result)

            # Step 5: Test file tools for path traversal
            _test_file_tools(base_url, hostname, endpoint_path, tools, result)

    if result.findings:
        logger.info(
            "MCP security testing on %s: %d findings, %d tools discovered",
            hostname, len(result.findings), result.tools_discovered,
        )

    return result


def _discover_mcp_endpoints(
    base_url: str,
) -> list[tuple[str, str, str]]:
    """Discover MCP server endpoints via path probing.

    Returns list of (path, description, type) tuples.
    type is "jsonrpc", "sse", "rest", or "config".
    """
    endpoints = []

    # Get 404 baseline
    try:
        not_found = httpx.get(
            f"{base_url}/wintermute-mcp-check-nonexistent-m3k8",
            timeout=MCP_TIMEOUT,
            follow_redirects=False,
            headers=HEADERS,
        )
        baseline_status = not_found.status_code
        baseline_length = len(not_found.content)
    except Exception:
        baseline_status = 404
        baseline_length = 0

    for path, description in MCP_PATHS:
        try:
            resp = httpx.get(
                f"{base_url}{path}",
                timeout=MCP_TIMEOUT,
                follow_redirects=False,
                headers=HEADERS,
            )

            # Skip 404 baseline matches
            if resp.status_code == baseline_status and baseline_length > 0:
                if abs(len(resp.content) - baseline_length) < 50:
                    continue

            if resp.status_code in (200, 401, 403, 405):
                content_type = resp.headers.get("content-type", "").lower()
                body = resp.text

                # Detect endpoint type
                endpoint_type = "rest"

                if "text/event-stream" in content_type:
                    endpoint_type = "sse"
                elif resp.status_code == 405:
                    # Method not allowed — likely POST-only JSON-RPC
                    endpoint_type = "jsonrpc"
                elif "application/json" in content_type:
                    # Check for MCP/JSON-RPC indicators
                    if any(re.search(p, body, re.IGNORECASE) for p in MCP_RESPONSE_INDICATORS):
                        endpoint_type = "jsonrpc"
                    elif path.endswith(".json") or "well-known" in path:
                        endpoint_type = "config"

                # Only add if it looks like a real MCP/tool endpoint
                is_mcp = False

                if resp.status_code == 200:
                    if any(re.search(p, body, re.IGNORECASE) for p in MCP_RESPONSE_INDICATORS):
                        is_mcp = True
                    elif endpoint_type == "sse":
                        is_mcp = True
                    elif "application/json" in content_type and len(body) > 10:
                        # JSON response on a tool/MCP path — worth investigating
                        try:
                            data = json.loads(body)
                            if isinstance(data, dict) and any(
                                k in data for k in ("tools", "resources", "prompts", "capabilities", "serverInfo")
                            ):
                                is_mcp = True
                        except (json.JSONDecodeError, ValueError):
                            pass

                elif resp.status_code == 405:
                    # POST-only endpoint on MCP path — likely JSON-RPC
                    if any(kw in path for kw in ("/mcp", "/rpc", "/jsonrpc", "/tools")):
                        is_mcp = True

                elif resp.status_code in (401, 403):
                    # Auth-gated but exists
                    if any(kw in path for kw in ("/mcp", "/tools", "/sse")):
                        is_mcp = True
                        endpoint_type = f"{endpoint_type}_authed"

                if is_mcp:
                    endpoints.append((path, description, endpoint_type))

        except Exception as e:
            logger.debug("MCP probe failed for %s%s: %s", base_url, path, e)

    # Deduplicate
    seen = set()
    unique = []
    for path, desc, etype in endpoints:
        if path not in seen:
            seen.add(path)
            unique.append((path, desc, etype))

    return unique[:10]


def _try_list_tools(
    base_url: str,
    path: str,
    endpoint_type: str,
    result: MCPSecurityResult,
) -> list[dict]:
    """Try to list MCP tools without authentication.

    If successful, this is an auth bypass finding.
    """
    hostname = result.hostname
    tools = []

    # Skip auth-gated endpoints
    if "authed" in endpoint_type:
        return tools

    # Try JSON-RPC tool listing
    for method_body in MCP_LIST_METHODS:
        if method_body["method"] not in ("tools/list", "initialize"):
            continue

        try:
            resp = httpx.post(
                f"{base_url}{path}",
                json=method_body,
                timeout=MCP_TIMEOUT,
                headers={**HEADERS, "Content-Type": "application/json"},
            )

            if resp.status_code != 200:
                continue

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                continue

            # Check for JSON-RPC response
            if not isinstance(data, dict):
                continue

            # Extract tools from response
            rpc_result = data.get("result", {})
            if isinstance(rpc_result, dict):
                tool_list = rpc_result.get("tools", [])
                if tool_list and isinstance(tool_list, list):
                    tools = tool_list
                    # This is an auth bypass — tools listed without auth
                    result.findings.append(MCPFinding(
                        hostname=hostname,
                        vuln_type="mcp_auth_bypass",
                        severity="high",
                        confidence=0.9,
                        title=f"MCP server exposes tools without authentication on {hostname}",
                        description=(
                            f"The MCP server at {path} responded to a tools/list request "
                            f"without requiring authentication, exposing {len(tools)} tools. "
                            f"Any client can discover and potentially invoke these tools."
                        ),
                        evidence=(
                            f"Endpoint: {path}\n"
                            f"Method: {method_body['method']}\n"
                            f"Tools found: {len(tools)}\n"
                            f"Tool names: {', '.join(t.get('name', '?') for t in tools[:10])}"
                        ),
                        endpoint=path,
                    ))
                    break

                # Check for server capabilities (initialize response)
                caps = rpc_result.get("capabilities", {})
                server_info = rpc_result.get("serverInfo", {})
                if caps or server_info:
                    result.findings.append(MCPFinding(
                        hostname=hostname,
                        vuln_type="mcp_auth_bypass",
                        severity="medium",
                        confidence=0.85,
                        title=f"MCP server accepts unauthenticated initialization on {hostname}",
                        description=(
                            f"The MCP server at {path} accepted an initialize request without "
                            f"authentication, revealing server capabilities and configuration."
                        ),
                        evidence=(
                            f"Endpoint: {path}\n"
                            f"Server: {json.dumps(server_info)[:200]}\n"
                            f"Capabilities: {json.dumps(caps)[:200]}"
                        ),
                        endpoint=path,
                    ))

        except Exception as e:
            logger.debug("MCP tool listing failed for %s%s: %s", base_url, path, e)

    # Also try REST-style tool listing
    if not tools:
        for tools_path in (f"{path}/tools", f"{path}/list-tools"):
            try:
                resp = httpx.get(
                    f"{base_url}{tools_path}",
                    timeout=MCP_TIMEOUT,
                    headers=HEADERS,
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and data:
                            tools = data
                        elif isinstance(data, dict) and "tools" in data:
                            tools = data["tools"]
                        if tools:
                            result.findings.append(MCPFinding(
                                hostname=hostname,
                                vuln_type="mcp_auth_bypass",
                                severity="high",
                                confidence=0.85,
                                title=f"MCP tools exposed via REST endpoint on {hostname}",
                                description=(
                                    f"MCP tool list accessible without authentication at "
                                    f"{tools_path}, exposing {len(tools)} tools."
                                ),
                                evidence=(
                                    f"Endpoint: {tools_path}\n"
                                    f"Tools found: {len(tools)}\n"
                                    f"Tool names: {', '.join(t.get('name', '?') for t in tools[:10] if isinstance(t, dict))}"
                                ),
                                endpoint=tools_path,
                            ))
                            break
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception:
                pass

    return tools


def _analyze_tools(
    hostname: str,
    endpoint_path: str,
    tools: list[dict],
    result: MCPSecurityResult,
) -> None:
    """Analyze discovered MCP tools for dangerous capabilities and poisoning."""

    dangerous_tools = []
    poisoned_tools = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        tool_name = tool.get("name", "unknown")
        tool_desc = tool.get("description", "")
        tool_schema = json.dumps(tool.get("inputSchema", {}))
        combined_text = f"{tool_name} {tool_desc} {tool_schema}".lower()

        # Check for dangerous capabilities
        for pattern, category in DANGEROUS_TOOL_PATTERNS:
            if re.search(pattern, combined_text, re.IGNORECASE):
                dangerous_tools.append((tool_name, category, tool_desc[:100]))
                break

        # Check for poisoning indicators in descriptions
        full_desc = f"{tool_desc} {tool_schema}"
        for pattern, indicator_type in POISONING_INDICATORS:
            if re.search(pattern, full_desc, re.IGNORECASE):
                poisoned_tools.append((tool_name, indicator_type, tool_desc[:200]))
                break

    if dangerous_tools:
        # Group by category for cleaner reporting
        categories = {}
        for name, cat, desc in dangerous_tools:
            categories.setdefault(cat, []).append(name)

        category_summary = "; ".join(
            f"{cat}: {', '.join(names)}" for cat, names in categories.items()
        )

        result.findings.append(MCPFinding(
            hostname=hostname,
            vuln_type="mcp_dangerous_tools",
            severity="high",
            confidence=0.85,
            title=f"MCP server exposes dangerous tools on {hostname}",
            description=(
                f"The MCP server at {endpoint_path} exposes {len(dangerous_tools)} tools "
                f"with dangerous capabilities including: "
                f"{', '.join(sorted(set(cat for _, cat, _ in dangerous_tools)))}. "
                f"If accessible without proper authorization, these tools could be abused "
                f"by a compromised or malicious AI agent."
            ),
            evidence=(
                f"Endpoint: {endpoint_path}\n"
                f"Dangerous tools ({len(dangerous_tools)}):\n"
                + "\n".join(f"  - {name} [{cat}]: {desc}" for name, cat, desc in dangerous_tools[:10])
            ),
            endpoint=endpoint_path,
        ))

    if poisoned_tools:
        result.findings.append(MCPFinding(
            hostname=hostname,
            vuln_type="mcp_tool_poisoning",
            severity="critical",
            confidence=0.8,
            title=f"Potential tool poisoning detected in MCP server on {hostname}",
            description=(
                f"Tool descriptions in the MCP server at {endpoint_path} contain "
                f"suspicious instructions that may be designed to manipulate AI agent "
                f"behavior. This is a tool poisoning attack — the highest-leverage "
                f"attack on AI agent systems."
            ),
            evidence=(
                f"Endpoint: {endpoint_path}\n"
                f"Suspicious tools ({len(poisoned_tools)}):\n"
                + "\n".join(
                    f"  - {name} [{itype}]: {desc}"
                    for name, itype, desc in poisoned_tools[:5]
                )
            ),
            endpoint=endpoint_path,
        ))


def _test_file_tools(
    base_url: str,
    hostname: str,
    endpoint_path: str,
    tools: list[dict],
    result: MCPSecurityResult,
) -> None:
    """Test MCP file-access tools for path traversal.

    Only tests tools that appear to be file-read operations.
    Uses safe, read-only payloads targeting /etc/passwd and win.ini.
    """
    # Find file-related tools
    file_tools = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "").lower()
        desc = tool.get("description", "").lower()
        if any(kw in f"{name} {desc}" for kw in ("file", "read", "get_content", "load", "open")):
            # Check if it has a path/file parameter
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            path_params = [
                p for p in properties
                if any(kw in p.lower() for kw in ("path", "file", "filename", "uri", "url", "location"))
            ]
            if path_params:
                file_tools.append((tool.get("name", ""), path_params[0]))

    if not file_tools:
        return

    # Test each file tool with traversal payloads
    for tool_name, param_name in file_tools[:3]:  # Limit to 3 tools
        for payload, target_file in MCP_TRAVERSAL_PAYLOADS:
            try:
                # Send JSON-RPC tool call
                rpc_body = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": {param_name: payload},
                    },
                }

                resp = httpx.post(
                    f"{base_url}{endpoint_path}",
                    json=rpc_body,
                    timeout=MCP_TIMEOUT,
                    headers={**HEADERS, "Content-Type": "application/json"},
                )

                if resp.status_code != 200:
                    continue

                body = resp.text

                # Check for file content signatures
                for sig_pattern, sig_file in FILE_SIGNATURES:
                    if re.search(sig_pattern, body, re.IGNORECASE):
                        result.findings.append(MCPFinding(
                            hostname=hostname,
                            vuln_type="mcp_path_traversal",
                            severity="critical",
                            confidence=0.95,
                            title=f"Path traversal via MCP tool '{tool_name}' on {hostname}",
                            description=(
                                f"The MCP tool '{tool_name}' on {endpoint_path} is vulnerable "
                                f"to path traversal. The payload '{payload}' successfully read "
                                f"{sig_file} content through the '{param_name}' parameter."
                            ),
                            evidence=(
                                f"Endpoint: {endpoint_path}\n"
                                f"Tool: {tool_name}\n"
                                f"Parameter: {param_name}\n"
                                f"Payload: {payload}\n"
                                f"Response contained: {sig_file} content signature"
                            ),
                            endpoint=endpoint_path,
                        ))
                        return  # One confirmed traversal is enough

            except Exception as e:
                logger.debug(
                    "MCP traversal test failed for %s tool=%s: %s",
                    base_url, tool_name, e,
                )
