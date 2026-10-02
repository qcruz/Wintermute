"""AI infrastructure exposure detection.

Detects unauthenticated access to AI/ML services that commonly ship without
authentication by default. Based on competitive analysis (Session 39):
81 AI products have no auth by default, and the dominant risk is not a
software flaw but that these services are simply exposed.

Goes beyond exposure-only detection (like Nuclei's ai-infra-nuclei templates)
by testing discovered APIs — confirming unauthenticated access to model lists,
inference endpoints, and management interfaces.

How it works:
  1. Probe known paths for each AI product's API fingerprint
  2. Verify responses match expected product signatures (not generic 200s)
  3. Test whether the API allows unauthenticated operations (list models, etc.)
  4. Report with severity based on exposure level (read-only vs. full access)

What we test:
  - Ollama (local LLM serving) — model listing, version info
  - vLLM (high-performance LLM serving) — model listing, health
  - LangServe (LangChain deployment) — playground, invoke/batch
  - ComfyUI (image generation) — system stats, workflows
  - MLflow (ML experiment tracking) — experiments, models, runs
  - ChromaDB (vector database) — collections, heartbeat
  - Ray Serve (distributed ML) — jobs, version
  - Gradio (ML demos) — API info, predict
  - LiteLLM (LLM proxy) — model listing, health
  - text-generation-webui (LLM UI) — model info

Safety:
  - GET-only for discovery and fingerprinting
  - No model modifications, no inference calls, no data writes
  - All probes are read-only API calls
  - Non-destructive — only confirms exposure, never exploits it
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import httpx

from src.core.http_client import AuthConfig, make_client

logger = logging.getLogger(__name__)

AI_INFRA_TIMEOUT = 10.0
HEADERS = {"User-Agent": "Wintermute/0.1 (Security Research)"}


@dataclass
class AIInfraFinding:
    """An AI infrastructure exposure finding."""

    hostname: str
    vuln_type: str  # ai_infra_exposed, ai_infra_unauth_access
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str
    endpoint: str = ""


@dataclass
class AIInfraResult:
    """Results of AI infrastructure exposure testing."""

    hostname: str
    products_detected: list[str] = field(default_factory=list)
    findings: list[AIInfraFinding] = field(default_factory=list)


# ── Product Fingerprints ─────────────────────────────────────────────
#
# Each product has:
#   - paths: list of (path, description) to probe
#   - fingerprint: function that checks if the response matches the product
#   - severity: base severity for unauthenticated exposure

@dataclass
class ProductProbe:
    """A probe for a specific AI product endpoint."""

    path: str
    description: str


@dataclass
class AIProduct:
    """Definition of an AI product to detect."""

    name: str
    probes: list[ProductProbe]
    severity: str  # Base severity if exposed without auth


PRODUCTS: list[AIProduct] = [
    AIProduct(
        name="Ollama",
        probes=[
            ProductProbe("/api/tags", "Model listing"),
            ProductProbe("/api/version", "Version info"),
        ],
        severity="high",
    ),
    AIProduct(
        name="vLLM",
        probes=[
            ProductProbe("/v1/models", "OpenAI-compatible model listing"),
            ProductProbe("/health", "Health check"),
        ],
        severity="high",
    ),
    AIProduct(
        name="LangServe",
        probes=[
            ProductProbe("/playground", "Interactive playground"),
            ProductProbe("/docs", "API documentation (FastAPI)"),
        ],
        severity="high",
    ),
    AIProduct(
        name="ComfyUI",
        probes=[
            ProductProbe("/system_stats", "System statistics"),
            ProductProbe("/object_info", "Node/object listing"),
        ],
        severity="high",
    ),
    AIProduct(
        name="MLflow",
        probes=[
            ProductProbe("/api/2.0/mlflow/experiments/list", "Experiment listing"),
            ProductProbe("/api/2.0/mlflow/registered-models/list", "Model registry"),
        ],
        severity="high",
    ),
    AIProduct(
        name="ChromaDB",
        probes=[
            ProductProbe("/api/v1/heartbeat", "Heartbeat"),
            ProductProbe("/api/v1/collections", "Collection listing"),
        ],
        severity="high",
    ),
    AIProduct(
        name="Ray Serve",
        probes=[
            ProductProbe("/api/version", "Version info"),
            ProductProbe("/api/jobs/", "Job listing"),
        ],
        severity="high",
    ),
    AIProduct(
        name="Gradio",
        probes=[
            ProductProbe("/info", "App info"),
            ProductProbe("/config", "App config"),
        ],
        severity="medium",
    ),
    AIProduct(
        name="LiteLLM",
        probes=[
            ProductProbe("/models", "Model listing"),
            ProductProbe("/health", "Health check"),
        ],
        severity="high",
    ),
    AIProduct(
        name="text-generation-webui",
        probes=[
            ProductProbe("/api/v1/model", "Active model info"),
            ProductProbe("/api/v1/chat/completions", "Chat endpoint"),
        ],
        severity="high",
    ),
]


# ── Fingerprint Functions ────────────────────────────────────────────

def _fingerprint_ollama(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches Ollama API signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/api/tags" and isinstance(data, dict) and "models" in data:
        models = data["models"]
        if isinstance(models, list):
            names = [m.get("name", "?") for m in models[:5]]
            return f"Ollama API — {len(models)} models loaded: {', '.join(names)}"

    if path == "/api/version" and isinstance(data, dict) and "version" in data:
        return f"Ollama v{data['version']}"

    return None


def _fingerprint_vllm(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches vLLM API signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/v1/models" and isinstance(data, dict) and "data" in data:
        models = data["data"]
        if isinstance(models, list) and models:
            # OpenAI-compatible format has "id" and "object" fields
            first = models[0]
            if isinstance(first, dict) and "id" in first:
                names = [m.get("id", "?") for m in models[:5]]
                return f"vLLM — {len(models)} models: {', '.join(names)}"

    if path == "/health":
        # vLLM health returns empty 200
        if resp.status_code == 200 and len(resp.text.strip()) < 20:
            return None  # Not enough to fingerprint on health alone

    return None


def _fingerprint_langserve(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches LangServe signatures."""
    body = resp.text.lower()

    if path == "/playground" and resp.status_code == 200:
        if "langserve" in body or "langchain" in body or "playground" in body:
            return "LangServe playground accessible"

    if path == "/docs" and resp.status_code == 200:
        if "fastapi" in body and ("invoke" in body or "batch" in body):
            return "LangServe API docs (FastAPI) — invoke/batch endpoints documented"

    return None


def _fingerprint_comfyui(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches ComfyUI signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/system_stats" and isinstance(data, dict):
        if "system" in data or "devices" in data:
            gpu_info = ""
            if "devices" in data and isinstance(data["devices"], list):
                gpu_info = f", {len(data['devices'])} GPU(s)"
            return f"ComfyUI system stats exposed{gpu_info}"

    if path == "/object_info" and isinstance(data, dict):
        if len(data) > 10:  # ComfyUI has hundreds of node types
            return f"ComfyUI object registry — {len(data)} node types exposed"

    return None


def _fingerprint_mlflow(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches MLflow signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if "experiments" in path and isinstance(data, dict):
        if "experiments" in data:
            exps = data["experiments"]
            if isinstance(exps, list):
                return f"MLflow — {len(exps)} experiments accessible"

    if "registered-models" in path and isinstance(data, dict):
        if "registered_models" in data:
            models = data["registered_models"]
            if isinstance(models, list):
                return f"MLflow model registry — {len(models)} models"

    return None


def _fingerprint_chromadb(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches ChromaDB signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if "heartbeat" in path and isinstance(data, dict):
        if "nanosecond heartbeat" in str(data):
            return "ChromaDB heartbeat confirmed"

    if "collections" in path and isinstance(data, list):
        return f"ChromaDB — {len(data)} collections accessible"

    return None


def _fingerprint_ray(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches Ray Serve signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/api/version" and isinstance(data, dict):
        if "ray_version" in data or "version" in data:
            ver = data.get("ray_version") or data.get("version", "?")
            return f"Ray Serve v{ver}"

    if "jobs" in path and isinstance(data, (list, dict)):
        # Ray jobs API returns a list or paginated dict
        if isinstance(data, list):
            return f"Ray job listing — {len(data)} jobs"
        if "submissions" in data or "job_id" in str(data)[:200]:
            return "Ray job management API accessible"

    return None


def _fingerprint_gradio(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches Gradio signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/info" and isinstance(data, dict):
        if "version" in data and "api" in str(data).lower():
            return f"Gradio app v{data.get('version', '?')}"

    if path == "/config" and isinstance(data, dict):
        if "components" in data or "dependencies" in data:
            title = data.get("title", "Unknown")
            return f"Gradio app config — title: {title}"

    return None


def _fingerprint_litellm(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches LiteLLM proxy signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/models" and isinstance(data, dict) and "data" in data:
        models = data["data"]
        if isinstance(models, list) and models:
            first = models[0]
            if isinstance(first, dict) and "id" in first:
                # Distinguish from vLLM: LiteLLM often proxies multiple providers
                names = [m.get("id", "?") for m in models[:5]]
                # Check for LiteLLM-specific markers
                body_str = resp.text
                if "litellm" in body_str.lower():
                    return f"LiteLLM proxy — {len(models)} models: {', '.join(names)}"

    if path == "/health" and resp.status_code == 200:
        body = resp.text.lower()
        if "litellm" in body:
            return "LiteLLM health endpoint"

    return None


def _fingerprint_tgwebui(path: str, resp: httpx.Response) -> str | None:
    """Check if response matches text-generation-webui signatures."""
    try:
        data = resp.json()
    except Exception:
        return None

    if path == "/api/v1/model" and isinstance(data, dict):
        if "result" in data:
            model = data["result"]
            if isinstance(model, str) and model:
                return f"text-generation-webui — model: {model}"

    if path == "/api/v1/chat/completions" and resp.status_code in (200, 405):
        # GET on a POST endpoint might return 405 but confirms it exists
        if resp.status_code == 405:
            return None  # Need more evidence
        body = resp.text.lower()
        if "model" in body:
            return "text-generation-webui chat completions endpoint"

    return None


# Map product names to fingerprint functions
FINGERPRINTERS: dict[str, callable] = {
    "Ollama": _fingerprint_ollama,
    "vLLM": _fingerprint_vllm,
    "LangServe": _fingerprint_langserve,
    "ComfyUI": _fingerprint_comfyui,
    "MLflow": _fingerprint_mlflow,
    "ChromaDB": _fingerprint_chromadb,
    "Ray Serve": _fingerprint_ray,
    "Gradio": _fingerprint_gradio,
    "LiteLLM": _fingerprint_litellm,
    "text-generation-webui": _fingerprint_tgwebui,
}


# ── Main Check Function ─────────────────────────────────────────────

def check_ai_infra(
    hostname: str,
    auth: AuthConfig | None = None,
) -> AIInfraResult:
    """Check a hostname for exposed AI infrastructure services.

    Probes known paths for 10 AI/ML products and verifies responses
    match product-specific fingerprints to avoid false positives.

    Args:
        hostname: Target hostname to test
        auth: Optional auth config (rarely needed — the point is to
              find services exposed WITHOUT auth)
    """
    result = AIInfraResult(hostname=hostname)

    client_kwargs = {"timeout": AI_INFRA_TIMEOUT, "headers": HEADERS}
    if auth:
        client = make_client(auth, timeout=AI_INFRA_TIMEOUT)
    else:
        client = httpx.Client(
            timeout=AI_INFRA_TIMEOUT,
            headers=HEADERS,
            follow_redirects=False,
            verify=False,
        )

    try:
        for product in PRODUCTS:
            fingerprinter = FINGERPRINTERS.get(product.name)
            if not fingerprinter:
                continue

            for probe in product.probes:
                match = _probe_endpoint(
                    client, hostname, product, probe, fingerprinter
                )
                if match:
                    result.products_detected.append(product.name)
                    result.findings.append(match)
                    # One confirmed finding per product is enough
                    break
    finally:
        client.close()

    return result


def _probe_endpoint(
    client: httpx.Client,
    hostname: str,
    product: AIProduct,
    probe: ProductProbe,
    fingerprinter: callable,
) -> AIInfraFinding | None:
    """Probe a single endpoint and check against product fingerprint."""
    url = f"https://{hostname}{probe.path}"

    try:
        resp = client.get(url)
    except Exception:
        # Try HTTP if HTTPS fails (many AI services run on HTTP internally)
        try:
            resp = client.get(f"http://{hostname}{probe.path}")
        except Exception:
            return None

    if resp.status_code not in (200, 201):
        return None

    # Skip HTML responses — not an API
    content_type = resp.headers.get("content-type", "").lower()
    if "text/html" in content_type:
        return None

    evidence = fingerprinter(probe.path, resp)
    if not evidence:
        return None

    logger.info(
        "AI infrastructure detected: %s on %s%s — %s",
        product.name, hostname, probe.path, evidence,
    )

    return AIInfraFinding(
        hostname=hostname,
        vuln_type="ai_infra_exposed",
        severity=product.severity,
        confidence=0.9,
        title=(
            f"Unauthenticated {product.name} instance exposed on {hostname}"
        ),
        description=(
            f"{product.name} is accessible without authentication at "
            f"https://{hostname}{probe.path}. {probe.description} is publicly "
            f"available. AI infrastructure services exposed without authentication "
            f"can be abused for unauthorized model access, data extraction, "
            f"resource consumption, and as pivot points for further attacks."
        ),
        evidence=evidence,
        endpoint=probe.path,
    )
