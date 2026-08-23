"""
Argus — API & OpenAPI Route Discovery Engine (FR-3)

Discovery strategy (executed in order, results merge):

  Phase 1 — OpenAPI / Swagger spec probing (FR-3.3)
      Probe well-known spec paths (/openapi.json, /swagger.json, etc.).
      If found, parse the full spec into structured APIEndpoint objects:
      exact HTTP methods, path params, query params, and JSON body schemas.

  Phase 2 — Passive JS bundle scraping (FR-3.2)
      Fetch the target's HTML, extract <script src="..."> links, download
      each JS bundle, and regex for endpoint strings in fetch(), axios.*(),
      $.ajax(), url: '...', etc. This is the primary fallback when specs
      are blocked/absent.

  Phase 3 — OPTIONS method probing
      For every discovered path, send an OPTIONS request. The Allow header
      in the response reveals supported HTTP methods (GET, POST, PUT, DELETE)
      without triggering application logic.

  Phase 4 — API path wordlist brute-force
      Fuzz common REST/GraphQL path conventions (/api/v1/users, /graphql,
      /health, etc.) using a built-in API-specific wordlist when all other
      phases produce nothing.

All phases feed into a unified list of APIEndpoint dataclass objects that
the param_fuzz module can consume for schema-aware vulnerability testing.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from core.auth_gate import ScanContext
from core import db

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAPI_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
    "/docs.json",
    "/swagger/v1/swagger.json",     # ASP.NET default
    "/_catalog",                     # Docker registry
    "/api/swagger.json",
]

# Regex patterns for passive JS API route extraction (FR-3.2)
JS_ROUTE_PATTERNS = [
    # Quoted path starting with /api or /v<N>
    r'["\'](/(?:api|v[0-9]+(?:\.[0-9]+)?)/[a-zA-Z0-9_\-/\.{}:]+)["\']',
    # fetch / axios / jQuery AJAX calls
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|axios)\s*\(\s*["\']([/a-zA-Z0-9_\-/\.:{}?=&]+)["\']',
    # Generic url/endpoint property assignments
    r'(?:url|endpoint|baseURL|apiUrl|apiEndpoint)\s*[:=]\s*["\']([/a-zA-Z0-9_\-/\.:{}]+)["\']',
    # Template literals:  `${baseUrl}/api/users`  →  captures /api/users
    r'`[^`]*(/(?:api|v[0-9]+)/[a-zA-Z0-9_\-/\.{}$]+)[^`]*`',
    # jQuery $.ajax calls
    r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([/a-zA-Z0-9_\-/\.:{}]+)["\']',
]

# Common hidden query parameter names for parameter mining
COMMON_PARAM_NAMES = [
    "id", "user", "user_id", "userId", "username", "email", "name",
    "page", "limit", "offset", "sort", "order", "filter", "search",
    "q", "query", "type", "status", "role", "token", "key", "api_key",
    "callback", "redirect", "url", "next", "return", "ref", "source",
    "action", "cmd", "command", "exec", "file", "path", "dir",
    "debug", "test", "admin", "verbose", "format", "output",
    "include", "fields", "select", "expand", "embed", "populate",
    "lang", "locale", "version", "v", "category", "tag",
]

# Built-in API path wordlist for Phase 4 brute-force (common conventions)
API_WORDLIST = [
    "api", "api/v1", "api/v2", "api/v1/users", "api/v1/auth", "api/v1/auth/login",
    "api/v1/auth/register", "api/v1/auth/token", "api/v1/admin", "api/v1/config",
    "api/v1/health", "api/v1/status", "api/v1/search", "api/v1/upload",
    "api/v1/files", "api/v1/settings", "api/v1/profile", "api/v1/orders",
    "api/v1/products", "api/v1/payments", "api/users", "api/admin",
    "graphql", "graphiql", "playground", "health", "healthz", "ready",
    "metrics", "info", "env", "debug", "console", "actuator",
    "actuator/health", "actuator/env", "actuator/beans",
    ".well-known/openid-configuration", "oauth/token", "auth/callback",
    "api/v1/query", "api/v1/data", "api/v1/export", "api/v1/import",
    "api/v1/notifications", "api/v1/messages", "api/v1/reports",
    "api/v1/analytics", "api/v1/events", "api/v1/webhooks",
]

# File extensions that are clearly not API endpoints (filter from JS matches)
STATIC_ASSET_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css",
                            ".js", ".woff", ".woff2", ".ttf", ".eot", ".ico",
                            ".map", ".webp", ".avif")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class APIEndpoint:
    """
    Structured representation of a discovered API endpoint. Carries enough
    information for param_fuzz to construct schema-compliant requests and
    inject payloads into the right places.
    """
    path: str
    method: str = "GET"
    summary: str = ""
    query_params: List[str] = field(default_factory=list)
    path_params: List[str] = field(default_factory=list)
    json_body_schema: Dict[str, Any] = field(default_factory=dict)
    content_type: str = ""
    source: str = "openapi"  # openapi | js_passive | options_probe | wordlist

    def __hash__(self):
        return hash((self.path, self.method))

    def __eq__(self, other):
        return isinstance(other, APIEndpoint) and self.path == other.path and self.method == other.method


# ---------------------------------------------------------------------------
# Phase 1: OpenAPI / Swagger spec parsing
# ---------------------------------------------------------------------------

async def _parse_openapi_specs(
    client: httpx.AsyncClient,
    base_url: str,
    ctx: ScanContext,
    scan_id: Optional[str] = None,
    spec_file: Optional[str] = None,
) -> Tuple[List[APIEndpoint], Set[str]]:
    """
    Parses OpenAPI/Swagger specs into APIEndpoint objects with methods, params, and body schemas.
    If spec_file is provided, loads the schema directly from the local filesystem (Grey-Box mode).
    Otherwise, probes well-known spec paths on the live target.
    """
    endpoints: List[APIEndpoint] = []
    flat_paths: Set[str] = set()

    # Case A: Local spec file provided (Grey-Box testing)
    if spec_file:
        spec_path_obj = Path(spec_file)
        if spec_path_obj.exists():
            try:
                with open(spec_path_obj, encoding="utf-8") as f:
                    spec = json.load(f)
                return _parse_spec_dict(spec)
            except Exception:
                pass

    # Case B: Probe live target spec paths
    for spec_path in OPENAPI_SPEC_PATHS:
        await ctx.throttle()
        url = f"{base_url.rstrip('/')}{spec_path}"
        try:
            resp = await client.get(url, timeout=5.0, follow_redirects=True)
            if scan_id:
                db.log_request(scan_id, base_url, "api_discovery", "GET", url,
                               resp.status_code)
            if resp.status_code != 200:
                continue
            try:
                spec = resp.json()
                ep_list, paths_set = _parse_spec_dict(spec)
                if ep_list:
                    return ep_list, paths_set
            except (json.JSONDecodeError, ValueError):
                continue
        except httpx.RequestError:
            continue

    return endpoints, flat_paths


def _parse_spec_dict(spec: dict) -> Tuple[List[APIEndpoint], Set[str]]:
    """Helper to parse a decoded OpenAPI/Swagger dictionary."""
    endpoints: List[APIEndpoint] = []
    flat_paths: Set[str] = set()

    if not isinstance(spec, dict) or "paths" not in spec:
        return endpoints, flat_paths

    for path, path_item in spec["paths"].items():
        clean = path.lstrip("/")
        if clean:
            flat_paths.add(clean)

        shared_params = path_item.get("parameters", [])

        for method_key, operation in path_item.items():
            if method_key.lower() not in ("get", "post", "put", "delete", "patch", "head", "options"):
                continue
            if not isinstance(operation, dict):
                continue

            ep = APIEndpoint(
                path=path,
                method=method_key.upper(),
                summary=operation.get("summary", ""),
                source="openapi",
            )

            all_params = shared_params + operation.get("parameters", [])
            for p in all_params:
                if not isinstance(p, dict):
                    continue
                p_name = p.get("name")
                p_in = p.get("in")
                if p_in == "query" and p_name:
                    ep.query_params.append(p_name)
                elif p_in == "path" and p_name:
                    ep.path_params.append(p_name)

            req_body = operation.get("requestBody", {})
            if isinstance(req_body, dict):
                content = req_body.get("content", {})
                for ct in ("application/json", "application/x-www-form-urlencoded"):
                    schema = content.get(ct, {}).get("schema", {})
                    if schema:
                        ep.json_body_schema = _resolve_schema(schema, spec)
                        ep.content_type = ct
                        break

            if not ep.json_body_schema:
                for p in all_params:
                    if isinstance(p, dict) and p.get("in") == "body":
                        schema = p.get("schema", {})
                        if schema:
                            ep.json_body_schema = _resolve_schema(schema, spec)
                            ep.content_type = "application/json"
                        break

            endpoints.append(ep)

    return endpoints, flat_paths


def _resolve_schema(schema: dict, spec: dict, depth: int = 0) -> dict:
    """
    Resolve $ref pointers in an OpenAPI schema (up to depth 5 to avoid
    infinite loops on circular references). Returns the resolved schema dict.
    """
    if depth > 5:
        return schema
    ref = schema.get("$ref")
    if ref and isinstance(ref, str):
        # e.g. "#/definitions/User" or "#/components/schemas/User"
        parts = ref.lstrip("#/").split("/")
        resolved = spec
        for part in parts:
            if isinstance(resolved, dict):
                resolved = resolved.get(part, {})
            else:
                return schema
        if isinstance(resolved, dict):
            return _resolve_schema(resolved, spec, depth + 1)
    # Resolve properties recursively
    if "properties" in schema and isinstance(schema["properties"], dict):
        resolved_props = {}
        for prop_name, prop_schema in schema["properties"].items():
            if isinstance(prop_schema, dict):
                resolved_props[prop_name] = _resolve_schema(prop_schema, spec, depth + 1)
            else:
                resolved_props[prop_name] = prop_schema
        schema = {**schema, "properties": resolved_props}
    return schema


# ---------------------------------------------------------------------------
# Phase 2: Passive JS bundle scraping
# ---------------------------------------------------------------------------

async def _extract_routes_from_js(
    client: httpx.AsyncClient,
    base_url: str,
    ctx: ScanContext,
    scan_id: Optional[str] = None,
) -> Set[str]:
    """
    Fetch the target's HTML page, find <script src="..."> tags, download
    each JS bundle (up to 15), and regex for API endpoint strings.
    """
    discovered: Set[str] = set()
    try:
        await ctx.throttle()
        resp = await client.get(base_url, timeout=8.0, follow_redirects=True)
        if scan_id:
            db.log_request(scan_id, base_url, "api_discovery", "GET", base_url,
                           resp.status_code)
        if resp.status_code != 200:
            return discovered

        # Also regex the HTML itself (inline <script> blocks)
        _extract_from_text(resp.text, discovered)

        # Extract external JS bundle links
        js_urls = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', resp.text)
        seen: Set[str] = set()
        for js_url in js_urls:
            if js_url in seen or len(seen) >= 15:
                continue
            seen.add(js_url)

            full_js_url = urljoin(base_url, js_url)
            parsed_host = urlparse(full_js_url).hostname
            if not parsed_host:
                continue
            # Only fetch JS from in-scope hosts (CDN scripts are noise)
            try:
                ctx.assert_in_scope(parsed_host)
            except Exception:
                continue

            try:
                await ctx.throttle()
                js_resp = await client.get(full_js_url, timeout=8.0)
                if scan_id:
                    db.log_request(scan_id, base_url, "api_discovery", "GET",
                                   full_js_url, js_resp.status_code)
                if js_resp.status_code == 200:
                    _extract_from_text(js_resp.text, discovered)
            except httpx.RequestError:
                continue
    except httpx.RequestError:
        pass
    return discovered


def _extract_from_text(text: str, out: Set[str]) -> None:
    """Apply all JS route patterns against a text blob, collecting clean paths."""
    for pattern in JS_ROUTE_PATTERNS:
        for match in re.findall(pattern, text):
            clean = match.strip().lstrip("/")
            if not clean or len(clean) < 2 or len(clean) > 200:
                continue
            if clean.endswith(STATIC_ASSET_EXTENSIONS):
                continue
            # Skip pure protocol strings or data URIs
            if clean.startswith(("http:", "https:", "data:", "mailto:", "//")):
                continue
            out.add(clean)


# ---------------------------------------------------------------------------
# Phase 2b: HTML form action & anchor link scraping
# ---------------------------------------------------------------------------

async def _extract_routes_from_html(
    client: httpx.AsyncClient,
    base_url: str,
    ctx: ScanContext,
    scan_id: Optional[str] = None,
) -> Tuple[Set[str], List[APIEndpoint]]:
    """
    Parse HTML <form action="..."> and <a href="..."> tags to discover
    endpoints that aren't in JS bundles or specs. Forms also give us the
    HTTP method (form method="POST") and input field names.
    """
    discovered_paths: Set[str] = set()
    discovered_endpoints: List[APIEndpoint] = []

    try:
        await ctx.throttle()
        resp = await client.get(base_url, timeout=8.0, follow_redirects=True)
        if scan_id:
            db.log_request(scan_id, base_url, "api_discovery", "GET", base_url,
                           resp.status_code)
        if resp.status_code != 200:
            return discovered_paths, discovered_endpoints

        html = resp.text

        # Extract <form action="/path" method="POST">
        form_pattern = r'<form[^>]*action=["\']([^"\']+)["\'][^>]*(?:method=["\']([^"\']*)["\'])?'
        for match in re.finditer(form_pattern, html, re.IGNORECASE):
            action = match.group(1).strip()
            method = (match.group(2) or "GET").upper()
            if action.startswith(("http:", "https:", "//", "javascript:", "mailto:", "#")):
                continue
            clean = action.lstrip("/")
            if clean and not clean.endswith(STATIC_ASSET_EXTENSIONS):
                discovered_paths.add(clean)
                ep = APIEndpoint(path=f"/{clean}", method=method, source="html_form")

                # Extract <input name="..."> within the form's context
                # (simplified: scan the full page for input names near this form)
                input_names = re.findall(
                    r'<input[^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE)
                for name in input_names:
                    if name not in ep.query_params:
                        ep.query_params.append(name)
                discovered_endpoints.append(ep)

        # Also extract form actions with method before action
        form_pattern2 = r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']+)["\']'
        for match in re.finditer(form_pattern2, html, re.IGNORECASE):
            method = (match.group(1) or "GET").upper()
            action = match.group(2).strip()
            if action.startswith(("http:", "https:", "//", "javascript:", "mailto:", "#")):
                continue
            clean = action.lstrip("/")
            if clean and not clean.endswith(STATIC_ASSET_EXTENSIONS):
                discovered_paths.add(clean)
                ep = APIEndpoint(path=f"/{clean}", method=method, source="html_form")
                discovered_endpoints.append(ep)

        # Extract <a href="/api/..."> links that look like API paths
        link_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.findall(link_pattern, html):
            href = match.strip()
            if href.startswith(("http:", "https:", "//", "javascript:", "mailto:", "#")):
                continue
            clean = href.lstrip("/").split("?")[0].split("#")[0]
            if not clean or len(clean) < 2:
                continue
            if clean.endswith(STATIC_ASSET_EXTENSIONS):
                continue
            # Only keep paths that look like API routes (not static pages)
            if any(seg in clean for seg in ("api", "v1", "v2", "graphql", "auth",
                                             "admin", "user", "search", "query")):
                discovered_paths.add(clean)

    except httpx.RequestError:
        pass

    return discovered_paths, discovered_endpoints


# ---------------------------------------------------------------------------
# Phase 2c: Parameter mining (hidden parameter discovery)
# ---------------------------------------------------------------------------

async def _mine_parameters(
    client: httpx.AsyncClient,
    base_url: str,
    paths: Set[str],
    ctx: ScanContext,
    scan_id: Optional[str] = None,
    concurrency: int = 10,
) -> Dict[str, List[str]]:
    """
    For each discovered path, try appending common query parameters and
    observe response changes. If adding ?param=test changes the response
    status or body size compared to the bare path, the param is likely
    handled by the backend — even if it's not documented anywhere.

    Returns a dict of {path: [discovered_param_names]}.
    """
    results: Dict[str, List[str]] = {}
    semaphore = asyncio.Semaphore(concurrency)

    async def probe_path(path: str):
        url_bare = f"{base_url.rstrip('/')}/{path}"

        # Get baseline response for the bare path
        await ctx.throttle()
        try:
            bare_resp = await client.get(url_bare, timeout=5.0, follow_redirects=False)
            if scan_id:
                db.log_request(scan_id, base_url, "api_discovery", "GET",
                               url_bare, bare_resp.status_code)
        except httpx.RequestError:
            return

        if bare_resp.status_code in (404, 502, 503):
            return

        bare_len = len(bare_resp.content)
        bare_status = bare_resp.status_code
        found_params: List[str] = []

        async def try_param(param_name: str):
            async with semaphore:
                test_url = f"{url_bare}?{param_name}=test"
                await ctx.throttle()
                try:
                    resp = await client.get(test_url, timeout=5.0, follow_redirects=False)
                    if scan_id:
                        db.log_request(scan_id, base_url, "api_discovery", "GET",
                                       test_url, resp.status_code)

                    resp_len = len(resp.content)
                    # A parameter is "active" if adding it changes the response
                    # in a meaningful way (different status or significant body
                    # size change), while still being a success response.
                    if resp.status_code != bare_status and resp.status_code < 400:
                        found_params.append(param_name)
                    elif (resp.status_code < 400
                          and abs(resp_len - bare_len) > 20
                          and resp_len > 0):
                        found_params.append(param_name)
                except httpx.RequestError:
                    pass

        await asyncio.gather(*(try_param(p) for p in COMMON_PARAM_NAMES))
        if found_params:
            results[path] = found_params

    # Only mine params on a subset of paths to avoid excessive requests
    paths_to_mine = sorted(paths)[:15]
    await asyncio.gather(*(probe_path(p) for p in paths_to_mine))
    return results


# ---------------------------------------------------------------------------
# Phase 3: OPTIONS method probing
# ---------------------------------------------------------------------------

async def _probe_options(
    client: httpx.AsyncClient,
    base_url: str,
    paths: Set[str],
    ctx: ScanContext,
    scan_id: Optional[str] = None,
    concurrency: int = 10,
) -> List[APIEndpoint]:
    """
    Send OPTIONS to each discovered path. Parse the Allow header to learn
    which HTTP methods the endpoint actually supports, producing richer
    APIEndpoint objects than path-only discovery.
    """
    endpoints: List[APIEndpoint] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(path: str):
        async with semaphore:
            url = f"{base_url.rstrip('/')}/{path}"
            await ctx.throttle()
            try:
                resp = await client.request("OPTIONS", url, timeout=5.0, follow_redirects=False)
                if scan_id:
                    db.log_request(scan_id, base_url, "api_discovery", "OPTIONS",
                                   url, resp.status_code)
                allow = resp.headers.get("allow", "")
                if allow:
                    for method in allow.upper().replace(" ", "").split(","):
                        method = method.strip()
                        if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            endpoints.append(APIEndpoint(
                                path=f"/{path}",
                                method=method,
                                source="options_probe",
                            ))
            except httpx.RequestError:
                pass

    await asyncio.gather(*(probe(p) for p in paths))
    return endpoints


# ---------------------------------------------------------------------------
# Phase 4: API wordlist brute-force
# ---------------------------------------------------------------------------

async def _brute_force_api_paths(
    client: httpx.AsyncClient,
    base_url: str,
    ctx: ScanContext,
    scan_id: Optional[str] = None,
    concurrency: int = 15,
) -> Set[str]:
    """
    Hit common API path conventions and keep anything that doesn't look like
    a generic "not found" response.  Uses baseline-diffing to filter custom
    404-handlers that return 200 for every path.

    Strategy:
      1. Probe a guaranteed-nonexistent canary path to capture the server's
         "unknown path" fingerprint (status + body size).
      2. Only report a path as *found* if its status or body differs
         meaningfully (>50 bytes) from that canary baseline.
    """
    found: Set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    # ------------------------------------------------------------------
    # Step 1 — establish canary baseline
    # ------------------------------------------------------------------
    canary_path = "__argus_canary_nonexistent_xzq__"
    canary_url = f"{base_url.rstrip('/')}/{canary_path}"
    await ctx.throttle()
    try:
        canary_resp = await client.get(canary_url, timeout=5.0, follow_redirects=False)
        canary_status = canary_resp.status_code
        canary_len = len(canary_resp.content)
    except httpx.RequestError:
        # If we can't reach the server at all, bail out early
        return found

    # ------------------------------------------------------------------
    # Step 2 — probe each wordlist path and diff against baseline
    # ------------------------------------------------------------------
    async def probe(path: str):
        async with semaphore:
            url = f"{base_url.rstrip('/')}/{path}"
            await ctx.throttle()
            try:
                resp = await client.get(url, timeout=5.0, follow_redirects=False)
                if scan_id:
                    db.log_request(scan_id, base_url, "api_discovery", "GET",
                                   url, resp.status_code)

                # Hard-skip known error codes regardless of baseline
                if resp.status_code in (404, 502, 503):
                    return

                # Accept if the status code differs from the canary
                if resp.status_code != canary_status:
                    found.add(path)
                    return

                # Same status as canary — only accept if body is meaningfully
                # larger (real endpoints usually return structured data)
                resp_len = len(resp.content)
                if abs(resp_len - canary_len) > 50:
                    found.add(path)
            except httpx.RequestError:
                pass

    await asyncio.gather(*(probe(p) for p in API_WORDLIST))
    return found


# ---------------------------------------------------------------------------
# Public API: full discovery pipeline
# ---------------------------------------------------------------------------

async def discover_api_routes(
    base_url: str,
    ctx: ScanContext,
    output_wordlist: Optional[str] = None,
) -> List[str]:
    """
    Backward-compatible simple interface: returns a flat list of path strings
    and optionally writes them to a wordlist file. Runs all 4 phases.
    """
    ctx.assert_in_scope(base_url)
    all_paths: Set[str] = set()

    async with httpx.AsyncClient() as client:
        # Phase 1: OpenAPI spec probing
        endpoints, spec_paths = await _parse_openapi_specs(client, base_url, ctx)
        all_paths.update(spec_paths)

        # Phase 2a: Passive JS bundle scraping
        js_paths = await _extract_routes_from_js(client, base_url, ctx)
        all_paths.update(js_paths)

        # Phase 2b: HTML form/link scraping
        html_paths, _ = await _extract_routes_from_html(client, base_url, ctx)
        all_paths.update(html_paths)

        # Phase 4 (brute-force) — only if phases 1+2 produced very little
        if len(all_paths) < 3:
            brute_paths = await _brute_force_api_paths(client, base_url, ctx)
            all_paths.update(brute_paths)

    routes_list = sorted(all_paths)

    if output_wordlist and routes_list:
        out_path = Path(output_wordlist)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("# Automatically generated by Argus API Discovery\n")
            for route in routes_list:
                f.write(f"{route}\n")

    return routes_list


async def discover_api_endpoints(
    base_url: str,
    ctx: ScanContext,
    scan_id: str,
    concurrency: int = 10,
    spec_file: Optional[str] = None,
) -> List[APIEndpoint]:
    """
    Full structured discovery: returns APIEndpoint objects with methods,
    params, and body schemas. This is what the smart param_fuzz module
    consumes for schema-aware vulnerability testing.
    """
    ctx.assert_in_scope(base_url)
    endpoint_set: Set[APIEndpoint] = set()
    all_paths: Set[str] = set()

    async with httpx.AsyncClient() as client:

        # Phase 1: OpenAPI spec (local file or live probe)
        spec_endpoints, spec_paths = await _parse_openapi_specs(
            client, base_url, ctx, scan_id=scan_id, spec_file=spec_file)
        all_paths.update(spec_paths)
        for ep in spec_endpoints:
            endpoint_set.add(ep)

        # Phase 2a: JS passive scraping (path-only)
        js_paths = await _extract_routes_from_js(
            client, base_url, ctx, scan_id=scan_id)
        all_paths.update(js_paths)

        # Phase 2b: HTML form action / anchor link scraping
        html_paths, html_endpoints = await _extract_routes_from_html(
            client, base_url, ctx, scan_id=scan_id)
        all_paths.update(html_paths)
        for ep in html_endpoints:
            endpoint_set.add(ep)

        # Phase 4: Brute-force if we have very little
        if len(all_paths) < 3:
            brute_paths = await _brute_force_api_paths(
                client, base_url, ctx, scan_id=scan_id, concurrency=concurrency)
            all_paths.update(brute_paths)

        # Phase 3: OPTIONS probing on paths not yet covered by spec
        spec_covered = {ep.path.lstrip("/") for ep in endpoint_set}
        uncovered = all_paths - spec_covered
        if uncovered:
            options_endpoints = await _probe_options(
                client, base_url, uncovered, ctx,
                scan_id=scan_id, concurrency=concurrency)
            for ep in options_endpoints:
                endpoint_set.add(ep)

        # Phase 2c: Parameter mining — discover hidden query params
        # Only run on paths that don't already have query_params from spec
        paths_without_params = {
            ep.path.lstrip("/") for ep in endpoint_set
            if not ep.query_params and ep.method == "GET"
        }
        if paths_without_params:
            mined = await _mine_parameters(
                client, base_url, paths_without_params, ctx,
                scan_id=scan_id, concurrency=concurrency)
            for path, params in mined.items():
                # Attach discovered params to matching endpoints
                for ep in endpoint_set:
                    if ep.path.lstrip("/") == path and ep.method == "GET":
                        ep.query_params.extend(params)

        # Any path still without an explicit method → default GET endpoint
        covered_paths = {ep.path.lstrip("/") for ep in endpoint_set}
        for path in all_paths:
            if path not in covered_paths:
                endpoint_set.add(APIEndpoint(
                    path=f"/{path}",
                    method="GET",
                    source="js_passive" if path in js_paths else "wordlist",
                ))

    result = sorted(endpoint_set, key=lambda e: (e.path, e.method))

    # Log discovery summary as findings
    if result:
        db.add_finding(
            scan_id=scan_id,
            target=base_url,
            module="api_discovery",
            vuln_type="misconfig",
            confidence="confirmed",
            url=base_url,
            request_evidence=f"Probed {len(OPENAPI_SPEC_PATHS)} spec paths + JS scraping + OPTIONS + brute-force",
            response_evidence=f"Discovered {len(result)} API endpoint(s) across {len(all_paths)} unique paths",
            description=(
                f"API surface discovery found {len(result)} endpoint(s). "
                f"Sources: {', '.join(sorted({e.source for e in result}))}. "
                f"Paths: {', '.join(sorted(all_paths)[:10])}{'...' if len(all_paths) > 10 else ''}"
            ),
            source_surface="cli",
        )

    return result


# ---------------------------------------------------------------------------
# Helpers for generating schema-compliant test payloads
# ---------------------------------------------------------------------------

def generate_baseline_body(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given an OpenAPI schema dict (potentially with resolved $refs), generate
    a minimal valid JSON body with placeholder values that satisfy type
    constraints. This baseline passes server-side schema validation so that
    fuzzing payloads injected into individual fields actually reach the
    application logic instead of being rejected at the validation layer.
    """
    if not schema or not isinstance(schema, dict):
        return {}

    properties = schema.get("properties", {})
    if not properties:
        # allOf / oneOf / anyOf — take the first schema's properties
        for key in ("allOf", "oneOf", "anyOf"):
            variants = schema.get(key, [])
            if variants and isinstance(variants, list):
                for v in variants:
                    if isinstance(v, dict) and "properties" in v:
                        properties = v["properties"]
                        break
                if properties:
                    break

    body: Dict[str, Any] = {}
    for prop_name, prop_schema in properties.items():
        if not isinstance(prop_schema, dict):
            body[prop_name] = ""
            continue
        body[prop_name] = _generate_value(prop_schema)
    return body


def _generate_value(schema: dict) -> Any:
    """Generate a single placeholder value for a schema property."""
    prop_type = schema.get("type", "string")
    example = schema.get("example")
    if example is not None:
        return example
    default = schema.get("default")
    if default is not None:
        return default
    enum = schema.get("enum")
    if enum and isinstance(enum, list):
        return enum[0]

    if prop_type == "string":
        fmt = schema.get("format", "")
        if fmt == "email":
            return "test@example.com"
        if fmt == "date":
            return "2024-01-01"
        if fmt == "date-time":
            return "2024-01-01T00:00:00Z"
        if fmt == "uri" or fmt == "url":
            return "https://example.com"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return "test"
    elif prop_type == "integer":
        return schema.get("minimum", 1)
    elif prop_type == "number":
        return schema.get("minimum", 1.0)
    elif prop_type == "boolean":
        return False
    elif prop_type == "array":
        items = schema.get("items", {})
        return [_generate_value(items)] if isinstance(items, dict) else []
    elif prop_type == "object":
        return generate_baseline_body(schema)
    return ""
