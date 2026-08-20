"""
Argus — Parameter Fuzzing (FR-4)

Two operating modes:

  MODE 1: Legacy single-parameter fuzzing (fuzz_parameter)
      Injects SQLi/XSS/RCE payloads into a single named URL query parameter.
      This is the original interface used by `--param <name>`.

  MODE 2: Schema-aware endpoint fuzzing (fuzz_api_endpoints)
      Consumes APIEndpoint objects from api_discovery.py. For each endpoint:
        - Generates a schema-compliant baseline request (correct method,
          content-type, path params, query params, JSON body).
        - Injects payloads into EACH field individually while keeping
          other fields valid → bypasses server-side schema validation.
        - Tests for: SQLi, XSS, IDOR/BOLA, mass assignment, type confusion.

Detection methods (FR-4.3):
  - Reflected XSS: payload marker reflected unescaped in the response body.
  - Error-based SQLi: SQL error signatures in the response.
  - Blind/timing-based SQLi: compare response time of a delay payload against
    a baseline request on the SAME endpoint.
  - IDOR/BOLA: path param ID mutation returns different-user data (200 + body change).
  - Mass assignment: adding admin fields to POST/PUT bodies triggers privilege change.
  - Type confusion: sending wrong types causes 500 errors or stack trace leaks.

Findings are labeled confirmed/suspected per FR-4.4:
  - confirmed: signature/reflection match (strong evidence)
  - suspected: timing-only heuristic or behavioral anomaly (weaker)

This is an ACTIVE module -- requires --i-own-this (FR-0.3).
"""

import asyncio
import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from core.auth_gate import ScanContext
from core import db

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

XSS_MARKER = "argusXSS7f3a"
XSS_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"'><img src=x onerror=alert('{XSS_MARKER}')>",
]

SQLI_ERROR_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1' AND '1'='2",
    "\" OR \"1\"=\"1",
]

SQLI_TIMING_PAYLOADS = [
    "1' AND SLEEP(3)-- -",
    "1) AND SLEEP(3)-- -",
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate",
    "sqlite3.operationalerror",
    "pg_query()",
    "odbc sql server driver",
    "postgresql query failed",
    "syntax error at or near",
    "ora-01756",
]

# Stack trace / debug leak signatures (for type confusion detection)
STACK_TRACE_SIGNATURES = [
    "traceback (most recent call last)",
    "internal server error",
    "exception in thread",
    "at java.",
    "at org.",
    "at com.",
    "stack trace:",
    "unhandled exception",
    "typeerror:",
    "valueerror:",
    "keyerror:",
    "attributeerror:",
    "nullpointerexception",
    "classcastexception",
]

# Mass assignment fields — extra admin/privilege fields to inject
MASS_ASSIGNMENT_FIELDS = {
    "is_admin": True,
    "role": "admin",
    "is_superuser": True,
    "admin": True,
    "role_id": 1,
    "permissions": ["admin", "write", "delete"],
    "is_staff": True,
    "privilege": "root",
}

ENCODING_VARIANTS = ["raw", "url", "double_url", "unicode"]


def _encode_payload(payload: str, variant: str) -> str:
    if variant == "raw":
        return payload
    if variant == "url":
        return urllib.parse.quote(payload)
    if variant == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    if variant == "unicode":
        return "".join(f"%u{ord(c):04x}" if not c.isalnum() else c for c in payload)
    return payload


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class ParamFinding:
    url: str
    parameter: str
    vuln_type: str   # XSS | SQLi | RCE | IDOR | mass_assignment | type_confusion
    confidence: str  # confirmed | suspected
    payload: str
    encoding: str
    evidence: str


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _timed_get(client: httpx.AsyncClient, url: str, ctx: ScanContext):
    await ctx.throttle()
    start = time.monotonic()
    try:
        resp = await client.get(url, timeout=10.0, follow_redirects=False)
        elapsed = time.monotonic() - start
        return resp, elapsed
    except httpx.RequestError:
        return None, time.monotonic() - start


async def _timed_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    ctx: ScanContext,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    data: Optional[str] = None,
) -> tuple:
    """Generic timed request supporting any HTTP method and body type."""
    await ctx.throttle()
    start = time.monotonic()
    try:
        kwargs = {"timeout": 10.0, "follow_redirects": False}
        if headers:
            kwargs["headers"] = headers
        if json_body is not None:
            kwargs["json"] = json_body
        elif data is not None:
            kwargs["content"] = data

        resp = await client.request(method, url, **kwargs)
        elapsed = time.monotonic() - start
        return resp, elapsed
    except httpx.RequestError:
        return None, time.monotonic() - start


# =========================================================================
# MODE 1: Legacy single-parameter fuzzing (unchanged public interface)
# =========================================================================

async def fuzz_parameter(
    base_url: str,
    param: str,
    ctx: ScanContext,
    scan_id: str,
    encodings: List[str] = None,
) -> List[ParamFinding]:
    """
    Fuzzes a single parameter on base_url with XSS + SQLi payloads across
    encoding variants (FR-4.2). Requires active confirmation (FR-0.3).
    """
    ctx.assert_in_scope(base_url)
    ctx.assert_active_allowed()

    encodings = encodings or ENCODING_VARIANTS
    findings: List[ParamFinding] = []

    async with httpx.AsyncClient() as client:
        # --- Reflected XSS detection ---
        for payload in XSS_PAYLOADS:
            for enc in encodings:
                encoded = _encode_payload(payload, enc)
                url = _inject_param(base_url, param, encoded)
                resp, elapsed = await _timed_get(client, url, ctx)
                db.log_request(scan_id, base_url, "param_fuzz", "GET", url,
                                resp.status_code if resp else 0)
                if resp is None:
                    continue
                # Confirmed: our marker shows up unescaped in the response
                if XSS_MARKER in resp.text and f"&lt;script&gt;" not in resp.text.split(XSS_MARKER)[0][-20:]:
                    if payload in resp.text or f"alert('{XSS_MARKER}')" in resp.text:
                        finding = ParamFinding(
                            url=base_url, parameter=param, vuln_type="XSS",
                            confidence="confirmed", payload=payload, encoding=enc,
                            evidence=f"Payload marker '{XSS_MARKER}' reflected unescaped in response.",
                        )
                        findings.append(finding)
                        db.add_finding(
                            scan_id=scan_id, target=base_url, module="param_fuzz",
                            vuln_type="XSS", confidence="confirmed",
                            url=url, parameter=param,
                            request_evidence=f"GET {url}",
                            response_evidence=f"Reflected: ...{resp.text[max(0, resp.text.find(XSS_MARKER)-30):resp.text.find(XSS_MARKER)+50]}...",
                            description=f"Reflected XSS in parameter '{param}' ({enc} encoding). "
                                        f"Payload reflected unescaped in response body.",
                            source_surface="cli",
                        )
                        break  # one confirmed hit per payload is enough signal

        # --- Error-based SQLi detection ---
        for payload in SQLI_ERROR_PAYLOADS:
            for enc in encodings:
                encoded = _encode_payload(payload, enc)
                url = _inject_param(base_url, param, encoded)
                resp, elapsed = await _timed_get(client, url, ctx)
                db.log_request(scan_id, base_url, "param_fuzz", "GET", url,
                                resp.status_code if resp else 0)
                if resp is None:
                    continue
                body_lower = resp.text.lower()
                matched_sig = next((sig for sig in SQL_ERROR_SIGNATURES if sig in body_lower), None)
                if matched_sig:
                    finding = ParamFinding(
                        url=base_url, parameter=param, vuln_type="SQLi",
                        confidence="confirmed", payload=payload, encoding=enc,
                        evidence=f"SQL error signature matched: '{matched_sig}'",
                    )
                    findings.append(finding)
                    db.add_finding(
                        scan_id=scan_id, target=base_url, module="param_fuzz",
                        vuln_type="SQLi", confidence="confirmed",
                        url=url, parameter=param,
                        request_evidence=f"GET {url}",
                        response_evidence=f"SQL error signature found: '{matched_sig}'",
                        description=f"Error-based SQLi in parameter '{param}' ({enc} encoding). "
                                    f"Database error signature leaked in response.",
                        source_surface="cli",
                    )

        # --- Blind/timing-based SQLi detection ---
        baseline_url = _inject_param(base_url, param, "1")
        baseline_resp, baseline_time = await _timed_get(client, baseline_url, ctx)
        db.log_request(scan_id, base_url, "param_fuzz", "GET", baseline_url,
                        baseline_resp.status_code if baseline_resp else 0)

        for payload in SQLI_TIMING_PAYLOADS:
            url = _inject_param(base_url, param, payload)
            resp, elapsed = await _timed_get(client, url, ctx)
            db.log_request(scan_id, base_url, "param_fuzz", "GET", url,
                            resp.status_code if resp else 0)
            if resp is None:
                continue
            if elapsed > baseline_time + 2.5:
                finding = ParamFinding(
                    url=base_url, parameter=param, vuln_type="SQLi",
                    confidence="suspected", payload=payload, encoding="raw",
                    evidence=f"Response time {elapsed:.2f}s vs baseline {baseline_time:.2f}s "
                             f"(delta {elapsed - baseline_time:.2f}s) on delay payload.",
                )
                findings.append(finding)
                db.add_finding(
                    scan_id=scan_id, target=base_url, module="param_fuzz",
                    vuln_type="SQLi", confidence="suspected",
                    url=url, parameter=param,
                    request_evidence=f"GET {url}",
                    response_evidence=f"Response time {elapsed:.2f}s (baseline {baseline_time:.2f}s)",
                    description=f"Possible blind/timing-based SQLi in parameter '{param}'. "
                                f"Delay payload response was {elapsed - baseline_time:.2f}s slower than baseline. "
                                f"Timing heuristics can produce false positives under network jitter -- "
                                f"treat as suspected, verify manually.",
                    source_surface="cli",
                )

    return findings


# =========================================================================
# MODE 2: Schema-aware endpoint fuzzing
# =========================================================================

async def fuzz_api_endpoints(
    base_url: str,
    endpoints: list,   # List[APIEndpoint] from api_discovery
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """
    Schema-aware fuzzing: for each APIEndpoint, build valid baseline requests
    using the endpoint's schema, then inject payloads field-by-field.

    Tests:
      1. SQLi + XSS in query parameters
      2. SQLi + XSS in JSON body string fields
      3. IDOR in path parameters (ID mutation)
      4. Mass assignment (extra admin fields in POST/PUT bodies)
      5. Type confusion (wrong types → 500 / stack trace leak)
    """
    ctx.assert_in_scope(base_url)
    ctx.assert_active_allowed()

    findings: List[ParamFinding] = []

    # Import here to avoid circular dependency
    from core.api_discovery import generate_baseline_body

    async with httpx.AsyncClient() as client:
        for ep in endpoints:
            endpoint_url = f"{base_url.rstrip('/')}{ep.path}"

            # Replace path params with baseline values for a valid URL
            resolved_url = _resolve_path_params(endpoint_url, ep.path_params)

            # --- 1. Query parameter injection (SQLi + XSS) ---
            if ep.query_params:
                for qp in ep.query_params:
                    qp_findings = await _fuzz_query_param(
                        client, resolved_url, ep.method, qp, ctx, scan_id)
                    findings.extend(qp_findings)

            # --- 2. JSON body field injection (SQLi + XSS) ---
            if ep.json_body_schema and ep.method in ("POST", "PUT", "PATCH"):
                baseline_body = generate_baseline_body(ep.json_body_schema)
                if baseline_body:
                    body_findings = await _fuzz_json_body(
                        client, resolved_url, ep.method, baseline_body,
                        ep.content_type or "application/json", ctx, scan_id)
                    findings.extend(body_findings)

                    # --- 4. Mass assignment ---
                    mass_findings = await _test_mass_assignment(
                        client, resolved_url, ep.method, baseline_body,
                        ep.content_type or "application/json", ctx, scan_id)
                    findings.extend(mass_findings)

                    # --- 5. Type confusion ---
                    type_findings = await _test_type_confusion(
                        client, resolved_url, ep.method, baseline_body,
                        ep.json_body_schema,
                        ep.content_type or "application/json", ctx, scan_id)
                    findings.extend(type_findings)

            # --- 3. IDOR in path parameters ---
            if ep.path_params and ep.method == "GET":
                idor_findings = await _test_idor(
                    client, endpoint_url, ep.path_params, ctx, scan_id)
                findings.extend(idor_findings)

            # --- 6. Header injection (SQLi/XSS via common injectable headers) ---
            header_findings = await _test_header_injection(
                client, resolved_url, ep.method, ctx, scan_id)
            findings.extend(header_findings)

    return findings


def _resolve_path_params(url: str, path_params: List[str]) -> str:
    """Replace {param} placeholders with benign test values."""
    resolved = url
    for param in path_params:
        placeholder = f"{{{param}}}"
        if placeholder in resolved:
            resolved = resolved.replace(placeholder, "1")
    return resolved


# ---------------------------------------------------------------------------
# Test: Query parameter injection (SQLi + XSS)
# ---------------------------------------------------------------------------

async def _fuzz_query_param(
    client: httpx.AsyncClient,
    base_url: str,
    method: str,
    param: str,
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """Inject SQLi/XSS payloads into a single query parameter."""
    findings: List[ParamFinding] = []

    # XSS
    for payload in XSS_PAYLOADS:
        url = _inject_param(base_url, param, payload)
        resp, elapsed = await _timed_request(client, method, url, ctx)
        db.log_request(scan_id, base_url, "param_fuzz", method, url,
                        resp.status_code if resp else 0)
        if resp and XSS_MARKER in resp.text:
            if payload in resp.text or f"alert('{XSS_MARKER}')" in resp.text:
                findings.append(ParamFinding(
                    url=base_url, parameter=param, vuln_type="XSS",
                    confidence="confirmed", payload=payload, encoding="raw",
                    evidence=f"Reflected XSS marker in {method} {url}",
                ))
                db.add_finding(
                    scan_id=scan_id, target=base_url, module="param_fuzz",
                    vuln_type="XSS", confidence="confirmed",
                    url=url, parameter=param,
                    request_evidence=f"{method} {url}",
                    response_evidence=f"XSS marker '{XSS_MARKER}' reflected unescaped",
                    description=f"Reflected XSS in query param '{param}' via {method}. "
                                f"Payload reflected unescaped in response body.",
                    source_surface="cli",
                )
                break

    # SQLi (error-based)
    for payload in SQLI_ERROR_PAYLOADS:
        url = _inject_param(base_url, param, payload)
        resp, elapsed = await _timed_request(client, method, url, ctx)
        db.log_request(scan_id, base_url, "param_fuzz", method, url,
                        resp.status_code if resp else 0)
        if resp:
            body_lower = resp.text.lower()
            matched = next((s for s in SQL_ERROR_SIGNATURES if s in body_lower), None)
            if matched:
                findings.append(ParamFinding(
                    url=base_url, parameter=param, vuln_type="SQLi",
                    confidence="confirmed", payload=payload, encoding="raw",
                    evidence=f"SQL error signature: '{matched}'",
                ))
                db.add_finding(
                    scan_id=scan_id, target=base_url, module="param_fuzz",
                    vuln_type="SQLi", confidence="confirmed",
                    url=url, parameter=param,
                    request_evidence=f"{method} {url}",
                    response_evidence=f"SQL error signature: '{matched}'",
                    description=f"Error-based SQLi in query param '{param}' via {method}.",
                    source_surface="cli",
                )
                break

    return findings


# ---------------------------------------------------------------------------
# Test: JSON body field injection (SQLi + XSS)
# ---------------------------------------------------------------------------

async def _fuzz_json_body(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    baseline_body: Dict[str, Any],
    content_type: str,
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """
    For each string field in the baseline JSON body, inject SQLi/XSS payloads
    one field at a time while keeping all other fields valid.
    """
    findings: List[ParamFinding] = []
    headers = {"Content-Type": content_type}

    string_fields = [k for k, v in baseline_body.items() if isinstance(v, str)]

    for field_name in string_fields:
        # XSS in JSON body field
        for payload in XSS_PAYLOADS[:2]:  # test first 2 XSS payloads
            fuzzed = {**baseline_body, field_name: payload}
            resp, elapsed = await _timed_request(
                client, method, url, ctx, headers=headers, json_body=fuzzed)
            db.log_request(scan_id, url, "param_fuzz", method,
                            f"{url} [body.{field_name}={payload[:30]}]",
                            resp.status_code if resp else 0)
            if resp and XSS_MARKER in resp.text:
                findings.append(ParamFinding(
                    url=url, parameter=f"body.{field_name}", vuln_type="XSS",
                    confidence="confirmed", payload=payload, encoding="raw",
                    evidence=f"XSS marker reflected in JSON response for field '{field_name}'",
                ))
                db.add_finding(
                    scan_id=scan_id, target=url, module="param_fuzz",
                    vuln_type="XSS", confidence="confirmed",
                    url=url, parameter=f"body.{field_name}",
                    request_evidence=f"{method} {url}\nBody: {json.dumps(fuzzed)[:200]}",
                    response_evidence=f"XSS marker reflected in response body",
                    description=f"Reflected XSS in JSON body field '{field_name}' via {method}.",
                    source_surface="cli",
                )
                break

        # SQLi in JSON body field
        for payload in SQLI_ERROR_PAYLOADS[:2]:
            fuzzed = {**baseline_body, field_name: payload}
            resp, elapsed = await _timed_request(
                client, method, url, ctx, headers=headers, json_body=fuzzed)
            db.log_request(scan_id, url, "param_fuzz", method,
                            f"{url} [body.{field_name}={payload[:30]}]",
                            resp.status_code if resp else 0)
            if resp:
                body_lower = resp.text.lower()
                matched = next((s for s in SQL_ERROR_SIGNATURES if s in body_lower), None)
                if matched:
                    findings.append(ParamFinding(
                        url=url, parameter=f"body.{field_name}", vuln_type="SQLi",
                        confidence="confirmed", payload=payload, encoding="raw",
                        evidence=f"SQL error in JSON field '{field_name}': '{matched}'",
                    ))
                    db.add_finding(
                        scan_id=scan_id, target=url, module="param_fuzz",
                        vuln_type="SQLi", confidence="confirmed",
                        url=url, parameter=f"body.{field_name}",
                        request_evidence=f"{method} {url}\nBody: {json.dumps(fuzzed)[:200]}",
                        response_evidence=f"SQL error signature: '{matched}'",
                        description=f"Error-based SQLi in JSON body field '{field_name}' via {method}.",
                        source_surface="cli",
                    )
                    break

    return findings


# ---------------------------------------------------------------------------
# Test: IDOR / BOLA (Broken Object-Level Authorization)
# ---------------------------------------------------------------------------

async def _test_idor(
    client: httpx.AsyncClient,
    url_template: str,
    path_params: List[str],
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """
    For each path parameter (e.g. {userId}), request the resource with
    two different IDs and compare. If both return 200 with different
    bodies, that's a suspected IDOR — the endpoint doesn't enforce
    authorization based on the authenticated user's identity.
    """
    findings: List[ParamFinding] = []

    for param in path_params:
        placeholder = f"{{{param}}}"
        if placeholder not in url_template:
            continue

        # Two different IDs
        url_a = url_template.replace(placeholder, "1")
        url_b = url_template.replace(placeholder, "2")

        # Fill remaining placeholders
        url_a = _fill_remaining_placeholders(url_a)
        url_b = _fill_remaining_placeholders(url_b)

        resp_a, _ = await _timed_request(client, "GET", url_a, ctx)
        db.log_request(scan_id, url_template, "param_fuzz", "GET", url_a,
                        resp_a.status_code if resp_a else 0)
        resp_b, _ = await _timed_request(client, "GET", url_b, ctx)
        db.log_request(scan_id, url_template, "param_fuzz", "GET", url_b,
                        resp_b.status_code if resp_b else 0)

        if (resp_a and resp_b
                and resp_a.status_code == 200
                and resp_b.status_code == 200
                and resp_a.text != resp_b.text
                and len(resp_a.text) > 10
                and len(resp_b.text) > 10):
            findings.append(ParamFinding(
                url=url_template, parameter=f"path.{param}",
                vuln_type="IDOR",
                confidence="suspected",
                payload=f"{param}=1 vs {param}=2",
                encoding="raw",
                evidence=(f"Both IDs returned 200 with different bodies "
                          f"({len(resp_a.text)}b vs {len(resp_b.text)}b). "
                          f"Possible missing authorization check."),
            ))
            db.add_finding(
                scan_id=scan_id, target=url_template, module="param_fuzz",
                vuln_type="misconfig", confidence="suspected",
                url=url_a, parameter=f"path.{param}",
                request_evidence=f"GET {url_a}\nGET {url_b}",
                response_evidence=(f"ID=1: {resp_a.status_code}, {len(resp_a.text)}b | "
                                   f"ID=2: {resp_b.status_code}, {len(resp_b.text)}b"),
                description=(f"Possible IDOR/BOLA on path param '{param}'. "
                             f"Two different resource IDs both returned 200 with distinct "
                             f"response bodies, suggesting the endpoint may not enforce "
                             f"object-level authorization."),
                source_surface="cli",
            )

    return findings


def _fill_remaining_placeholders(url: str) -> str:
    """Replace any leftover {param} placeholders with '1'."""
    import re
    return re.sub(r'\{[^}]+\}', '1', url)


# ---------------------------------------------------------------------------
# Test: Mass assignment
# ---------------------------------------------------------------------------

async def _test_mass_assignment(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    baseline_body: Dict[str, Any],
    content_type: str,
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """
    Send a POST/PUT with extra admin/privilege fields appended to the
    baseline body. If the server returns 200/201 (instead of 400/422 for
    unexpected fields), it may be accepting and processing unintended fields.
    """
    findings: List[ParamFinding] = []
    if method not in ("POST", "PUT", "PATCH"):
        return findings

    headers = {"Content-Type": content_type}

    # First, send the clean baseline to get the expected response
    baseline_resp, _ = await _timed_request(
        client, method, url, ctx, headers=headers, json_body=baseline_body)
    db.log_request(scan_id, url, "param_fuzz", method,
                    f"{url} [baseline body]",
                    baseline_resp.status_code if baseline_resp else 0)
    if baseline_resp is None:
        return findings

    # Now send with extra admin fields injected
    poisoned_body = {**baseline_body, **MASS_ASSIGNMENT_FIELDS}
    poisoned_resp, _ = await _timed_request(
        client, method, url, ctx, headers=headers, json_body=poisoned_body)
    db.log_request(scan_id, url, "param_fuzz", method,
                    f"{url} [mass_assignment body]",
                    poisoned_resp.status_code if poisoned_resp else 0)

    if poisoned_resp is None:
        return findings

    # If the poisoned request succeeds (2xx) and baseline also succeeds,
    # check if the response body reflects any of the injected admin fields
    if poisoned_resp.status_code in range(200, 300):
        resp_lower = poisoned_resp.text.lower()
        reflected_fields = []
        for field_name in MASS_ASSIGNMENT_FIELDS:
            if field_name in resp_lower:
                reflected_fields.append(field_name)

        if reflected_fields:
            findings.append(ParamFinding(
                url=url, parameter=f"body.[injected]",
                vuln_type="misconfig",
                confidence="suspected",
                payload=json.dumps({k: v for k, v in MASS_ASSIGNMENT_FIELDS.items()
                                    if k in reflected_fields}),
                encoding="raw",
                evidence=(f"Mass assignment: injected fields {reflected_fields} "
                          f"reflected in {poisoned_resp.status_code} response."),
            ))
            db.add_finding(
                scan_id=scan_id, target=url, module="param_fuzz",
                vuln_type="misconfig", confidence="suspected",
                url=url, parameter="body.[mass_assignment]",
                request_evidence=f"{method} {url}\nBody: {json.dumps(poisoned_body)[:300]}",
                response_evidence=(f"Status {poisoned_resp.status_code}, "
                                   f"reflected admin fields: {reflected_fields}"),
                description=(f"Possible mass assignment vulnerability. Extra admin fields "
                             f"({', '.join(reflected_fields)}) were accepted and reflected "
                             f"in the response, suggesting the server processes unintended "
                             f"properties without field whitelisting."),
                source_surface="cli",
            )

    return findings


# ---------------------------------------------------------------------------
# Test: Type confusion / null injection
# ---------------------------------------------------------------------------

async def _test_type_confusion(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    baseline_body: Dict[str, Any],
    schema: Dict[str, Any],
    content_type: str,
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """
    Send wrong types for schema fields and check for 500 errors or
    stack trace leaks. If a field expects 'integer', send a string;
    if it expects 'string', send null or an array.
    """
    findings: List[ParamFinding] = []
    if method not in ("POST", "PUT", "PATCH"):
        return findings

    headers = {"Content-Type": content_type}
    properties = schema.get("properties", {})
    if not properties:
        return findings

    type_confusion_payloads = {
        "string": [None, 12345, True, [], {"nested": "object"}],
        "integer": ["not_a_number", None, True, [], "1; DROP TABLE users--"],
        "number": ["not_a_number", None, [], "NaN", "Infinity"],
        "boolean": ["yes", None, 0, "true", [], 999],
        "array": [None, "not_an_array", 42, True, {"key": "val"}],
        "object": [None, "not_an_object", 42, True, []],
    }

    for field_name, prop_schema in properties.items():
        if not isinstance(prop_schema, dict):
            continue
        expected_type = prop_schema.get("type", "string")
        payloads = type_confusion_payloads.get(expected_type, [None, 42, "unexpected"])

        for payload in payloads[:2]:  # limit to 2 type confusion tests per field
            confused_body = {**baseline_body, field_name: payload}
            resp, _ = await _timed_request(
                client, method, url, ctx, headers=headers, json_body=confused_body)
            db.log_request(scan_id, url, "param_fuzz", method,
                            f"{url} [type_confusion {field_name}={payload!r}]",
                            resp.status_code if resp else 0)
            if resp is None:
                continue

            # Check for 500 errors with stack trace leaks
            if resp.status_code >= 500:
                body_lower = resp.text.lower()
                leaked_traces = [s for s in STACK_TRACE_SIGNATURES if s in body_lower]
                if leaked_traces:
                    findings.append(ParamFinding(
                        url=url, parameter=f"body.{field_name}",
                        vuln_type="misconfig",
                        confidence="confirmed",
                        payload=repr(payload),
                        encoding="raw",
                        evidence=(f"Type confusion on '{field_name}' (expected {expected_type}, "
                                  f"sent {type(payload).__name__}) caused {resp.status_code} "
                                  f"with stack trace leak: {leaked_traces[:2]}"),
                    ))
                    db.add_finding(
                        scan_id=scan_id, target=url, module="param_fuzz",
                        vuln_type="misconfig", confidence="confirmed",
                        url=url, parameter=f"body.{field_name}",
                        request_evidence=(f"{method} {url}\n"
                                          f"Body: {json.dumps(confused_body, default=str)[:200]}"),
                        response_evidence=(f"Status {resp.status_code}, "
                                           f"stack trace signatures: {leaked_traces[:2]}"),
                        description=(f"Type confusion in JSON field '{field_name}': sending "
                                     f"{type(payload).__name__} instead of {expected_type} caused "
                                     f"a {resp.status_code} error with debug information leaked. "
                                     f"This reveals internal implementation details and suggests "
                                     f"missing input validation."),
                        source_surface="cli",
                    )
                    break  # one confirmed finding per field is enough

    return findings


# ---------------------------------------------------------------------------
# Test: Header injection (SQLi/XSS via injectable HTTP headers)
# ---------------------------------------------------------------------------

# Headers commonly logged/reflected/processed by backends without sanitization
INJECTABLE_HEADERS = [
    "X-Forwarded-For",
    "Referer",
    "User-Agent",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Origin",
    "X-Custom-IP-Authorization",
]


async def _test_header_injection(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    ctx: ScanContext,
    scan_id: str,
) -> List[ParamFinding]:
    """
    Inject SQLi/XSS payloads into common HTTP headers that many backends
    log, reflect, or process without sanitization (e.g. X-Forwarded-For
    gets written to access logs and sometimes rendered in admin dashboards;
    Referer/User-Agent get echoed in error pages).
    """
    findings: List[ParamFinding] = []

    # XSS via headers (check if marker gets reflected in response)
    for header_name in INJECTABLE_HEADERS:
        xss_payload = f"<script>alert('{XSS_MARKER}')</script>"
        headers = {header_name: xss_payload}
        resp, _ = await _timed_request(client, method, url, ctx, headers=headers)
        db.log_request(scan_id, url, "param_fuzz", method,
                        f"{url} [header:{header_name}=XSS]",
                        resp.status_code if resp else 0)
        if resp and XSS_MARKER in resp.text:
            findings.append(ParamFinding(
                url=url, parameter=f"header.{header_name}",
                vuln_type="XSS", confidence="confirmed",
                payload=xss_payload, encoding="raw",
                evidence=f"XSS marker reflected via {header_name} header",
            ))
            db.add_finding(
                scan_id=scan_id, target=url, module="param_fuzz",
                vuln_type="XSS", confidence="confirmed",
                url=url, parameter=f"header.{header_name}",
                request_evidence=f"{method} {url}\n{header_name}: {xss_payload}",
                response_evidence=f"XSS marker '{XSS_MARKER}' reflected in response",
                description=f"Reflected XSS via {header_name} header. The header value "
                            f"is echoed in the response without sanitization.",
                source_surface="cli",
            )
            break  # one confirmed XSS via headers is enough

    # SQLi via headers (check for SQL error signatures)
    for header_name in INJECTABLE_HEADERS[:4]:  # test top 4 headers
        sqli_payload = "' OR '1'='1"
        headers = {header_name: sqli_payload}
        resp, _ = await _timed_request(client, method, url, ctx, headers=headers)
        db.log_request(scan_id, url, "param_fuzz", method,
                        f"{url} [header:{header_name}=SQLi]",
                        resp.status_code if resp else 0)
        if resp:
            body_lower = resp.text.lower()
            matched = next((s for s in SQL_ERROR_SIGNATURES if s in body_lower), None)
            if matched:
                findings.append(ParamFinding(
                    url=url, parameter=f"header.{header_name}",
                    vuln_type="SQLi", confidence="confirmed",
                    payload=sqli_payload, encoding="raw",
                    evidence=f"SQL error via {header_name}: '{matched}'",
                ))
                db.add_finding(
                    scan_id=scan_id, target=url, module="param_fuzz",
                    vuln_type="SQLi", confidence="confirmed",
                    url=url, parameter=f"header.{header_name}",
                    request_evidence=f"{method} {url}\n{header_name}: {sqli_payload}",
                    response_evidence=f"SQL error signature: '{matched}'",
                    description=f"Error-based SQLi via {header_name} header. The header "
                                f"value reaches a SQL query without parameterization.",
                    source_surface="cli",
                )
                break

    return findings


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python core/param_fuzz.py <url_with_param> <param_name>")
        print("Example: python core/param_fuzz.py 'http://127.0.0.1:8080/search?q=test' q")
        sys.exit(1)

    target_url = sys.argv[1]
    param_name = sys.argv[2]

    db.init_db()
    scan_id = db.start_scan(target_url, scope_file="scope/scope.yaml")
    ctx = ScanContext("scope/scope.yaml", confirmed_active=True, requests_per_second=15)

    results = asyncio.run(fuzz_parameter(target_url, param_name, ctx, scan_id))
    db.finish_scan(scan_id)

    print(f"\n{len(results)} finding(s):")
    for r in results:
        print(f"  [{r.confidence}] {r.vuln_type} in '{r.parameter}' ({r.encoding}): {r.evidence}")
