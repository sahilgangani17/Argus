"""
Argus — Parameter Fuzzing (FR-4)

Injects SQLi/XSS/RCE signature-heuristic payloads into discovered URL
parameters. This is DETECTION-ONLY, not an exploitation engine (see PRD
non-goals) -- we look for evidence a payload landed (reflection, error
signatures, timing deltas), we never chain that into actual exploitation.

Detection methods (FR-4.3):
  - Reflected XSS: payload marker reflected unescaped in the response body.
  - Error-based SQLi: SQL error signatures in the response.
  - Blind/timing-based SQLi: compare response time of a delay payload against
    a baseline request on the SAME endpoint (not against an unrelated
    baseline like dir_enum does -- this is the reliable use of timing).

Findings are labeled confirmed/suspected per FR-4.4:
  - confirmed: signature/reflection match (strong evidence)
  - suspected: timing-only heuristic (weaker, more prone to noise)

This is an ACTIVE module -- requires --i-own-this (FR-0.3).
"""

import asyncio
import time
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from core.auth_gate import ScanContext
from core import db

# --- Payloads ----------------------------------------------------------------

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

# Timing payload: only fires DB delay if injectable; response-time delta vs
# baseline (same endpoint, param set to a harmless value) is the signal.
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
]

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


@dataclass
class ParamFinding:
    url: str
    parameter: str
    vuln_type: str  # XSS | SQLi
    confidence: str  # confirmed | suspected
    payload: str
    encoding: str
    evidence: str


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
        # Baseline: same endpoint, harmless value, to get a normal response time.
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
            # If the delay payload took meaningfully longer than baseline,
            # that's suggestive (not conclusive) of blind SQLi -> 'suspected'.
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
