"""
Argus — Custom YAML Rules Engine (FR-6)

Accepts user-defined YAML templates that specify an HTTP request pattern and
one or more response matchers. Executes all templates against the target in a
concurrent, rate-limited loop using the same ScanContext gate as every other
Argus module.

Template YAML format
--------------------
id: argus-exposed-env
name: Exposed .env File
description: Checks if the .env file is publicly readable
severity: exposed_file      # must be a key in db.BASE_SEVERITY
confidence: confirmed       # confirmed | suspected

request:
  method: GET               # HTTP verb
  path: /.env               # path appended to the target base URL
  headers: {}               # extra request headers (optional)
  body: null                # raw string body or null (optional)
  params: {}                # extra query parameters (optional)

matchers:
  - type: status            # match HTTP response status codes
    values: [200]
  - type: word              # one or more substring(s) in the response body
    values: ["APP_KEY", "DB_PASSWORD"]
  - type: regex             # one or more regex patterns in the response body
    values: ["[A-Z_]+=.+"]
  - type: size_gt           # body byte count > threshold
    value: 0
  - type: size_lt           # body byte count < threshold
    value: 4096
  - type: header            # substring in a response header value
    header: content-type
    values: ["text/plain"]

matcher_condition: and      # and = ALL matchers must pass
                            # or  = ANY matcher passing is enough (default)
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlencode, urlparse

import httpx
import yaml

from core.auth_gate import ScanContext
from core import db


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MatcherSpec:
    type: str                        # status | word | regex | size_gt | size_lt | header
    values: List[Any] = field(default_factory=list)  # strings or ints depending on type
    value: Optional[Any] = None      # single numeric value (size_gt / size_lt)
    header: Optional[str] = None     # header name for 'header' type


@dataclass
class RequestSpec:
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)


@dataclass
class RuleTemplate:
    id: str
    name: str
    description: str
    severity: str                         # must match a db.BASE_SEVERITY key
    confidence: str                       # confirmed | suspected
    request: RequestSpec = field(default_factory=RequestSpec)
    matchers: List[MatcherSpec] = field(default_factory=list)
    matcher_condition: str = "or"         # 'and' | 'or'
    source_file: str = ""                 # path to the .yaml that produced this template


@dataclass
class RuleResult:
    """Returned for every template that fires a match."""
    template_id: str
    template_name: str
    url: str
    matched: bool
    status_code: int
    evidence: str
    finding_id: Optional[str] = None     # db finding_id if written to DB


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------

def _parse_matcher(raw: Dict[str, Any]) -> MatcherSpec:
    return MatcherSpec(
        type=raw.get("type", "word"),
        values=raw.get("values", []),
        value=raw.get("value"),
        header=raw.get("header"),
    )


def _parse_template(data: Dict[str, Any], source_file: str = "") -> RuleTemplate:
    """Parse a raw YAML dict into a RuleTemplate. Raises ValueError for bad input."""
    required = ("id", "name", "severity", "confidence")
    for key in required:
        if key not in data:
            raise ValueError(f"Template missing required field '{key}' in {source_file}")

    severity = data["severity"]
    if severity not in db.BASE_SEVERITY:
        raise ValueError(
            f"Template '{data['id']}': severity '{severity}' is not in "
            f"db.BASE_SEVERITY ({list(db.BASE_SEVERITY.keys())}). "
            f"File: {source_file}"
        )

    confidence = data.get("confidence", "suspected")
    if confidence not in ("confirmed", "suspected"):
        raise ValueError(
            f"Template '{data['id']}': confidence must be 'confirmed' or 'suspected'. "
            f"File: {source_file}"
        )

    raw_req = data.get("request", {})
    request = RequestSpec(
        method=raw_req.get("method", "GET").upper(),
        path=raw_req.get("path", "/"),
        headers=raw_req.get("headers") or {},
        body=raw_req.get("body"),
        params=raw_req.get("params") or {},
    )

    matchers = [_parse_matcher(m) for m in data.get("matchers", [])]
    if not matchers:
        raise ValueError(
            f"Template '{data['id']}' has no matchers defined. "
            f"File: {source_file}"
        )

    condition = data.get("matcher_condition", "or").lower()
    if condition not in ("and", "or"):
        raise ValueError(
            f"Template '{data['id']}': matcher_condition must be 'and' or 'or'. "
            f"File: {source_file}"
        )

    return RuleTemplate(
        id=data["id"],
        name=data["name"],
        description=data.get("description", ""),
        severity=severity,
        confidence=confidence,
        request=request,
        matchers=matchers,
        matcher_condition=condition,
        source_file=source_file,
    )


def load_templates(path: str) -> List[RuleTemplate]:
    """
    Load templates from a single YAML file or every *.yaml / *.yml file in a directory.
    Silently skips files that fail to parse (logs a warning to stdout).

    Returns a (possibly empty) list of valid RuleTemplate objects.
    """
    templates: List[RuleTemplate] = []
    p = Path(path)

    if not p.exists():
        raise FileNotFoundError(f"Templates path not found: {path}")

    yaml_files: List[Path]
    if p.is_file():
        yaml_files = [p]
    else:
        yaml_files = sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml"))

    for yf in yaml_files:
        try:
            with open(yf, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                raise ValueError("Template file must be a YAML mapping at the top level")
            tmpl = _parse_template(data, source_file=str(yf))
            templates.append(tmpl)
        except Exception as exc:
            print(f"[custom_rules] WARNING: skipping '{yf}': {exc}")

    return templates


# ---------------------------------------------------------------------------
# Matcher evaluation
# ---------------------------------------------------------------------------

def _evaluate_matcher(matcher: MatcherSpec, resp: httpx.Response) -> bool:
    """Return True if the single matcher passes against the given response."""
    mtype = matcher.type

    if mtype == "status":
        return resp.status_code in [int(v) for v in matcher.values]

    body_bytes = resp.content
    try:
        body = resp.text
    except Exception:
        body = body_bytes.decode("latin-1", errors="replace")

    if mtype == "word":
        body_lower = body.lower()
        return any(str(v).lower() in body_lower for v in matcher.values)

    if mtype == "regex":
        return any(bool(re.search(str(v), body, re.IGNORECASE)) for v in matcher.values)

    if mtype == "size_gt":
        threshold = int(
            matcher.value if matcher.value is not None
            else (matcher.values[0] if matcher.values else 0)
        )
        return len(body_bytes) > threshold

    if mtype == "size_lt":
        threshold = int(
            matcher.value if matcher.value is not None
            else (matcher.values[0] if matcher.values else 0)
        )
        return len(body_bytes) < threshold

    if mtype == "header":
        hdr_name = (matcher.header or "").lower()
        hdr_value = resp.headers.get(hdr_name, "").lower()
        return any(str(v).lower() in hdr_value for v in matcher.values)

    # Unknown matcher type — warn and treat as non-match
    print(f"[custom_rules] WARNING: unknown matcher type '{mtype}' — skipping")
    return False


def _evaluate_all_matchers(template: RuleTemplate, resp: httpx.Response) -> bool:
    """Combine all matcher results using the template's matcher_condition."""
    results = [_evaluate_matcher(m, resp) for m in template.matchers]
    if template.matcher_condition == "and":
        return all(results)
    return any(results)  # "or" (default)


# ---------------------------------------------------------------------------
# Template execution
# ---------------------------------------------------------------------------

def _build_url(base_url: str, path: str, params: Dict[str, str]) -> str:
    """
    Combine target base URL + template path + query params into a full URL.
    The template path replaces any existing path on the base URL so templates
    always test specific paths, not whatever path the user passed as TARGET.
    """
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    full = base.rstrip("/") + "/" + path.lstrip("/")
    if params:
        full += ("&" if "?" in full else "?") + urlencode(params)
    return full


async def run_template(
    client: httpx.AsyncClient,
    template: RuleTemplate,
    target_url: str,
    ctx: ScanContext,
    scan_id: str,
) -> RuleResult:
    """
    Fire one template against target_url.
    Returns a RuleResult regardless of match status.
    Only writes to DB (and populates finding_id) when the template matches.
    """
    url = _build_url(target_url, template.request.path, template.request.params)
    ctx.assert_in_scope(url)
    await ctx.throttle()

    req_kwargs: Dict[str, Any] = {
        "timeout": 8.0,
        "follow_redirects": False,
        "headers": template.request.headers or {},
    }
    if template.request.body is not None:
        body_val = template.request.body
        req_kwargs["content"] = (
            body_val.encode() if isinstance(body_val, str) else body_val
        )

    try:
        resp = await client.request(template.request.method, url, **req_kwargs)
    except httpx.RequestError as exc:
        db.log_request(scan_id, target_url, "custom_rules",
                       template.request.method, url, 0)
        return RuleResult(
            template_id=template.id,
            template_name=template.name,
            url=url,
            matched=False,
            status_code=0,
            evidence=f"Request failed: {exc}",
        )

    db.log_request(scan_id, target_url, "custom_rules",
                   template.request.method, url, resp.status_code)

    matched = _evaluate_all_matchers(template, resp)

    if not matched:
        return RuleResult(
            template_id=template.id,
            template_name=template.name,
            url=url,
            matched=False,
            status_code=resp.status_code,
            evidence="",
        )

    # Build human-readable evidence strings
    body_snippet = resp.text[:300].replace("\n", " ").replace("\r", "")
    evidence = (
        f"Template '{template.id}' matched. "
        f"Status: {resp.status_code}. "
        f"Body snippet: {body_snippet!r}"
    )
    request_evidence = (
        f"{template.request.method} {url}\n"
        f"Headers: {json.dumps(dict(template.request.headers))}\n"
        f"Body: {template.request.body or ''}"
    )
    response_evidence = (
        f"Status {resp.status_code}\n"
        f"Content-Type: {resp.headers.get('content-type', '')}\n"
        f"Body snippet: {body_snippet}"
    )

    finding_id = db.add_finding(
        scan_id=scan_id,
        target=target_url,
        module="custom_rules",
        vuln_type=template.severity,
        confidence=template.confidence,
        url=url,
        parameter=template.request.path,
        request_evidence=request_evidence,
        response_evidence=response_evidence,
        description=(
            f"{template.name}: {template.description}"
            if template.description else template.name
        ),
        source_surface="cli",
    )

    return RuleResult(
        template_id=template.id,
        template_name=template.name,
        url=url,
        matched=True,
        status_code=resp.status_code,
        evidence=evidence,
        finding_id=finding_id,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def run_all_templates(
    target: str,
    templates: List[RuleTemplate],
    ctx: ScanContext,
    scan_id: str,
    concurrency: int = 10,
) -> List[RuleResult]:
    """
    Run all loaded templates against `target` concurrently (rate-limited).
    Returns a list of RuleResult for every template that produced a match.

    Requires --i-own-this (active module gate) because templates send HTTP
    requests to the target.
    """
    ctx.assert_active_allowed()
    ctx.assert_in_scope(target)

    semaphore = asyncio.Semaphore(concurrency)
    results: List[RuleResult] = []

    async def _run_one(tmpl: RuleTemplate) -> None:
        async with semaphore:
            try:
                result = await run_template(client, tmpl, target, ctx, scan_id)
                if result.matched:
                    results.append(result)
            except Exception as exc:
                print(f"[custom_rules] ERROR running template '{tmpl.id}': {exc}")

    async with httpx.AsyncClient() as client:
        await asyncio.gather(*(_run_one(t) for t in templates))

    return results
