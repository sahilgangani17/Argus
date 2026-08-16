"""
Argus — Virtual Host (VHost) Discovery (FR-2)

Many servers host multiple sites/applications behind one IP, routing by the
Host header (name-based virtual hosting). Standard directory/subdomain
enumeration won't find these if they aren't in public DNS -- you have to
fuzz the Host header directly against the IP and watch for a response that
diverges from the "unknown vhost" baseline.

This is an ACTIVE module (FR-0.3): it requires --i-own-this confirmation,
since sending crafted Host headers at scale against a fixed IP is the kind
of thing that should require explicit authorization, same as parameter
fuzzing.
"""

import asyncio
import random
import string
import time
from dataclasses import dataclass
from typing import List, Optional

import httpx

from core.auth_gate import ScanContext
from core import db


@dataclass
class VhostBaseline:
    status_code: int
    content_length: int
    title: str


@dataclass
class VhostFinding:
    vhost: str
    status_code: int
    content_length: int
    title: str


def _extract_title(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start != -1 and end != -1 and end > start:
        return html[start + 7:end].strip()
    return ""


async def _fetch_with_host(client: httpx.AsyncClient, base_url: str, host_header: str,
                            ctx: ScanContext) -> Optional[httpx.Response]:
    await ctx.throttle()
    try:
        return await client.get(base_url, headers={"Host": host_header}, timeout=8.0, follow_redirects=False)
    except httpx.RequestError:
        return None


async def _get_vhost_baseline(client: httpx.AsyncClient, base_url: str, ctx: ScanContext) -> VhostBaseline:
    """
    Request the target with a random, near-guaranteed-unregistered Host
    header value to characterize the "default"/"unknown vhost" response
    (many servers fall back to a default site or an error page).
    """
    junk_host = "".join(random.choices(string.ascii_lowercase, k=20)) + ".invalid-vhost-probe.test"
    resp = await _fetch_with_host(client, base_url, junk_host, ctx)
    if resp is None:
        return VhostBaseline(status_code=404, content_length=0, title="")
    return VhostBaseline(
        status_code=resp.status_code,
        content_length=len(resp.content),
        title=_extract_title(resp.text),
    )


def _is_vhost_false_positive(resp: httpx.Response, baseline: VhostBaseline,
                              length_delta_threshold: int = 5) -> bool:
    """
    Same principle as directory enumeration's FP filter (FR-1.3), applied to
    vhosts: a candidate Host header is "nothing new" if it produces the same
    status code AND a near-identical content length/title to the unknown-vhost
    baseline. A genuinely distinct vhost will differ noticeably in at least one.
    """
    if resp.status_code != baseline.status_code:
        return False
    title = _extract_title(resp.text)
    if title and baseline.title and title != baseline.title:
        return False  # different page title -> distinct vhost
    length_delta = abs(len(resp.content) - baseline.content_length)
    return length_delta <= length_delta_threshold


async def discover_vhosts(
    base_url: str,
    subdomain_wordlist: List[str],
    ctx: ScanContext,
    scan_id: str,
    concurrency: int = 15,
    root_host_override: Optional[str] = None,
) -> List[VhostFinding]:
    """
    Fuzzes the Host header with candidate subdomains against base_url's IP.
    Requires active-module confirmation (--i-own-this) since this is an
    active module per FR-0.3.

    root_host_override: in real-world use, you often scan a fixed IP while
    fuzzing Host headers built from a known company domain (e.g. scanning
    203.0.113.5 but building candidates like "internal.example.com"), since
    the IP's reverse DNS may not reflect the org's actual domain. Pass this
    to control which domain candidate hostnames are built against; otherwise
    it defaults to the hostname parsed from base_url.
    """
    ctx.assert_in_scope(base_url)
    ctx.assert_active_allowed()

    from urllib.parse import urlparse
    root_host = root_host_override or (urlparse(base_url).hostname or base_url)
    if root_host_override:
        ctx.assert_in_scope(root_host_override)

    findings: List[VhostFinding] = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient() as client:
        baseline = await _get_vhost_baseline(client, base_url, ctx)

        candidates = sorted({f"{word}.{root_host}" for word in subdomain_wordlist} |
                             {f"internal.{root_host}", f"admin.{root_host}", f"staging.{root_host}"})

        async def probe(host_header: str):
            async with semaphore:
                resp = await _fetch_with_host(client, base_url, host_header, ctx)
                db.log_request(scan_id, base_url, "vhost", "GET", f"{base_url} (Host: {host_header})",
                                resp.status_code if resp else 0)
                if resp is None:
                    return
                if _is_vhost_false_positive(resp, baseline):
                    return

                title = _extract_title(resp.text)
                finding = VhostFinding(
                    vhost=host_header,
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    title=title,
                )
                findings.append(finding)

                db.add_finding(
                    scan_id=scan_id,
                    target=base_url,
                    module="vhost",
                    vuln_type="misconfig",
                    confidence="confirmed",
                    url=f"{base_url} (Host: {host_header})",
                    request_evidence=f"GET {base_url}\nHost: {host_header}",
                    response_evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes, title='{title}'",
                    description=f"Discovered distinct virtual host '{host_header}' "
                                f"(baseline was {baseline.status_code}/{baseline.content_length}b, "
                                f"title='{baseline.title}').",
                    source_surface="cli",
                )

        await asyncio.gather(*(probe(c) for c in candidates))

    return findings


def load_wordlist(path: str) -> List[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python core/vhost.py <base_url> [root_host_for_candidates]")
        sys.exit(1)

    target = sys.argv[1]
    root_host_override = sys.argv[2] if len(sys.argv) > 2 else None

    db.init_db()
    scan_id = db.start_scan(target, scope_file="scope/scope.yaml")
    ctx = ScanContext("scope/scope.yaml", confirmed_active=True, requests_per_second=15)
    wordlist = ["www", "internal", "admin", "staging", "dev", "api", "mail", "test"]

    results = asyncio.run(discover_vhosts(target, wordlist, ctx, scan_id, root_host_override=root_host_override))
    db.finish_scan(scan_id)

    print(f"\n{len(results)} vhost finding(s):")
    for r in results:
        print(f"  [{r.status_code}] Host: {r.vhost}  title='{r.title}'  ({r.content_length}b)")
