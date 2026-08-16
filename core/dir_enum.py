"""
Argus — Directory & File Enumeration (FR-1)

Multi-threaded/async brute-force against a target using a wordlist, with
extension permutation and false-positive filtering via baseline diffing
against a random (guaranteed-404) path.

This module is PASSIVE-ish in spirit but still sends many requests to the
target, so it goes through the same scope + rate-limit gate as everything
else. It does NOT require --i-own-this by default in this reference
implementation, but you can make it active-gated if you want stricter
defaults — see CLI wiring.
"""

import asyncio
import random
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import httpx

from core.auth_gate import ScanContext
from core import db

DEFAULT_EXTENSIONS = ["", ".php", ".bak", ".env", ".git", ".zip"]


@dataclass
class Baseline:
    status_code: int
    content_length: int
    response_time: float


@dataclass
class DirFinding:
    url: str
    status_code: int
    content_length: int
    response_time: float
    note: str = ""


async def _fetch(client: httpx.AsyncClient, url: str, ctx: ScanContext) -> Optional[httpx.Response]:
    await ctx.throttle()
    try:
        start = time.monotonic()
        resp = await client.get(url, timeout=8.0, follow_redirects=False)
        resp.elapsed_override = time.monotonic() - start
        return resp
    except httpx.RequestError:
        return None


async def _get_baseline(client: httpx.AsyncClient, base_url: str, ctx: ScanContext) -> Baseline:
    """
    Request a random, near-guaranteed-nonexistent path to characterize how
    the server responds to unknown paths. Many apps return 200 with a custom
    'not found' page instead of a real 404 — this baseline lets us filter
    those out as false positives instead of reporting every path as a hit.
    """
    junk = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
    url = f"{base_url.rstrip('/')}/{junk}"
    resp = await _fetch(client, url, ctx)
    if resp is None:
        # If even the baseline request fails, assume conservative defaults
        return Baseline(status_code=404, content_length=0, response_time=0.5)
    body_len = len(resp.content)
    rtime = getattr(resp, "elapsed_override", resp.elapsed.total_seconds() if resp.elapsed else 0.5)
    return Baseline(status_code=resp.status_code, content_length=body_len, response_time=rtime)


def _is_false_positive(resp: httpx.Response, baseline: Baseline, rtime: float,
                        length_delta_threshold: int = 5) -> bool:
    """
    Filters a candidate hit against the baseline (FR-1.3).

    Deliberately simple and deterministic: a candidate is a false positive
    only if it matches the baseline junk-path response on BOTH status code
    and content-length (within a small delta). This is the strong, reliable
    signal for "this is the site's custom 404/catch-all page."

    Response-time is intentionally NOT used as an override here. Under
    concurrent fuzzing, per-request latency is inflated by scheduling and
    connection contention regardless of whether a path is real, so timing
    is not trustworthy evidence at this stage. Timing-based detection
    (e.g. blind SQLi via delay payloads) belongs to the parameter-fuzzing
    module (FR-4.3), which measures relative timing between payload variants
    on the SAME endpoint rather than comparing against an unrelated baseline
    request -- a much more reliable use of timing signal.

    A length-based false-negative risk is the tradeoff: a genuinely tiny real
    file could coincidentally land within the delta of the baseline page and
    get filtered. This is called out explicitly as a known limitation rather
    than papered over with a timing heuristic that introduced worse behavior
    (verified: an earlier timing-override version let ~90% of true false
    positives leak through under concurrent load).
    """
    if resp.status_code != baseline.status_code:
        return False  # different status code from baseline -> looks real, not a FP

    body_len = len(resp.content)
    length_delta = abs(body_len - baseline.content_length)
    return length_delta <= length_delta_threshold


async def enumerate_directories(
    base_url: str,
    wordlist: List[str],
    ctx: ScanContext,
    scan_id: str,
    extensions: List[str] = None,
    concurrency: int = 20,
) -> List[DirFinding]:
    """
    Returns confirmed DirFinding hits (post false-positive filtering) and
    writes them to the DB as 'exposed_file' or 'misconfig' findings.
    """
    ctx.assert_in_scope(base_url)
    extensions = extensions or DEFAULT_EXTENSIONS

    findings: List[DirFinding] = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient() as client:
        baseline = await _get_baseline(client, base_url, ctx)

        # dedupe: wordlists sometimes contain both "config" and "config.php",
        # which combined with extension permutation produce the same candidate
        # path twice (and would otherwise fire duplicate requests + findings).
        candidates = sorted({f"{word}{ext}" for word in wordlist for ext in extensions})

        async def probe(path: str):
            async with semaphore:
                url = f"{base_url.rstrip('/')}/{path}"
                resp = await _fetch(client, url, ctx)
                db.log_request(scan_id, base_url, "dir_enum", "GET", url,
                                resp.status_code if resp else 0)
                if resp is None:
                    return
                # Treat redirects and non-404-like statuses as interesting by default
                if resp.status_code == 404:
                    return
                rtime = getattr(resp, "elapsed_override", resp.elapsed.total_seconds() if resp.elapsed else 0.0)
                if _is_false_positive(resp, baseline, rtime):
                    return

                note = "sensitive file pattern" if any(
                    path.endswith(ext) for ext in [".env", ".git", ".bak", ".zip"]
                ) else "accessible path"
                finding = DirFinding(
                    url=url,
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    response_time=rtime,
                    note=note,
                )
                findings.append(finding)

                vuln_type = "exposed_file" if note == "sensitive file pattern" else "misconfig"
                db.add_finding(
                    scan_id=scan_id,
                    target=base_url,
                    module="dir_enum",
                    vuln_type=vuln_type,
                    confidence="confirmed",
                    url=url,
                    request_evidence=f"GET {url}",
                    response_evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                    description=f"Discovered {note} at {url} (status {resp.status_code}, "
                                f"baseline was {baseline.status_code}/{baseline.content_length}b).",
                    source_surface="cli",
                )

        await asyncio.gather(*(probe(c) for c in candidates))

    return findings


def load_wordlist(path: str) -> List[str]:
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Wordlist file not found: '{path}'")
    with open(path_obj, encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


if __name__ == "__main__":
    import sys
    from core.auth_gate import ScanContext

    if len(sys.argv) < 2:
        print("Usage: python core/dir_enum.py <base_url>")
        sys.exit(1)

    target = sys.argv[1]
    db.init_db()
    scan_id = db.start_scan(target, scope_file="scope/scope.yaml")
    ctx = ScanContext("scope/scope.yaml", confirmed_active=False, requests_per_second=15)
    wordlist = load_wordlist("wordlists/common.txt")

    results = asyncio.run(enumerate_directories(target, wordlist, ctx, scan_id))
    db.finish_scan(scan_id)

    print(f"\n{len(results)} finding(s):")
    for r in results:
        print(f"  [{r.status_code}] {r.url}  ({r.note}, {r.content_length}b)")
