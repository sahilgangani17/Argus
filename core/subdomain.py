"""
Argus — Subdomain Enumeration (FR-5)

Two-phase pipeline:

  Phase 1 — PASSIVE  (no --i-own-this required)
    - Certificate Transparency via the crt.sh JSON API.
      crt.sh indexes public cert SANs, so this is entirely passive — we never
      send a packet to the target. It's the same source used by tools like
      subfinder and amass's passive mode.

  Phase 2 — ACTIVE  (requires --i-own-this)
    - DNS brute-force: resolve a wordlist of candidate subdomains against the
      target domain using asyncio-native DNS (via socket.getaddrinfo in a
      thread pool, avoiding external libraries).
    - Zone transfer (AXFR) attempt: legitimate DNS misconfiguration that
      leaks the entire zone; checked first since one request can enumerate
      everything. Requires dnspython; silently skipped if not installed.

  Phase 3 — FEEDBACK  (feeds live hosts into other modules)
    - Resolve each discovered subdomain to an IP.
    - Probe HTTP/HTTPS liveness.
    - Return live hosts so the CLI can re-feed them into dir_enum / vhost.

All findings (discovered subdomains) are stored in the DB as
  module='subdomain', vuln_type='misconfig', confidence='confirmed'.
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse

import httpx

from core.auth_gate import ScanContext
from core import db


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SubdomainFinding:
    subdomain: str
    ip: Optional[str]
    is_live: bool
    live_url: Optional[str]
    source: str  # 'crtsh' | 'bruteforce' | 'axfr'


# ---------------------------------------------------------------------------
# Phase 1 — Passive: Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
CRTSH_TIMEOUT = 15.0


async def _query_crtsh(domain: str) -> Set[str]:
    """
    Query crt.sh for all SANs/common-names ever issued for *.<domain>.
    Returns a set of raw name strings (may include wildcards, deduplicated).
    """
    url = CRTSH_URL.format(domain=domain)
    found: Set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return found
            data = resp.json()
            for entry in data:
                for field_name in ("name_value", "common_name"):
                    names = entry.get(field_name, "")
                    for name in names.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and domain in name:
                            found.add(name)
    except Exception:
        pass  # crt.sh is best-effort; network hiccups shouldn't abort the scan
    return found


# ---------------------------------------------------------------------------
# Phase 2a — Active: DNS Zone Transfer (AXFR)
# ---------------------------------------------------------------------------

def _attempt_zone_transfer(domain: str) -> Set[str]:
    """
    Try an AXFR zone transfer against the domain's authoritative nameservers.
    Silently skipped if dnspython is not installed (it's optional).
    Returns a set of discovered FQDNs on success, empty set otherwise.
    """
    found: Set[str] = set()
    try:
        import dns.resolver
        import dns.query
        import dns.zone
    except ImportError:
        return found  # dnspython not installed — skip gracefully

    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                for name in zone.nodes:
                    fqdn = f"{name}.{domain}".lstrip("@.").lower()
                    if fqdn and domain in fqdn:
                        found.add(fqdn)
                if found:
                    break  # one successful transfer is enough
            except Exception:
                continue
    except Exception:
        pass

    return found


# ---------------------------------------------------------------------------
# Phase 2b — Active: DNS Brute-Force
# ---------------------------------------------------------------------------

async def _resolve_host(hostname: str) -> Optional[str]:
    """Resolve hostname to IP. Returns None if resolution fails."""
    loop = asyncio.get_event_loop()
    try:
        results = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
        )
        if results:
            return results[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


async def _dns_bruteforce(
    domain: str,
    wordlist: List[str],
    ctx: ScanContext,
    concurrency: int = 50,
) -> Set[str]:
    """
    Resolves <word>.<domain> for every word in wordlist.
    Returns the set of hostnames that resolved.
    """
    found: Set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(word: str):
        candidate = f"{word}.{domain}"
        async with semaphore:
            await ctx.throttle()
            ip = await _resolve_host(candidate)
            if ip:
                found.add(candidate)

    await asyncio.gather(*(probe(w) for w in wordlist))
    return found


# ---------------------------------------------------------------------------
# Phase 3 — Liveness Check
# ---------------------------------------------------------------------------

async def _check_liveness(hostname: str, timeout: float = 5.0) -> tuple[bool, Optional[str]]:
    """
    Probe HTTPS then HTTP. Returns (is_live, live_url).
    """
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                  verify=False) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            try:
                resp = await client.get(url)
                if resp.status_code < 600:
                    return True, url
            except Exception:
                continue
    return False, None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "internal",
    "vpn", "remote", "blog", "shop", "store", "portal", "cdn", "static", "media",
    "img", "images", "video", "assets", "upload", "download", "secure", "ssl",
    "ns", "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail", "autodiscover",
    "autoconfig", "help", "support", "docs", "wiki", "jira", "gitlab", "github",
    "bitbucket", "jenkins", "ci", "beta", "alpha", "sandbox", "demo", "app",
    "apps", "api-v1", "api-v2", "v1", "v2", "mobile", "m", "wap", "dashboard",
    "monitor", "status", "health", "metrics", "analytics", "tracking", "sentry",
    "grafana", "kibana", "elastic", "db", "mysql", "postgres", "redis", "cache",
    "queue", "broker", "kafka", "rabbitmq", "mq", "s3", "storage", "backup",
    "archive", "old", "legacy", "newdev", "preview", "uat", "qa", "int",
    "prod", "production", "corp", "intranet", "extranet", "git", "svn",
    "deploy", "infra", "ops", "devops", "sysadmin", "owa", "exchange",
]


async def enumerate_subdomains(
    target: str,
    ctx: ScanContext,
    scan_id: str,
    wordlist: Optional[List[str]] = None,
    passive_only: bool = False,
    concurrency: int = 50,
    liveness_check: bool = True,
) -> List[SubdomainFinding]:
    """
    Full subdomain enumeration pipeline (FR-5).

    Args:
        target:        Base URL or bare domain (e.g. 'http://example.com' or 'example.com').
        ctx:           ScanContext for scope checking and rate limiting.
        scan_id:       Active scan ID for DB logging.
        wordlist:      Custom wordlist for DNS brute-force. Defaults to built-in list.
        passive_only:  If True, skip DNS brute-force and AXFR (crt.sh only). Does NOT
                       require --i-own-this.
        concurrency:   Max parallel DNS resolution tasks.
        liveness_check: Probe HTTP/HTTPS for each resolved subdomain.

    Returns:
        List of SubdomainFinding, one per unique discovered subdomain.
    """
    # Normalize target to bare domain
    if "://" in target:
        domain = urlparse(target).hostname or target
    else:
        domain = target.split(":")[0].split("/")[0]

    ctx.assert_in_scope(target)
    if not passive_only:
        ctx.assert_active_allowed()

    all_subdomains: dict[str, str] = {}  # subdomain -> source

    # --- Phase 1: Passive crt.sh -------------------------------------------------
    print(f"  [subdomain:crtsh] Querying certificate transparency for {domain}...")
    crtsh_names = await _query_crtsh(domain)
    for name in crtsh_names:
        all_subdomains[name] = "crtsh"
    print(f"  [subdomain:crtsh] Found {len(crtsh_names)} name(s)")

    if not passive_only:
        # --- Phase 2a: Zone Transfer -------------------------------------------------
        print(f"  [subdomain:axfr] Attempting DNS zone transfer for {domain}...")
        axfr_names = await asyncio.get_event_loop().run_in_executor(
            None, _attempt_zone_transfer, domain
        )
        for name in axfr_names:
            all_subdomains.setdefault(name, "axfr")
        if axfr_names:
            print(f"  [subdomain:axfr] ZONE TRANSFER SUCCEEDED — {len(axfr_names)} record(s)!")
        else:
            print(f"  [subdomain:axfr] Zone transfer refused (expected for hardened servers)")

        # --- Phase 2b: DNS Brute-Force -----------------------------------------------
        wl = wordlist or DEFAULT_SUBDOMAIN_WORDLIST
        print(f"  [subdomain:brute] DNS brute-force with {len(wl)} word(s)...")
        brute_names = await _dns_bruteforce(domain, wl, ctx, concurrency=concurrency)
        for name in brute_names:
            all_subdomains.setdefault(name, "bruteforce")
        print(f"  [subdomain:brute] Resolved {len(brute_names)} candidate(s)")

    # --- Phase 3: Resolve + Liveness check ------------------------------------------
    findings: List[SubdomainFinding] = []

    async def process_subdomain(subdomain: str, source: str):
        ip = await _resolve_host(subdomain)
        if ip is None and source == "crtsh":
            # crt.sh can return expired/parked names; skip unresolvable ones
            return

        is_live = False
        live_url = None
        if liveness_check and ip:
            is_live, live_url = await _check_liveness(subdomain)

        finding = SubdomainFinding(
            subdomain=subdomain,
            ip=ip,
            is_live=is_live,
            live_url=live_url,
            source=source,
        )
        findings.append(finding)

        db.add_finding(
            scan_id=scan_id,
            target=target,
            module="subdomain",
            vuln_type="misconfig",
            confidence="confirmed",
            url=live_url or subdomain,
            description=(
                f"Subdomain discovered via {source}: {subdomain} → {ip or 'unresolved'}"
                + (f" [LIVE: {live_url}]" if is_live else " [not HTTP-reachable]")
            ),
            request_evidence=f"Source: {source}",
            response_evidence=f"Resolved IP: {ip or 'N/A'} | Live: {is_live}",
            source_surface="cli",
        )

    sem = asyncio.Semaphore(concurrency)

    async def bounded_process(subdomain, source):
        async with sem:
            await process_subdomain(subdomain, source)

    await asyncio.gather(
        *(bounded_process(sub, src) for sub, src in all_subdomains.items())
    )

    # Sort: live hosts first, then alphabetical
    findings.sort(key=lambda f: (not f.is_live, f.subdomain))
    return findings


# ---------------------------------------------------------------------------
# Stand-alone usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from core import db as _db

    if len(sys.argv) < 2:
        print("Usage: python core/subdomain.py <domain> [--passive]")
        sys.exit(1)

    target_arg = sys.argv[1]
    passive = "--passive" in sys.argv

    _db.init_db()
    scan_id = _db.start_scan(target_arg, scope_file="scope/scope.yaml")
    _ctx = ScanContext("scope/scope.yaml", confirmed_active=not passive, requests_per_second=50)

    results = asyncio.run(enumerate_subdomains(
        target_arg, _ctx, scan_id,
        passive_only=passive,
    ))
    _db.finish_scan(scan_id)

    print(f"\n{'=' * 60}")
    print(f"Subdomain Enumeration Results: {len(results)} found")
    print(f"{'=' * 60}")
    for r in results:
        live_tag = f"  LIVE → {r.live_url}" if r.is_live else ""
        ip_tag = f"  [{r.ip}]" if r.ip else "  [unresolved]"
        print(f"  [{r.source:10s}] {r.subdomain}{ip_tag}{live_tag}")
