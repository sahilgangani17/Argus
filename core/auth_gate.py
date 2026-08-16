"""
Argus — Authorization Gate (FR-0)

This is a code-level enforcement layer, not a disclaimer. Every scan module
must call `check_scope()` before firing a single request, and active modules
must call `require_active_confirmation()` before running.

scope.yaml format:
------------------
authorized_targets:
  - example.com
  - "*.example.com"
  - 10.0.0.0/24
owner: "Jane Doe"
signed: true          # placeholder for a real signature check in a future version
"""

import asyncio
import fnmatch
import ipaddress
import time
import yaml
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""


class ScopeViolation(ScopeError):
    pass


class ActiveModuleBlocked(Exception):
    """Raised when an active module is invoked without --i-own-this confirmation."""


def load_scope(scope_path: str) -> dict:
    path = Path(scope_path)
    if not path.exists():
        raise ScopeError(f"Scope file not found: {scope_path}")
    with open(path) as f:
        data = yaml.safe_load(f)
    if not data or "authorized_targets" not in data:
        raise ScopeError("scope.yaml must contain an 'authorized_targets' list")
    return data


def _extract_hostname(target: str) -> str:
    """Accept raw hostnames, IPs, or full URLs and normalize to a hostname."""
    if "://" in target:
        return urlparse(target).hostname or target
    # strip path/port if someone passed host:port/path
    return target.split("/")[0].split(":")[0]


def _hostname_matches(hostname: str, pattern: str) -> bool:
    # Wildcard subdomain match: *.example.com
    if pattern.startswith("*."):
        return hostname == pattern[2:] or fnmatch.fnmatch(hostname, pattern)
    # CIDR match
    try:
        if "/" in pattern:
            net = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(hostname)
            return ip in net
    except ValueError:
        pass
    return hostname == pattern


def check_scope(target: str, scope: dict) -> None:
    """
    Raises ScopeViolation if target's hostname is not in the authorized list.
    This is called at the request layer — every module must invoke this
    before sending a request to a new host (including newly discovered
    subdomains from the recursive feedback loop).
    """
    hostname = _extract_hostname(target)
    authorized = scope.get("authorized_targets", [])
    for pattern in authorized:
        if _hostname_matches(hostname, str(pattern)):
            return
    raise ScopeViolation(
        f"Target '{hostname}' is not in the authorized scope file. "
        f"Add it to 'authorized_targets' in scope.yaml to proceed."
    )


def require_active_confirmation(confirmed: bool) -> None:
    """
    Active modules (parameter fuzzing, vhost brute-force) must call this.
    Passive-only modules (crt.sh lookups) do not need to.
    """
    if not confirmed:
        raise ActiveModuleBlocked(
            "This module performs active scanning against the target. "
            "Re-run with --i-own-this to confirm you are authorized to actively "
            "test this target."
        )


class RateLimiter:
    """
    Simple async token-bucket rate limiter shared across all outbound requests
    in a scan. Prevents accidental DoS during demos or real use.
    """

    def __init__(self, requests_per_second: float = 10.0):
        self.rate = requests_per_second
        self.capacity = max(1.0, requests_per_second)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
                self.last_refill = time.monotonic()
            else:
                self.tokens -= 1.0


class ScanContext:
    """
    Bundles the gate checks + rate limiter so scan modules get one object
    to thread through their request loops. This is the thing every module
    receives — it makes it structurally hard to "forget" to gate a request.
    """

    def __init__(self, scope_path: str, confirmed_active: bool, requests_per_second: float = 10.0):
        self.scope = load_scope(scope_path)
        self.confirmed_active = confirmed_active
        self.rate_limiter = RateLimiter(requests_per_second)

    def assert_in_scope(self, target: str) -> None:
        check_scope(target, self.scope)

    def assert_active_allowed(self) -> None:
        require_active_confirmation(self.confirmed_active)

    async def throttle(self) -> None:
        await self.rate_limiter.acquire()


if __name__ == "__main__":
    # quick smoke test
    demo_scope = {"authorized_targets": ["dvwa.local", "*.example.com", "127.0.0.1"]}
    for t in ["dvwa.local", "http://127.0.0.1:8080/login.php", "api.example.com", "evil.com"]:
        try:
            check_scope(t, demo_scope)
            print(f"ALLOWED: {t}")
        except ScopeViolation as e:
            print(f"BLOCKED: {t} -> {e}")
