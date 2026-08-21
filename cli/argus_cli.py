"""
Argus CLI — the deep, automatable scan engine (FR-7.1).

Usage:
  python cli/argus_cli.py scan <target> --scope scope/scope.yaml [flags]

Examples:
  # Passive-only run (directory enum only, no active confirmation needed)
  python cli/argus_cli.py scan http://127.0.0.1:8080 --scope scope/scope.yaml --modules dir

  # Full active run (dir + vhost + param fuzzing)
  python cli/argus_cli.py scan http://127.0.0.1:8080 --scope scope/scope.yaml \\
      --modules dir,vhost,param --i-own-this --param q --root-host dvwa.local

  # Schema-aware API fuzzing (auto-discovers endpoints, then fuzzes them)
  python cli/argus_cli.py scan http://127.0.0.1:8000 --scope scope/scope.yaml \\
      --modules api --i-own-this

  # List findings from the most recent scan
  python cli/argus_cli.py findings
"""

import asyncio
import sys
from pathlib import Path

import click

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from core.auth_gate import ScanContext, ScopeViolation, ActiveModuleBlocked, ScopeError
from core.dir_enum import enumerate_directories, load_wordlist as load_dir_wordlist
from core.vhost import discover_vhosts
from core.param_fuzz import fuzz_parameter, fuzz_api_endpoints
from core.api_discovery import discover_api_routes, discover_api_endpoints


@click.group()
def cli():
    """Argus — comprehensive web application fuzzer (CLI engine)."""
    pass


@cli.command()
@click.argument("target")
@click.option("--scope", "scope_file", default="scope/scope.yaml", show_default=True,
              help="Path to the signed scope.yaml authorization file.")
@click.option("--modules", default="dir", show_default=True,
              help="Comma-separated modules to run: dir,vhost,param,api")
@click.option("--i-own-this", "confirmed_active", is_flag=True, default=False,
              help="Required to unlock active modules (vhost, param, api fuzzing).")
@click.option("--rate", default=15.0, show_default=True, help="Requests per second (rate limit).")
@click.option("--wordlist", default="wordlists/common.txt", show_default=True,
              help="Wordlist for directory enumeration.")
@click.option("--auto-discover", is_flag=True, default=False,
              help="Automatically extract routes from target's OpenAPI/Swagger spec before scanning.")
@click.option("--root-host", default=None,
              help="Domain to build vhost candidates against (defaults to target's hostname).")
@click.option("--param", "param_name", default=None,
              help="Query parameter name to fuzz (required if 'param' module is enabled).")
@click.option("--param-url", default=None,
              help="Full URL (with existing query params) to fuzz. Defaults to TARGET if not given. "
                   "Use this when TARGET is a clean base URL for dir/vhost but the param lives "
                   "on a different path, e.g. --param-url 'http://host/search?q=x'.")
@click.option("--spec-file", default=None,
              help="Path to a local openapi.json/yaml file to ingest schemas when live specs are blocked.")
def scan(target, scope_file, modules, confirmed_active, rate, wordlist, auto_discover, root_host, param_name, param_url, spec_file):
    """Run a scan against TARGET using the specified modules.

    TARGET should be a clean base URL (no query string) for dir/vhost modules.
    Use --param-url if the parameter to fuzz lives on a different path/query.

    Modules:
      dir   — Directory & file enumeration with false-positive filtering
      vhost — Virtual host discovery via Host header fuzzing (active)
      param — Single query parameter fuzzing with SQLi/XSS payloads (active)
      api   — Schema-aware API endpoint discovery + targeted fuzzing (active)
    """
    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    param_target = param_url or target

    db.init_db()

    try:
        ctx = ScanContext(scope_file, confirmed_active=confirmed_active, requests_per_second=rate)
        ctx.assert_in_scope(target)
    except ScopeError as e:
        click.secho(f"[BLOCKED] {e}", fg="red", bold=True)
        sys.exit(1)

    if auto_discover:
        click.echo("[api_discovery] Probing for OpenAPI / Swagger specs...")
        auto_wordlist_path = wordlist if wordlist != "wordlists/common.txt" else "wordlists/talk2tables.txt"
        disc_routes = asyncio.run(discover_api_routes(target, ctx, output_wordlist=auto_wordlist_path))
        if disc_routes:
            click.secho(f"  -> Discovered {len(disc_routes)} routes! Saved to '{auto_wordlist_path}'.", fg="green")
            wordlist = auto_wordlist_path
        else:
            click.secho("  -> No OpenAPI spec found; proceeding with configured wordlist.", fg="yellow")

    if "dir" in module_list and not Path(wordlist).exists():
        click.secho(f"[ERROR] Wordlist file not found: '{wordlist}'", fg="red", bold=True)
        sys.exit(1)

    scan_id = db.start_scan(target, scope_file=scope_file)
    click.secho(f"Started scan {scan_id[:8]} against {target}", fg="cyan")
    click.echo(f"Modules: {', '.join(module_list)} | Rate: {rate} req/s | Active confirmed: {confirmed_active}")

    async def run_all():
        total = 0

        if "dir" in module_list:
            click.echo("\n[dir_enum] Running directory & file enumeration...")
            wl = load_dir_wordlist(wordlist)
            results = await enumerate_directories(target, wl, ctx, scan_id)
            click.secho(f"  -> {len(results)} finding(s)", fg="green" if results else "white")
            for r in results:
                click.echo(f"     [{r.status_code}] {r.url}  ({r.note})")
            total += len(results)

        if "vhost" in module_list:
            click.echo("\n[vhost] Running virtual host discovery...")
            try:
                subdomain_wl = ["www", "internal", "admin", "staging", "dev", "api", "mail", "test"]
                results = await discover_vhosts(
                    target, subdomain_wl, ctx, scan_id, root_host_override=root_host
                )
                click.secho(f"  -> {len(results)} finding(s)", fg="green" if results else "white")
                for r in results:
                    click.echo(f"     [{r.status_code}] Host: {r.vhost}  title='{r.title}'")
                total += len(results)
            except ActiveModuleBlocked as e:
                click.secho(f"  [SKIPPED] {e}", fg="yellow")

        if "param" in module_list:
            if not param_name:
                click.secho("\n[param_fuzz] SKIPPED: --param <name> is required for this module.", fg="yellow")
            else:
                click.echo(f"\n[param_fuzz] Fuzzing parameter '{param_name}' on {param_target}...")
                try:
                    results = await fuzz_parameter(param_target, param_name, ctx, scan_id)
                    click.secho(f"  -> {len(results)} finding(s)", fg="green" if results else "white")
                    for r in results:
                        click.echo(f"     [{r.confidence}] {r.vuln_type}: {r.evidence}")
                    total += len(results)
                except ActiveModuleBlocked as e:
                    click.secho(f"  [SKIPPED] {e}", fg="yellow")

        if "api" in module_list:
            click.echo("\n[api_discovery] Discovering API endpoints...")
            try:
                endpoints = await discover_api_endpoints(target, ctx, scan_id, spec_file=spec_file)
                if endpoints:
                    click.secho(f"  -> Discovered {len(endpoints)} endpoint(s):", fg="green")
                    for ep in endpoints[:20]:  # show first 20
                        params_info = ""
                        if ep.query_params:
                            params_info += f" query=[{','.join(ep.query_params)}]"
                        if ep.path_params:
                            params_info += f" path=[{','.join(ep.path_params)}]"
                        if ep.json_body_schema:
                            fields = list(ep.json_body_schema.get("properties", {}).keys())
                            params_info += f" body=[{','.join(fields[:5])}]"
                        click.echo(f"     {ep.method:6s} {ep.path}{params_info}  ({ep.source})")
                    if len(endpoints) > 20:
                        click.echo(f"     ... and {len(endpoints) - 20} more")

                    click.echo("\n[api_fuzz] Running schema-aware vulnerability fuzzing...")
                    results = await fuzz_api_endpoints(target, endpoints, ctx, scan_id)
                    click.secho(f"  -> {len(results)} finding(s)", fg="green" if results else "white")
                    for r in results:
                        click.echo(f"     [{r.confidence}] {r.vuln_type} in '{r.parameter}': {r.evidence[:80]}")
                    total += len(results)
                else:
                    click.secho("  -> No API endpoints discovered.", fg="yellow")
            except ActiveModuleBlocked as e:
                click.secho(f"  [SKIPPED] {e}", fg="yellow")

        return total

    try:
        # Single event loop for the whole scan -- ScanContext's rate limiter
        # holds an asyncio.Lock bound to whichever loop is running when it's
        # first used, so running each module through its own asyncio.run()
        # call (i.e. a fresh loop each time) breaks the lock on the 2nd+ call.
        total_findings = asyncio.run(run_all())
    finally:
        db.finish_scan(scan_id)

    click.secho(f"\nScan {scan_id[:8]} complete. {total_findings} total finding(s). "
                f"Run 'python cli/argus_cli.py findings --scan {scan_id[:8]}' to review.",
                fg="cyan", bold=True)


@cli.command()
@click.argument("target")
@click.option("--scope", "scope_file", default="scope/scope.yaml", show_default=True,
              help="Path to the signed scope.yaml authorization file.")
@click.option("--output", "output_wordlist", default="wordlists/talk2tables.txt", show_default=True,
              help="File path to save the generated wordlist.")
def discover(target, scope_file, output_wordlist):
    """Automatically discover API routes from OpenAPI/Swagger specs and save to wordlist."""
    try:
        ctx = ScanContext(scope_file, confirmed_active=False, requests_per_second=15.0)
        ctx.assert_in_scope(target)
    except ScopeError as e:
        click.secho(f"[BLOCKED] {e}", fg="red", bold=True)
        sys.exit(1)

    click.echo(f"Probing {target} for OpenAPI / Swagger specs...")
    routes = asyncio.run(discover_api_routes(target, ctx, output_wordlist=output_wordlist))
    if routes:
        click.secho(f"[+] Discovered {len(routes)} routes! Saved to '{output_wordlist}'.", fg="green", bold=True)
        for r in routes:
            click.echo(f"   - {r}")
    else:
        click.secho("[-] No OpenAPI specs found on target.", fg="yellow")


@cli.command()
@click.option("--scan", "scan_id_prefix", default=None,
              help="Scan ID prefix to triage. Omit to triage all confirmed findings across all scans.")
def triage(scan_id_prefix):
    """Generate LLM fix suggestions for confirmed findings (FR-8.1)."""
    from core.ai_triage import triage_scan, LLM_PROVIDER, GEMINI_API_KEY, OPENAI_API_KEY

    db.init_db()
    scan_id = None
    if scan_id_prefix:
        matches = [s["scan_id"] for s in db.get_scans() if s["scan_id"].startswith(scan_id_prefix)]
        if not matches:
            click.secho(f"No scan found matching prefix '{scan_id_prefix}'.", fg="red")
            sys.exit(1)
        scan_id = matches[0]

    key_configured = bool(GEMINI_API_KEY or OPENAI_API_KEY)
    click.echo(f"LLM provider: {LLM_PROVIDER} (key configured: {key_configured})")
    if not key_configured:
        click.secho("No API key set -- suggestions will use offline fallback guidance.", fg="yellow")

    count = triage_scan(scan_id=scan_id)
    click.secho(f"Generated {count} fix suggestion(s). View them in the dashboard.", fg="cyan", bold=True)


@cli.command()
@click.option("--scan", "scan_id_prefix", default=None, help="Filter by scan ID prefix.")
@click.option("--min-severity", default=0.0, show_default=True, help="Only show findings >= this severity.")
def findings(scan_id_prefix, min_severity):
    """List findings from the database, sorted by severity."""
    db.init_db()
    all_findings = db.get_findings()

    if scan_id_prefix:
        all_findings = [f for f in all_findings if f["scan_id"].startswith(scan_id_prefix)]
    all_findings = [f for f in all_findings if f["severity_score"] >= min_severity]

    if not all_findings:
        click.echo("No findings match the given filters.")
        return

    for f in all_findings:
        color = "red" if f["severity_score"] >= 7 else ("yellow" if f["severity_score"] >= 4 else "white")
        click.secho(
            f"[{f['severity_score']:.1f}] {f['vuln_type']} ({f['confidence']}) "
            f"via {f['module']} @ {f['url']} — {f['status']}",
            fg=color,
        )


@cli.command()
def scans():
    """List all scans on record."""
    db.init_db()
    for s in db.get_scans():
        click.echo(f"{s['scan_id'][:8]}  {s['target']:40s}  {s['status']:10s}  started {s['started_at']:.0f}")


if __name__ == "__main__":
    cli()
