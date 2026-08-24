"""
Argus Interactive CLI — Claude Code Style Terminal UI

Key interactions:
  Module selector  : Up/Down to navigate  |  Space to toggle [✓]
                     Tab to show description of current item
                     Enter to confirm      |  Esc to go back
  Report selector  : Up/Down to navigate scans
                     Enter to export       |  Esc to go back
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.columns import Columns
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
from rich.live import Live
from rich.table import Table

# prompt_toolkit — already installed as InquirerPy dependency
from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout import Layout
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import FormattedText

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from core.auth_gate import ScanContext, ActiveModuleBlocked, ScopeError
from core.dir_enum import enumerate_directories, load_wordlist as load_dir_wordlist
from core.vhost import discover_vhosts
from core.param_fuzz import fuzz_parameter, fuzz_api_endpoints
from core.api_discovery import discover_api_routes, discover_api_endpoints
from core.subdomain import enumerate_subdomains
from core.custom_rules import load_templates, run_all_templates
from core import report_gen
from cli.pixel_agents import render_agent_panel, get_frame, MODULE_NAMES

# ─── Constants ────────────────────────────────────────────────────────────────
VERSION = "1.0.0"

ARGUS_ART = r"""
    _    ____   ____ _   _ ____
   / \  |  _ \ / ___| | | / ___|
  / _ \ | |_) | |  _| | | \___ \
 / ___ \|  _ <| |_| | |_| |___) |
/_/   \_\_| \_\\____|\___/|____/"""

MODULES: Dict[str, Dict[str, str]] = {
    "dir": {
        "label": "Directory & File Enumeration",
        "kind":  "passive / active",
        "desc":  "Brute-forces hidden paths, sensitive files (.env, .git, backups) "
                 "with false-positive filtering via content-length and hash comparison.",
    },
    "vhost": {
        "label": "Virtual Host Discovery",
        "kind":  "active",
        "desc":  "Fuzzes the HTTP Host header to surface internal vhosts (admin, staging, "
                 "internal APIs) not exposed via public DNS.",
    },
    "param": {
        "label": "Parameter Fuzzing",
        "kind":  "active",
        "desc":  "Tests query-string and form parameters for SQLi, XSS, and path-traversal. "
                 "Auto-crawls the target HTML for fuzzable inputs if no param is specified.",
    },
    "api": {
        "label": "Schema-Aware API Discovery",
        "kind":  "active",
        "desc":  "Fetches OpenAPI / Swagger specs (live or local), enumerates all routes, "
                 "then fuzzes every parameter with targeted security payloads.",
    },
    "subdomain": {
        "label": "Subdomain Enumeration",
        "kind":  "passive + active DNS",
        "desc":  "Combines passive certificate-transparency logs (crt.sh), active DNS "
                 "brute-force wordlist, and AXFR zone-transfer probes.",
    },
    "rules": {
        "label": "Custom YAML Rule Templates",
        "kind":  "active",
        "desc":  "Runs Nuclei-style YAML templates — match on status codes, response "
                 "headers, or body patterns to detect custom vulnerability signatures.",
    },
}

console = Console()


# ─── Layout helpers ───────────────────────────────────────────────────────────

def _header(right_title: str = "Getting started",
            right_lines: Optional[List[str]] = None) -> None:
    """Persistent two-column header: big ARGUS art left, tips right."""
    console.clear()
    console.print()

    # Left: raw ASCII art — no Panel border, no flanking dashes
    art_lines = ARGUS_ART.strip("\n").splitlines()
    left_text = Text()
    for line in art_lines:
        left_text.append(line + "\n", style="bold blue")
    left_text.append(f"\n  v{VERSION}  —  Security Scanner", style="bright_black")

    # Right: contextual tips
    default_tips = [
        "[white]Select [cyan]1[/cyan]  Scan wizard — full config[/white]",
        "[white]Select [cyan]2[/cyan]  Quick scan — fast presets[/white]",
        "[white]Select [cyan]3[/cyan]  Export reports[/white]",
        "[white]Select [cyan]4[/cyan]  View all findings[/white]",
    ]
    body = "\n".join(right_lines if right_lines is not None else default_tips)

    right = Panel(
        body,
        title=f"[bright_black]{right_title}[/bright_black]",
        border_style="bright_black",
        padding=(1, 2),
    )

    console.print(Columns([left_text, right], expand=True, equal=True, padding=(0, 2)))
    console.print()


def _rule(title: str = "") -> None:
    if title:
        console.print(Rule(f" {title} ", style="blue", align="left"))
    else:
        console.print(Rule(style="bright_black"))


def _kv(key: str, value: str, width: int = 16) -> None:
    console.print(f"  [bright_black]{key:<{width}}[/bright_black]  [white]{value}[/white]")


def safe_input() -> None:
    try:
        if sys.stdin.isatty():
            input()
    except Exception:
        pass


# ─── Interactive module selector ──────────────────────────────────────────────

def _select_modules_interactive(
    default: Optional[List[str]] = None,
) -> Optional[List[str]]:
    """
    Arrow + Space + Tab interactive module selector.
      Up / Down   navigate items
      Space       toggle selection  ([✓] / [ ])
      Tab         show / hide description for current item
      Enter       confirm and return selected list
      Esc         go back to main menu (returns None)
    """
    all_ids = list(MODULES.keys())
    selected = set(default or ["dir", "vhost"])
    cursor = [0]
    show_desc = [False]
    result: List[Optional[List[str]]] = [None]

    # ── key bindings ─────────────────────────────────────────────────────────
    kb = KeyBindings()

    @kb.add("up")
    def _up(event):
        cursor[0] = (cursor[0] - 1) % len(all_ids)
        show_desc[0] = False
        event.app.invalidate()

    @kb.add("down")
    def _down(event):
        cursor[0] = (cursor[0] + 1) % len(all_ids)
        show_desc[0] = False
        event.app.invalidate()

    @kb.add("space")
    def _toggle(event):
        mid = all_ids[cursor[0]]
        if mid in selected:
            selected.discard(mid)
        else:
            selected.add(mid)
        event.app.invalidate()

    @kb.add("tab")
    def _desc(event):
        show_desc[0] = not show_desc[0]
        event.app.invalidate()

    @kb.add("enter")
    def _confirm(event):
        result[0] = [m for m in all_ids if m in selected]
        event.app.exit()

    @kb.add("escape")
    def _back(event):
        result[0] = None
        event.app.exit()

    # ── content renderer ─────────────────────────────────────────────────────
    def _render() -> FormattedText:
        lines: list = []

        for i, mid in enumerate(all_ids):
            meta   = MODULES[mid]
            is_cur = i == cursor[0]
            is_sel = mid in selected

            arrow = ">" if is_cur else " "
            tick  = "✓" if is_sel else " "

            if is_cur:
                arrow_s  = "class:arrow"
                bracket_s = "class:bracket-sel" if is_sel else "class:bracket-cur"
                tick_s   = "class:tick-sel" if is_sel else "class:tick-cur"
                id_s     = "class:id-cur"
                label_s  = "class:label-cur"
                kind_s   = "class:kind"
            else:
                arrow_s  = "class:normal"
                bracket_s = "class:bracket-sel" if is_sel else "class:bracket-off"
                tick_s   = "class:tick-sel" if is_sel else "class:tick-off"
                id_s     = "class:id-sel" if is_sel else "class:id-off"
                label_s  = "class:label-sel" if is_sel else "class:label-off"
                kind_s   = "class:kind"

            lines += [
                (arrow_s,   f"  {arrow} "),
                (bracket_s, "["),
                (tick_s,    tick),
                (bracket_s, "]"),
                ("",        "  "),
                (id_s,      f"{mid:<12}"),
                (label_s,   f"{meta['label']:<36}"),
                (kind_s,    f"  {meta['kind']}"),
                ("",        "\n"),
            ]

        # Description pane (toggled by Tab)
        if show_desc[0]:
            cur_mid = all_ids[cursor[0]]
            lines += [
                ("",             "\n"),
                ("class:d-head", f"  {cur_mid}  "),
                ("class:d-kind", f"({MODULES[cur_mid]['kind']})\n"),
                ("class:d-text", f"  {MODULES[cur_mid]['desc']}\n"),
            ]

        lines += [
            ("", "\n"),
            ("class:hint",
             "  Up/Down: navigate   Space: toggle   Tab: description"
             "   Enter: confirm   Esc: main menu\n"),
        ]

        return FormattedText(lines)

    style = Style.from_dict({
        "arrow":       "bold ansicyan",
        "normal":      "",
        "bracket-sel": "bold ansicyan",
        "bracket-cur": "bold ansiblue",
        "bracket-off": "ansibrightblack",
        "tick-sel":    "bold ansicyan",
        "tick-cur":    "ansiblue",
        "tick-off":    "ansibrightblack",
        "id-cur":      "bold ansiwhite",
        "id-sel":      "ansicyan",
        "id-off":      "ansibrightblack",
        "label-cur":   "bold ansiwhite",
        "label-sel":   "ansiwhite",
        "label-off":   "ansibrightblack",
        "kind":        "ansibrightblack",
        "d-head":      "bold ansicyan",
        "d-kind":      "ansibrightblack",
        "d-text":      "ansiwhite",
        "hint":        "ansibrightblack",
    })

    ctrl   = FormattedTextControl(_render, focusable=True)
    window = Window(content=ctrl)
    app    = Application(layout=Layout(window), key_bindings=kb,
                         style=style, full_screen=False, mouse_support=False)
    app.run()
    return result[0]


# ─── Interactive scan selector (for report export) ────────────────────────────

def _select_scan_interactive(scans: List[dict]) -> Optional[dict]:
    """
    Arrow-key scan selector.
      Up / Down   navigate scans
      a           select all scans (returns {})
      Enter       choose highlighted scan
      Esc         go back (returns None)
    """
    if not scans:
        return None

    items  = scans[:20]
    cursor = [0]
    result: List[Optional[dict]] = [None]

    kb = KeyBindings()

    @kb.add("up")
    def _up(event):
        cursor[0] = (cursor[0] - 1) % len(items)
        event.app.invalidate()

    @kb.add("down")
    def _down(event):
        cursor[0] = (cursor[0] + 1) % len(items)
        event.app.invalidate()

    @kb.add("a")
    def _all(event):
        result[0] = {}  # empty dict == all scans
        event.app.exit()

    @kb.add("enter")
    def _select(event):
        result[0] = items[cursor[0]]
        event.app.exit()

    @kb.add("escape")
    def _back(event):
        result[0] = None
        event.app.exit()

    def _render() -> FormattedText:
        lines: list = [
            ("class:col-header",
             f"  {'':2}  {'SCAN ID':<10}  {'TARGET':<36}  {'STATUS':<12}  STARTED\n"),
            ("class:sep", "  " + "─" * 80 + "\n"),
        ]

        for i, s in enumerate(items):
            is_cur = i == cursor[0]
            started = time.strftime(
                "%Y-%m-%d %H:%M",
                time.localtime(s.get("started_at") or 0),
            )
            arrow = ">" if is_cur else " "
            row_s = "class:row-cur" if is_cur else "class:row"
            lines += [
                ("class:arrow" if is_cur else "class:normal", f"  {arrow} "),
                (row_s, f"  {s['scan_id'][:8]:<10}  "
                         f"{s['target'][:35]:<36}  "
                         f"{s['status']:<12}  {started}"),
                ("", "\n"),
            ]

        lines += [
            ("", "\n"),
            ("class:hint",
             "  Up/Down: navigate   a: all scans   Enter: select   Esc: main menu\n"),
        ]
        return FormattedText(lines)

    style = Style.from_dict({
        "col-header": "ansibrightblack",
        "sep":        "ansiblue",
        "row-cur":    "bold ansiwhite",
        "row":        "ansiwhite",
        "arrow":      "bold ansicyan",
        "normal":     "",
        "hint":       "ansibrightblack",
    })

    ctrl   = FormattedTextControl(_render, focusable=True)
    window = Window(content=ctrl)
    app    = Application(layout=Layout(window), key_bindings=kb,
                         style=style, full_screen=False, mouse_support=False)
    app.run()
    return result[0]


# ─── Main CLI class ───────────────────────────────────────────────────────────

class ArgusInteractiveCLI:

    def __init__(self):
        db.init_db()

    # ── Main menu ─────────────────────────────────────────────────────────────

    def main_menu(self) -> None:
        MENU = [
            ("1", "Launch Interactive Scan Wizard"),
            ("2", "Quick Target Scan  (Fast Mode)"),
            ("3", "Generate & Export Reports  (HTML / PDF / JSON)"),
            ("4", "View Scan Database & Past Findings"),
            ("5", "Inspect Scope Authorization File"),
            ("0", "Exit"),
        ]

        while True:
            _header()

            for key, label in MENU:
                ks = "bold cyan" if key != "0" else "bright_black"
                ls = "white"     if key != "0" else "bright_black"
                console.print(f"  [{ks}]{key}[/{ks}]  [{ls}]{label}[/{ls}]")

            console.print()
            choice = Prompt.ask("[bold blue]>[/bold blue]", default="1").strip()

            dispatch = {
                "1": self.scan_wizard,    "wizard":   self.scan_wizard,
                "2": self.quick_scan,     "quick":    self.quick_scan,
                "3": self.export_reports, "reports":  self.export_reports,
                "4": self.view_findings,  "findings": self.view_findings,
                "5": self.inspect_scope,  "scope":    self.inspect_scope,
                "0": self._exit,
                "q": self._exit, "exit": self._exit, "quit": self._exit,
            }

            fn = dispatch.get(choice)
            if fn:
                fn()
            else:
                console.print(f"\n  [red]Unknown option '{choice}'.[/red]")
                time.sleep(0.8)

    def _exit(self) -> None:
        console.print("\n  [bright_black]Goodbye.[/bright_black]\n")
        sys.exit(0)

    # ── Quick scan ────────────────────────────────────────────────────────────

    def quick_scan(self) -> None:
        _header(
            right_title="Quick Scan",
            right_lines=[
                "[white]Presets: dir, vhost, param, api[/white]",
                "[white]Rate: 15 req/s[/white]",
                "[white]Wordlist: wordlists/common.txt[/white]",
                "[white]Reports: saved to reports/[/white]",
            ],
        )
        _rule("QUICK SCAN")
        console.print()

        target = Prompt.ask(
            "  [bold blue]>[/bold blue] Target URL / IP",
            default="http://127.0.0.1:8080",
        ).strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        confirmed = Confirm.ask(
            "  [bold blue]>[/bold blue] Enable active modules  (vhost, param, api)",
            default=True,
        )
        modules = ["dir", "vhost", "param", "api"] if confirmed else ["dir"]

        asyncio.run(self._run_scan(
            target=target, scope_file="scope/scope.yaml",
            modules=modules, confirmed_active=confirmed,
            rate=15.0, wordlist="wordlists/common.txt",
            auto_discover=True, root_host=None,
            param_name=None, param_url=None,
            spec_file=None, templates_path=None,
            output_folder="reports", report_formats="all",
        ))

    # ── Scan wizard ───────────────────────────────────────────────────────────

    def scan_wizard(self) -> None:
        # Step 1 — target
        _header(
            right_title="Step 1 / 6  —  Target",
            right_lines=[
                "[white]Enter the full URL, bare IP, or domain.[/white]",
                "[bright_black]Examples:[/bright_black]",
                "[cyan]  http://192.168.1.10:8080[/cyan]",
                "[cyan]  https://example.com[/cyan]",
                "[cyan]  10.0.0.1[/cyan]",
            ],
        )
        _rule("TARGET")
        console.print()
        target = Prompt.ask(
            "  [bold blue]>[/bold blue] URL / IP / Domain",
            default="http://127.0.0.1:8080",
        ).strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        # Step 2 — scope file
        _header(
            right_title="Step 2 / 6  —  Scope File",
            right_lines=[
                "[white]YAML file that authorizes this scan.[/white]",
                "[white]Must list the target host or CIDR.[/white]",
                "[bright_black]Default: scope/scope.yaml[/bright_black]",
            ],
        )
        _rule("SCOPE FILE")
        console.print()
        scope_file = Prompt.ask(
            "  [bold blue]>[/bold blue] Path to scope.yaml",
            default="scope/scope.yaml",
        ).strip()

        # Step 3 — module selection (arrow + space + tab)
        _header(
            right_title="Step 3 / 6  —  Modules",
            right_lines=[
                "[white]Use [cyan]Up/Down[/cyan] to navigate[/white]",
                "[white]Use [cyan]Space[/cyan] to toggle [cyan][✓][/cyan][/white]",
                "[white]Press [cyan]Tab[/cyan] on a module to see its description[/white]",
                "[white]Press [cyan]Enter[/cyan] to confirm selection[/white]",
                "[white]Press [cyan]Esc[/cyan] to return to main menu[/white]",
            ],
        )
        _rule("SELECT MODULES")
        console.print()

        modules = _select_modules_interactive(default=["dir", "vhost"])
        if modules is None:
            return  # Esc → back to main menu

        # Step 4 — active module auth
        has_active       = any(m in modules for m in ("vhost", "param", "api"))
        confirmed_active = False
        if has_active:
            _header(
                right_title="Step 4 / 6  —  Authorization",
                right_lines=[
                    "[yellow]Active modules send real HTTP requests.[/yellow]",
                    "[white]Only scan systems you own or have[/white]",
                    "[white]explicit written permission to test.[/white]",
                ],
            )
            _rule("ACTIVE MODULE AUTHORIZATION")
            console.print()
            confirmed_active = Confirm.ask(
                "  [bold blue]>[/bold blue] I own / have authorization to scan this target",
                default=False,
            )
            if not confirmed_active:
                console.print("\n  [bright_black]Active modules will be skipped.[/bright_black]")
                time.sleep(1)

        # Step 5 — advanced options
        _header(
            right_title="Step 5 / 6  —  Advanced Options",
            right_lines=[
                "[white]Rate: requests per second[/white]",
                "[white]Wordlist: path for dir enumeration[/white]",
                "[white]Param: manual name or auto-crawl[/white]",
                "[white]Spec: local OpenAPI file (optional)[/white]",
            ],
        )
        _rule("ADVANCED OPTIONS")
        console.print()

        rate_str = Prompt.ask("  [bold blue]>[/bold blue] Rate limit  (req/sec)", default="15.0")
        try:    rate = float(rate_str)
        except: rate = 15.0

        wordlist = "wordlists/common.txt"
        if "dir" in modules:
            wordlist = Prompt.ask(
                "  [bold blue]>[/bold blue] Wordlist path",
                default="wordlists/common.txt",
            ).strip()

        auto_discover = False
        if "api" in modules or "param" in modules:
            auto_discover = Confirm.ask(
                "  [bold blue]>[/bold blue] Auto-discover OpenAPI / Swagger specs before scanning",
                default=True,
            )

        param_name = param_url = None
        if "param" in modules:
            manual = Confirm.ask(
                "  [bold blue]>[/bold blue] Specify a parameter manually  (skip auto-crawl)",
                default=False,
            )
            if manual:
                param_name = Prompt.ask(
                    "  [bold blue]>[/bold blue] Parameter name  (e.g. q)", default="q"
                ).strip()
                param_url = Prompt.ask(
                    "  [bold blue]>[/bold blue] Parameter URL  (Enter = use target)",
                    default=target,
                ).strip()

        root_host = None
        if "vhost" in modules:
            rh = Prompt.ask(
                "  [bold blue]>[/bold blue] Root domain for vhost fuzzing  (Enter = auto)",
                default="",
            ).strip()
            root_host = rh or None

        spec_file = None
        if "api" in modules:
            sp = Prompt.ask(
                "  [bold blue]>[/bold blue] Local OpenAPI spec file  (Enter = skip)",
                default="",
            ).strip()
            spec_file = sp or None

        templates_path = None
        if "rules" in modules:
            templates_path = Prompt.ask(
                "  [bold blue]>[/bold blue] YAML templates path", default="templates/"
            ).strip()

        # Step 6 — report settings
        _header(
            right_title="Step 6 / 6  —  Report Settings",
            right_lines=[
                "[white]Reports auto-saved after scan.[/white]",
                "[bright_black]Formats: html  pdf  json  all[/bright_black]",
            ],
        )
        _rule("REPORT SETTINGS")
        console.print()
        output_folder  = Prompt.ask(
            "  [bold blue]>[/bold blue] Output directory", default="reports"
        ).strip()
        report_formats = Prompt.ask(
            "  [bold blue]>[/bold blue] Formats  (html / pdf / json / all)", default="all"
        ).strip().lower()

        # Confirm summary
        _header(
            right_title="Review & Confirm",
            right_lines=[
                f"[bright_black]Target   [/bright_black][white]{target}[/white]",
                f"[bright_black]Modules  [/bright_black][cyan]{', '.join(modules)}[/cyan]",
                f"[bright_black]Rate     [/bright_black][white]{rate} req/s[/white]",
                f"[bright_black]Auth     [/bright_black][white]{'yes' if confirmed_active else 'no'}[/white]",
                f"[bright_black]Reports  [/bright_black][white]{output_folder}/ ({report_formats})[/white]",
            ],
        )
        _rule("CONFIRM")
        console.print()
        _kv("Target",      target)
        _kv("Modules",     "  ".join(modules))
        _kv("Rate",        f"{rate} req/s")
        _kv("Active auth", "yes  (--i-own-this)" if confirmed_active else "no")
        _kv("Scope file",  scope_file)
        _kv("Report dir",  output_folder + "/")
        _kv("Formats",     report_formats)
        console.print()

        if not Confirm.ask("  [bold blue]>[/bold blue] Start scan now", default=True):
            console.print("\n  [bright_black]Scan cancelled.[/bright_black]\n")
            time.sleep(0.8)
            return

        asyncio.run(self._run_scan(
            target=target, scope_file=scope_file,
            modules=modules, confirmed_active=confirmed_active,
            rate=rate, wordlist=wordlist,
            auto_discover=auto_discover, root_host=root_host,
            param_name=param_name, param_url=param_url,
            spec_file=spec_file, templates_path=templates_path,
            output_folder=output_folder, report_formats=report_formats,
        ))

    # ── Scan engine ───────────────────────────────────────────────────────────

    async def _run_scan(
        self, target, scope_file, modules, confirmed_active,
        rate, wordlist, auto_discover, root_host,
        param_name, param_url, spec_file, templates_path,
        output_folder, report_formats,
    ) -> None:

        _header(
            right_title="Scan in Progress",
            right_lines=[
                f"[white]Target   [bright_black]{target}[/bright_black][/white]",
                f"[white]Modules  [cyan]{', '.join(modules)}[/cyan][/white]",
                f"[white]Rate     [bright_black]{rate} req/s[/bright_black][/white]",
            ],
        )
        _rule("LIVE EXECUTION")
        console.print()

        # Scope check
        try:
            ctx = ScanContext(scope_file, confirmed_active=confirmed_active, requests_per_second=rate)
            ctx.assert_in_scope(target)
            console.print(f"  [green][+][/green]  Scope authorized  [bright_black]{scope_file}[/bright_black]")
        except ScopeError as e:
            console.print(f"\n  [red][!]  Scope blocked:[/red] {e}\n")
            Prompt.ask("  Press Enter to return")
            return

        scan_id = db.start_scan(target, scope_file=scope_file)
        console.print(f"  [bright_black][*]  Session {scan_id[:8]}  |  {', '.join(modules)}  |  {rate} req/s[/bright_black]")
        console.print()

        start_time  = time.time()
        total_found = 0
        stream: List[str] = []

        # Auto-discover
        if auto_discover and ("api" in modules or "dir" in modules):
            console.print("  [bright_black][*]  Probing for OpenAPI / Swagger specs...[/bright_black]")
            auto_wl = "wordlists/talk2tables.txt" if wordlist == "wordlists/common.txt" else wordlist
            disc    = await discover_api_routes(target, ctx, output_wordlist=auto_wl)
            if disc:
                console.print(f"  [green][+][/green]  {len(disc)} route(s) discovered — wordlist updated")
                wordlist = auto_wl
            console.print()

        # ── Helper: run one module with animated pixel agent display ──────────
        async def _run_module_animated(
            mod_id: str,
            label: str,
            coro,
        ):
            """
            Runs `coro` (an awaitable) while showing an animated pixel-art
            agent character in a Rich Live panel on the left and a progress
            bar + latest-finding log on the right.
            Returns the result of `coro`.
            """
            tick       = 0
            done_flag  = [False]
            coro_result = [None]
            log_lines: List[str] = []

            def _build_live() -> Table:
                """Build the two-column live renderable."""
                # Left: animated pixel agent panel
                agent_markup = render_agent_panel(
                    mod_id, tick,
                    status_line=f"findings: {len(log_lines)}"
                )
                agent_panel = Panel(
                    agent_markup,
                    title=f"[bold cyan]{MODULE_NAMES.get(mod_id, 'Agent')}[/bold cyan]",
                    border_style="blue",
                    width=22,
                    padding=(0, 1),
                )

                # Right: label + recent log lines
                log_text = "\n".join(
                    f"[bright_black]{ln[-60:]}[/bright_black]"
                    for ln in log_lines[-6:]
                ) or "[bright_black]running...[/bright_black]"

                right_panel = Panel(
                    f"[bold bright_blue]{label}[/bold bright_blue]\n\n{log_text}",
                    border_style="bright_black",
                    padding=(0, 1),
                )

                grid = Table.grid(expand=True)
                grid.add_column(width=22)
                grid.add_column()
                grid.add_row(agent_panel, right_panel)
                return grid

            async def _animate():
                nonlocal tick
                while not done_flag[0]:
                    await asyncio.sleep(0.25)
                    tick += 1

            async def _run_coro():
                coro_result[0] = await coro
                done_flag[0] = True

            with Live(
                _build_live(),
                console=console,
                refresh_per_second=4,
                transient=False,
            ) as live:
                anim_task = asyncio.create_task(_animate())
                run_task  = asyncio.create_task(_run_coro())

                while not done_flag[0]:
                    live.update(_build_live())
                    await asyncio.sleep(0.25)

                anim_task.cancel()
                await run_task
                # Final frame — show done state
                live.update(_build_live())

            return coro_result[0], log_lines

        # ── dir_enum ──────────────────────────────────────────────────────────
        if "dir" in modules:
            if Path(wordlist).exists():
                wl = load_dir_wordlist(wordlist)

                async def _dir_coro():
                    return await enumerate_directories(target, wl, ctx, scan_id)

                results, _ = await _run_module_animated(
                    "dir", "Directory & File Enumeration", _dir_coro()
                )
                total_found += len(results)
                for r in results:
                    stream.append(f"[EXPOSED]    {r.status_code}  {r.url}  ({r.note})")
                console.print(f"  [bright_black]dir_enum complete — {len(results)} paths[/bright_black]\n")
            else:
                console.print(f"  [yellow][!]  Wordlist not found: {wordlist}[/yellow]")
                stream.append(f"[SKIP]       Wordlist not found: {wordlist}")

        # ── vhost ─────────────────────────────────────────────────────────────
        if "vhost" in modules:
            try:
                wl_vhost = ["www", "internal", "admin", "staging", "dev", "api", "mail", "test"]

                async def _vhost_coro():
                    return await discover_vhosts(
                        target, wl_vhost, ctx, scan_id, root_host_override=root_host
                    )

                results, _ = await _run_module_animated(
                    "vhost", "Virtual Host Discovery", _vhost_coro()
                )
                total_found += len(results)
                for r in results:
                    stream.append(f"[VHOST]      {r.vhost}  status={r.status_code}  title='{r.title}'")
                console.print(f"  [bright_black]vhost complete — {len(results)} virtual hosts[/bright_black]\n")
            except ActiveModuleBlocked as e:
                console.print(f"  [yellow][!]  vhost skipped: {e}[/yellow]\n")
                stream.append(f"[SKIP]       vhost — {e}")

        # ── param ─────────────────────────────────────────────────────────────
        if "param" in modules:
            try:
                ctx.assert_active_allowed()
                p_url = param_url or target

                if param_name:
                    async def _param_coro():
                        return await fuzz_parameter(p_url, param_name, ctx, scan_id)

                    results, _ = await _run_module_animated(
                        "param", f"Parameter Fuzzing  [{param_name}]", _param_coro()
                    )
                    total_found += len(results)
                    for r in results:
                        stream.append(f"[VULN]       {r.vuln_type}  param={param_name}  {r.evidence[:60]}")
                    console.print(f"  [bright_black]param complete — {len(results)} vulnerabilities[/bright_black]\n")
                else:
                    console.print("  [bright_black][*]  param: no --param set, skipping manual fuzz[/bright_black]\n")
            except ActiveModuleBlocked as e:
                console.print(f"  [yellow][!]  param skipped: {e}[/yellow]\n")
                stream.append(f"[SKIP]       param — {e}")

        # ── api ───────────────────────────────────────────────────────────────
        if "api" in modules:
            try:
                ctx.assert_active_allowed()

                async def _api_coro():
                    eps = await discover_api_endpoints(
                        target, ctx, scan_id=scan_id, spec_file=spec_file
                    )
                    if eps:
                        return await fuzz_api_endpoints(target, eps, ctx, scan_id=scan_id)
                    return []

                results, _ = await _run_module_animated(
                    "api", "API Discovery & Fuzzing", _api_coro()
                )
                total_found += len(results)
                for r in results:
                    stream.append(f"[API]        {r.vuln_type}  {r.endpoint}  {r.evidence[:60]}")
                console.print(f"  [bright_black]api complete — {len(results)} issues[/bright_black]\n")
            except ActiveModuleBlocked as e:
                console.print(f"  [yellow][!]  api skipped: {e}[/yellow]\n")
                stream.append(f"[SKIP]       api — {e}")

        # ── subdomain ─────────────────────────────────────────────────────────
        if "subdomain" in modules:
            async def _sub_coro():
                return await enumerate_subdomains(target, ctx, scan_id)

            results, _ = await _run_module_animated(
                "subdomain", "Subdomain Enumeration  (DNS/AXFR)", _sub_coro()
            )
            total_found += len(results)
            for r in results:
                stream.append(f"[SUBDOMAIN]  {r.subdomain}  ({r.source})")
            console.print(f"  [bright_black]subdomain complete — {len(results)} found[/bright_black]\n")

        # ── rules ─────────────────────────────────────────────────────────────
        if "rules" in modules and templates_path:
            tpls = load_templates(templates_path)

            async def _rules_coro():
                return await run_all_templates(target, tpls, ctx, scan_id)

            results, _ = await _run_module_animated(
                "rules", "YAML Template Scanner", _rules_coro()
            )
            total_found += len(results)
            for r in results:
                stream.append(f"[RULE]       {r.rule_name}  matched at {r.matched_at}")
            console.print(f"  [bright_black]rules complete — {len(results)} matches[/bright_black]\n")

        db.finish_scan(scan_id)
        elapsed = round(time.time() - start_time, 2)

        # Results
        console.print()
        _rule("RESULTS")
        console.print()
        _kv("Duration",  f"{elapsed}s")
        _kv("Findings",  str(total_found))
        console.print()

        SEV = {
            "VULN": "red", "API": "red", "EXPOSED": "yellow",
            "VHOST": "cyan", "SUBDOMAIN": "bright_blue",
            "RULE": "magenta", "SKIP": "bright_black",
        }
        if stream:
            for line in stream[:20]:
                tag   = line.split("]")[0].lstrip("[").strip()
                color = SEV.get(tag, "white")
                console.print(f"  [{color}]{line}[/{color}]")
            if len(stream) > 20:
                console.print(f"\n  [bright_black]... and {len(stream) - 20} more[/bright_black]")
        else:
            console.print("  [bright_black]No findings recorded.[/bright_black]")

        # Auto-save reports
        console.print()
        _rule("REPORT EXPORT")
        console.print()
        os.makedirs(output_folder, exist_ok=True)
        ts       = time.strftime("%Y%m%d_%H%M%S")
        safe_tgt = (target.replace("http://", "").replace("https://", "")
                          .replace("/", "_").replace(":", "_"))
        saved: List[tuple] = []

        if report_formats in ("html", "all"):
            p = os.path.join(output_folder, f"argus_{safe_tgt}_{ts}.html")
            try:
                report_gen.export_html(output_path=p, scan_id=scan_id)
                saved.append(("HTML", p))
            except Exception as e:
                console.print(f"  [red][!]  HTML: {e}[/red]")

        if report_formats in ("pdf", "all"):
            p = os.path.join(output_folder, f"argus_{safe_tgt}_{ts}.pdf")
            try:
                report_gen.export_pdf(output_path=p, scan_id=scan_id)
                saved.append(("PDF ", p))
            except Exception as e:
                console.print(f"  [red][!]  PDF: {e}[/red]")

        if report_formats in ("json", "all"):
            p = os.path.join(output_folder, f"argus_{safe_tgt}_{ts}.json")
            try:
                data = db.get_findings(scan_id=scan_id)
                with open(p, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, default=str)
                saved.append(("JSON", p))
            except Exception as e:
                console.print(f"  [red][!]  JSON: {e}[/red]")

        for fmt, path in saved:
            console.print(f"  [green][+][/green]  [bright_black]{fmt}[/bright_black]  {os.path.abspath(path)}")

        console.print()
        console.print("  [bright_black]Press Enter to return to the main menu...[/bright_black]")
        safe_input()

    # ── Export reports ────────────────────────────────────────────────────────

    def export_reports(self) -> None:
        scans = db.get_scans()

        _header(
            right_title="Report Export",
            right_lines=[
                "[white]Use [cyan]Up/Down[/cyan] to navigate scans[/white]",
                "[white]Press [cyan]Enter[/cyan] to export selected scan[/white]",
                "[white]Press [cyan]a[/cyan] to export all scans combined[/white]",
                "[white]Press [cyan]Esc[/cyan] to return to main menu[/white]",
            ],
        )
        _rule("SELECT SCAN TO EXPORT")
        console.print()

        if not scans:
            console.print("  [yellow]No scan sessions in database. Run a scan first.[/yellow]")
            console.print("\n  [bright_black]Press Enter to return...[/bright_black]")
            safe_input()
            return

        # Arrow-key scan selector
        chosen = _select_scan_interactive(scans)

        if chosen is None:
            return  # Esc → back to main menu

        # chosen == {} means all scans; otherwise it's a scan dict
        _header(
            right_title="Report Export",
            right_lines=[
                f"[white]Scan: [cyan]{'all scans' if not chosen else chosen['scan_id'][:8]}[/cyan][/white]",
                "[bright_black]Formats: html  pdf  json  all[/bright_black]",
            ],
        )
        _rule("EXPORT OPTIONS")
        console.print()

        scan_id = chosen.get("scan_id") if chosen else None
        folder  = Prompt.ask("  [bold blue]>[/bold blue] Output folder", default="reports").strip()
        fmt     = Prompt.ask("  [bold blue]>[/bold blue] Formats  (html / pdf / json / all)", default="all").strip().lower()

        os.makedirs(folder, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")

        console.print()
        if fmt in ("html", "all"):
            p = os.path.join(folder, f"argus_export_{ts}.html")
            report_gen.export_html(output_path=p, scan_id=scan_id)
            console.print(f"  [green][+][/green]  HTML  {os.path.abspath(p)}")

        if fmt in ("pdf", "all"):
            p = os.path.join(folder, f"argus_export_{ts}.pdf")
            report_gen.export_pdf(output_path=p, scan_id=scan_id)
            console.print(f"  [green][+][/green]  PDF   {os.path.abspath(p)}")

        if fmt in ("json", "all"):
            p = os.path.join(folder, f"argus_export_{ts}.json")
            data = db.get_findings(scan_id=scan_id)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
            console.print(f"  [green][+][/green]  JSON  {os.path.abspath(p)}")

        console.print("\n  [bright_black]Press Enter to return...[/bright_black]")
        safe_input()

    # ── Findings viewer ───────────────────────────────────────────────────────

    def view_findings(self) -> None:
        findings = db.get_findings()

        _header(
            right_title="Findings Database",
            right_lines=[
                f"[white]Total records: [cyan]{len(findings)}[/cyan][/white]",
                "[bright_black]Sorted by severity (high → low)[/bright_black]",
            ],
        )
        _rule("FINDINGS DATABASE")
        console.print()

        if not findings:
            console.print("  [yellow]Database is empty. Run a scan first.[/yellow]")
            console.print("\n  [bright_black]Press Enter to return...[/bright_black]")
            safe_input()
            return

        console.print(
            f"  [bright_black]{'SCAN':<10}  {'TYPE':<15}  {'CONF':<12}  {'SEV':>5}  URL[/bright_black]"
        )
        console.print(f"  [blue]{'─' * 88}[/blue]")

        VTYPE_C = {"RCE": "red", "SQLi": "red", "XSS": "yellow",
                   "exposed_file": "cyan", "misconfig": "bright_blue"}

        for f in findings[:30]:
            sev   = f.get("severity_score", 0.0)
            sc    = "red" if sev >= 8 else "yellow" if sev >= 5 else "bright_black"
            vtype = f.get("vuln_type", "N/A")
            vc    = VTYPE_C.get(vtype, "white")
            url   = (f.get("url") or f.get("target") or "")[:50]
            console.print(
                f"  [bright_black]{f.get('scan_id','')[:8]:<10}[/bright_black]"
                f"  [{vc}]{vtype:<15}[/{vc}]"
                f"  [bright_black]{f.get('confidence',''):<12}[/bright_black]"
                f"  [{sc}]{sev:>5.1f}[/{sc}]"
                f"  [white]{url}[/white]"
            )

        if len(findings) > 30:
            console.print(f"\n  [bright_black]... and {len(findings) - 30} more[/bright_black]")

        console.print("\n  [bright_black]Press Enter to return...[/bright_black]")
        safe_input()

    # ── Scope inspector ───────────────────────────────────────────────────────

    def inspect_scope(self) -> None:
        _header(
            right_title="Scope Authorization",
            right_lines=[
                "[white]The scope YAML grants Argus permission[/white]",
                "[white]to scan specific hosts or CIDRs.[/white]",
                "[bright_black]Format: targets, exclusions,[/bright_black]",
                "[bright_black]active flag, rate limits.[/bright_black]",
            ],
        )
        _rule("SCOPE AUTHORIZATION")
        console.print()

        path = Prompt.ask(
            "  [bold blue]>[/bold blue] Path to scope.yaml", default="scope/scope.yaml"
        ).strip()
        console.print()

        if not Path(path).exists():
            console.print(f"  [red][!]  File not found: {path}[/red]")
        else:
            console.print(f"  [green][+][/green]  {os.path.abspath(path)}\n")
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("#"):
                    console.print(f"  [bright_black]{line}[/bright_black]")
                elif ":" in line:
                    k, _, v = line.partition(":")
                    console.print(f"  [cyan]{k}[/cyan][bright_black]:[/bright_black][white]{v}[/white]")
                else:
                    console.print(f"  [white]{line}[/white]")

        console.print("\n  [bright_black]Press Enter to return...[/bright_black]")
        safe_input()


# ─── Entry point ──────────────────────────────────────────────────────────────

def launch_interactive_cli() -> None:
    ArgusInteractiveCLI().main_menu()


if __name__ == "__main__":
    launch_interactive_cli()
