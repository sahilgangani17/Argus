# Argus — Implementation Audit & Status Report (SIH1750)

**Date:** August 24, 2026
**Status:** Core Backend, Fuzzing Pipeline & Interactive TUI Active | Multi-Surface Expansion Pending

---

## 1. Executive Summary

| Category | Total Requirements | Implemented | Pending | Completion Rate |
|---|---|---|---|---|
| **Core Fuzzing Engines** | 6 | 6 | 0 | **100%** |
| **Authorization & Control** | 4 | 4 | 0 | **100%** |
| **Delivery Surfaces & UI** | 5 | 3 | 2 | **60%** |
| **AI & Scoring Engine** | 3 | 2 | 1 | **67%** |
| **Reporting & Export** | 1 | 1 | 0 | **100%** |
| **Overall Project** | **19** | **16** | **3** | **84%** |

---

## 2. Detailed Requirement Breakdown

### FR-0: Authorization Gate & Control
- **[FR-0.1] Signed Scope File Validation**: Done ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Enforces `scope.yaml` loading and allowlist host/IP matching before any requests fire.
- **[FR-0.2] Target Host Rejection**: Done ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Hostnames not matching scope rules are immediately blocked at the request layer with `ScopeViolation`.
- **[FR-0.3] Active Scanning Confirmation Flag**: Done ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Requires `--i-own-this` CLI flag (or TUI authorization step) to unlock active fuzzing modules.
- **[FR-0.4] Default Token-Bucket Rate Limiter**: Done ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Configurable async rate limiting (`requests_per_second`, default 15 req/sec).

---

### FR-1: Directory & File Enumeration
- **[FR-1.1] Async Multi-Threaded Brute Force**: Done ([core/dir_enum.py](file:///d:/Project/SIH/Argus/core/dir_enum.py))
  - High-concurrency directory enumeration using `httpx` async client and customizable wordlists.
- **[FR-1.2] Automatic Extension Permutations**: Done ([core/dir_enum.py](file:///d:/Project/SIH/Argus/core/dir_enum.py))
  - Permutes targets with extensions (`.php`, `.bak`, `.env`, `.git`, `.zip`, etc.).
- **[FR-1.3] False-Positive Filtering (Custom-404 Detection)**: Done ([core/dir_enum.py](file:///d:/Project/SIH/Argus/core/dir_enum.py))
  - Establishes baseline responses to filter out soft-404 traps using status code, body size delta, and timing anomalies.

---

### FR-2: Virtual Host (VHost) Discovery
- **[FR-2.1] Host Header Fuzzing**: Done ([core/vhost.py](file:///d:/Project/SIH/Argus/core/vhost.py))
  - Fuzzes `Host` headers against target IP using subdomain wordlists.
- **[FR-2.2] Baseline Diff Detection**: Done ([core/vhost.py](file:///d:/Project/SIH/Argus/core/vhost.py))
  - Measures response size and page title against baseline invalid-vhost response to identify live virtual hosts.

---

### FR-3 & FR-4: API Endpoint Discovery & Schema-Aware Fuzzing
- **[FR-3.1 - FR-3.3] 4-Phase API Discovery**: Done ([core/api_discovery.py](file:///d:/Project/SIH/Argus/core/api_discovery.py))
  - Parses OpenAPI v2/v3 & Swagger specs (`/openapi.json`, `/swagger.json`).
  - Extracts endpoints passively from JS bundles using regex (`fetch`, `axios`, `$.ajax`, template literals).
  - Extracts endpoints from HTML forms and `<a>` links.
  - OPTIONS method probing & REST wordlist brute-forcing.
- **[FR-4.1 - FR-4.4] Targeted Vulnerability Fuzzing**: Done ([core/param_fuzz.py](file:///d:/Project/SIH/Argus/core/param_fuzz.py))
  - Fuzzes query parameters, JSON body fields, and HTTP headers.
  - Detects **SQL Injection** (error-based & delay timing), **Reflected XSS**, **IDOR/BOLA**, **Mass Assignment**, **Type Confusion**, and **Header Injection**.
  - Applies encoding variants (raw, URL, double-URL, Unicode) and assigns `confirmed` vs `suspected` labels.

---

### FR-5: Subdomain Enumeration
- **[FR-5.1] Active DNS Brute-Force & Zone Transfer**: Done ([core/subdomain.py](file:///d:/Project/SIH/Argus/core/subdomain.py))
  - Wordlist-based DNS resolution across 105 built-in dictionary words and `AXFR` zone-transfer attempts.
- **[FR-5.2] Passive Certificate Transparency Lookups**: Done ([core/subdomain.py](file:///d:/Project/SIH/Argus/core/subdomain.py))
  - Queries Certificate Transparency logs via `crt.sh` JSON API.
- **[FR-5.3] Liveness Verification & Recursive Feedback**: Done ([core/subdomain.py](file:///d:/Project/SIH/Argus/core/subdomain.py))
  - Resolves IP addresses, probes HTTP/HTTPS liveness, and automatically feeds live subdomains back into directory enumeration.

---

### FR-6: Custom Test Cases (YAML Templates)
- **[FR-6.1] YAML Template Runner**: Done ([core/custom_rules.py](file:///d:/Project/SIH/Argus/core/custom_rules.py))
  - Loads Nuclei-style YAML templates from a file or directory. Supports 5 matcher types: `status`, `word`, `regex`, `size_gt/lt`, `header`. Combinable with `and`/`or` logic.
- **[FR-6.2] Integrated Execution alongside Standard Modules**: Done ([cli/argus_cli.py](file:///d:/Project/SIH/Argus/cli/argus_cli.py))
  - Use `--modules rules --templates <path>` or just `--templates <path>` (auto-enables the rules module). Three ready-to-use example templates ship in `templates/`.
  - Example templates: `templates/exposed_env.yaml`, `templates/debug_endpoint.yaml`, `templates/sql_error.yaml`.

---

### FR-7: Delivery Surfaces

- **[FR-7.1] CLI Scan Engine**: Done ([cli/argus_cli.py](file:///d:/Project/SIH/Argus/cli/argus_cli.py))
  - Full-featured CLI for running single or combined modules, specifying scope, rate limits, and viewing results.

- **[FR-7.1.1] Interactive TUI**: Done ([cli/interactive_cli.py](file:///d:/Project/SIH/Argus/cli/interactive_cli.py), [cli/pixel_agents.py](file:///d:/Project/SIH/Argus/cli/pixel_agents.py))
  - Claude Code-style terminal UI launched by running `python cli/argus_cli.py` with no subcommand (or `interactive`).
  - **Persistent two-column header**: large ASCII ARGUS art on the left, contextual tips panel on the right — shown on every screen clear.
  - **Arrow-key module selector** (`prompt_toolkit`): Up/Down to navigate, Space to toggle `[✓]`, Tab to show inline description of highlighted module, Enter to confirm, Esc to return to main menu.
  - **6-step scan wizard**: target → scope → modules → authorization → advanced options → report settings. Right panel updates contextually at each step.
  - **Pixel-art scan agents** (`cli/pixel_agents.py`): each scan module runs with its own animated ASCII character at 4 FPS via `asyncio` + Rich `Live` display. Characters cycle through 4-frame walking/typing/climbing animations while the scan coroutine runs. Findings stream into the right panel in real time.

    | Module | Agent | Animation |
    |---|---|---|
    | `dir` | Scout | Walks, crouches, peeks at paths |
    | `vhost` | Recon | Binoculars sweeping left/right |
    | `param` | Hacker | Typing at keyboard, injecting payloads |
    | `api` | API Bot | Points at schema, rotates chart |
    | `subdomain` | Spider | Climbs web, drops on DNS results |
    | `rules` | Ruler | Reads scroll, stamps MATCH |

  - **Arrow-key report export**: navigate past scans Up/Down, Enter to export, `a` for all scans, Esc to go back.
  - **Auto-saved reports**: HTML, PDF, and JSON written to output folder automatically after each scan.

- **[FR-7.2] VS Code Extension**: Pending (`vscode-extension/`)
  - Editor extension surfacing inline security diagnostics and AI fix suggestions.

- **[FR-7.3] Chrome Browser Extension**: Pending (`browser-extension/`)
  - Manifest V3 extension for client-side request interception and live response alerts.

- **[FR-7.4] Central Web Dashboard**: Done ([dashboard/app.py](file:///d:/Project/SIH/Argus/dashboard/app.py))
  - Flask web application rendering live findings, severity metrics, detailed request/response evidence, and AI remediation cards.

---

### FR-8 & FR-9 & FR-10: AI Triage, Scoring & Database
- **[FR-8.1] LLM Fix Suggestions**: Done ([core/ai_triage.py](file:///d:/Project/SIH/Argus/core/ai_triage.py))
  - Generates code-level remediation suggestions using Google Gemini API (`gemini-2.5-flash`) or OpenAI API (with offline rule-based fallback).
- **[FR-8.2] ML Prioritization Classifier**: Pending (Stretch Item)
  - Scikit-learn classifier for ordering suspected findings.
- **[FR-9 & FR-10] Vulnerability Scoring & SQLite Storage**: Done ([core/db.py](file:///d:/Project/SIH/Argus/core/db.py))
  - SQLite database storing findings with CVSS-inspired score math (`base_severity * confidence_multiplier`).

---

### FR-11: Reporting Engine
- **[FR-11.1] HTML & PDF Report Export**: Done ([core/report_gen.py](file:///d:/Project/SIH/Argus/core/report_gen.py))
  - Standalone report engine rendering self-contained dark-mode HTML reports (Jinja2) and Windows-native PDF exports (`xhtml2pdf`). Includes executive summary cards, severity distribution charts, evidence pre blocks, and AI remediation guidance.

---

## 3. New Files Added (August 24, 2026)

| File | Description |
|---|---|
| `cli/interactive_cli.py` | Full interactive TUI — Claude Code-style wizard, arrow-key selectors, Live scan display |
| `cli/pixel_agents.py` | Pixel-art ASCII sprite library — 6 named agents, 4-frame animations, Rich markup renderer |

### Key design decisions

- **`prompt_toolkit` for raw keyboard input** — already installed as an InquirerPy dependency. Used directly for `FormattedTextControl` with custom `KeyBindings` for Up/Down/Space/Tab/Enter/Esc without echoing to the terminal.
- **`asyncio.create_task` for concurrent animation** — each scan module's coroutine and the 4 FPS sprite animation task run as separate asyncio tasks, so the animation never blocks the actual network I/O.
- **`Rich Live` for the scan display** — `transient=False` keeps completed module panels visible above the currently running one, giving a scrolling log of agent activity.
- **No `Panel()` for the main menu** — flat indented list with `>` prompt matches the Claude Code aesthetic and avoids the heavy box-drawing that dominated the previous CLI.

---

## 4. What Needs to Be Built Next (Roadmap)

```
[Phase 1 - Complete]             [Phase 2 - Complete]             [Phase 3 - In Progress]
   Auth Gate (FR-0)                 Custom YAML Templates (FR-6)     Interactive TUI (FR-7.1.1) DONE
   Directory Enum (FR-1)            HTML/PDF Report Exporter (FR-11) VS Code Extension (FR-7.2)
   VHost Discovery (FR-2)           Interactive TUI & Pixel Agents   Browser Extension (FR-7.3)
   API Fuzzing (FR-3 & FR-4)                                         ML Prioritizer (FR-8.2)
   Subdomain Enumeration (FR-5)
   Gemini AI Fix Triage (FR-8.1)
   Web Dashboard (FR-7.4)
```

### Next Implementation Priorities
1. **Surfaces**: Implement VS Code Extension (`vscode-extension/`) and Chrome Browser Extension (`browser-extension/`).
2. **ML Prioritizer**: Implement `scikit-learn` finding prioritizer (FR-8.2).
