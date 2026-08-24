# Argus — Comprehensive Web Application Security Scanner

> **SIH1750** — An integrated web application security testing engine that automates discovery and vulnerability testing across directories, virtual hosts, API endpoints, parameters, and subdomains — with an interactive Claude Code-style terminal UI, animated pixel-art scan agents, AI-assisted remediation, and PDF/HTML reporting.

---

## Feature Overview

| Module | FR | Status |
|---|---|---|
| Authorization Gate (scope enforcement, rate limiting) | FR-0 | Done |
| Directory & File Enumeration + false-positive filtering | FR-1 | Done |
| Virtual Host Discovery (Host header fuzzing) | FR-2 | Done |
| API Endpoint Discovery (4-phase: spec, JS scrape, OPTIONS, wordlist) | FR-3 | Done |
| Schema-Aware Parameter Fuzzing (SQLi, XSS, IDOR, mass assignment) | FR-4 | Done |
| Subdomain Enumeration (crt.sh CT, AXFR, DNS brute-force) | FR-5 | Done |
| Custom YAML Rule Templates (Nuclei-style engine) | FR-6 | Done |
| CLI Scan Engine (direct subcommands) | FR-7.1 | Done |
| Interactive TUI (Claude Code-style wizard + pixel agents) | FR-7.1.1 | Done |
| Web Dashboard | FR-7.4 | Done |
| AI Fix Suggestions (Gemini / OpenAI / offline fallback) | FR-8.1 | Done |
| CVSS-inspired Severity Scoring + SQLite storage | FR-9/10 | Done |
| HTML & PDF Report Exporter | FR-11 | Done |
| VS Code Extension | FR-7.2 | Roadmap |
| Chrome Browser Extension | FR-7.3 | Roadmap |

---

## Quick Start

### 1. Install dependencies

```bash
python -m venv venv

# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure your scope file

Copy the example and edit it with your authorized target(s).
**Never commit your real `scope.yaml`** — it is gitignored.

```bash
cp scope/scope.example.yaml scope/scope.yaml
```

```yaml
# scope/scope.yaml
authorized_targets:
  - 127.0.0.1
  - localhost
owner: "Your Name"
signed: true
```

### 3. Start a local test target

```bash
python test_target.py
# → http://127.0.0.1:8080
```

Or use DVWA via Docker:

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

---

## Interactive TUI (Recommended)

Run with no arguments to launch the **Claude Code-style interactive terminal UI**:

```bash
python cli/argus_cli.py
# or explicitly:
python cli/argus_cli.py interactive
```

The TUI provides:

- **Persistent two-column header** — large ASCII ARGUS art on the left, contextual tips on the right, shown on every screen
- **Arrow-key module selector** — Up/Down to navigate, Space to toggle `[✓]`, Tab to see a live description of the highlighted module, Enter to confirm, Esc to go back
- **6-step scan wizard** — target → scope → modules → authorization → advanced options → report settings, with the right panel updating for each step
- **Animated pixel-art scan agents** — each module runs with its own character animating at 4 FPS while the task executes:

| Module | Agent | Animation |
|---|---|---|
| `dir` | Scout | Walks, crouches, peeks at paths |
| `vhost` | Recon | Binoculars sweeping left/right |
| `param` | Hacker | Typing at keyboard, injecting payloads |
| `api` | API Bot | Points at schema, rotates chart |
| `subdomain` | Spider | Climbs web, drops on DNS results |
| `rules` | Ruler | Reads scroll, stamps MATCH |

- **Arrow-key report selector** — navigate past scans with Up/Down, press Enter to export, `a` for all scans combined, Esc to return
- **Auto-saved reports** — HTML, PDF, and JSON saved to your configured output folder after every scan

---

## CLI Reference

All commands follow the pattern:

```
python cli/argus_cli.py <command> [options]
```

### `scan` — run any combination of modules

```bash
# Directory enumeration only (no active confirmation needed)
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml --modules dir

# Full active scan: dir + vhost + API + subdomain
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml \
    --modules dir,vhost,api,subdomain \
    --i-own-this

# API fuzzing with a local OpenAPI spec (grey-box mode)
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml --modules api --i-own-this \
    --spec-file path/to/openapi.json

# Custom YAML rule templates (FR-6)
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml --i-own-this \
    --templates templates/

# Parameter fuzzing — auto mode (no --param needed)
# Argus crawls the target HTML for <form> fields and ?param= links
python cli/argus_cli.py scan "http://127.0.0.1:8080/search?q=test" \
    --scope scope/scope.yaml --modules param --i-own-this

# Parameter fuzzing — manual mode (specific param + URL)
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml --modules param --i-own-this \
    --param q --param-url "http://127.0.0.1:8080/search?q=x"

# Passive subdomain scan (no --i-own-this required)
python cli/argus_cli.py scan target.com \
    --scope scope/scope.yaml --modules subdomain

# Subdomain -> directory enumeration feedback loop
python cli/argus_cli.py scan target.com \
    --scope scope/scope.yaml --modules subdomain,dir --i-own-this
```

#### `scan` flags

| Flag | Default | Description |
|---|---|---|
| `--scope` | `scope/scope.yaml` | Authorization scope file (required) |
| `--modules` | `dir` | Comma-separated: `dir` `vhost` `param` `api` `subdomain` `rules` |
| `--i-own-this` | off | Unlocks active modules (`vhost`, `param`, `api`, `subdomain`, `rules`) |
| `--rate` | `15.0` | Max requests per second |
| `--wordlist` | `wordlists/common.txt` | Wordlist for directory enumeration |
| `--templates` | — | Path to YAML rule file or directory (auto-enables `rules` module) |
| `--spec-file` | — | Local `openapi.json` / `.yaml` for grey-box API scanning |
| `--auto-discover` | off | Auto-fetch API routes from target's OpenAPI spec before scanning |
| `--param` | — | Parameter name to fuzz. Optional — if omitted, Argus auto-discovers params from the target HTML |
| `--param-url` | TARGET | Full URL to fuzz. Optional — can embed params directly in TARGET |
| `--root-host` | — | Domain for vhost candidate generation |

---

### `interactive` — launch the TUI wizard

```bash
python cli/argus_cli.py interactive
# equivalent to running with no subcommand
```

---

### `discover` — save discovered API routes to a wordlist

```bash
python cli/argus_cli.py discover http://127.0.0.1:8080 \
    --scope scope/scope.yaml \
    --output wordlists/mytarget.txt
```

---

### `triage` — generate AI fix suggestions

Uses Google Gemini (or OpenAI), with a rule-based offline fallback if no key is set.

```bash
# Set your API key (optional — offline fallback works without it)
export GEMINI_API_KEY="your-key"      # or GOOGLE_API_KEY
export OPENAI_API_KEY="your-key"

# Triage confirmed findings from a specific scan
python cli/argus_cli.py triage --scan <scan-id-prefix>

# Triage all confirmed findings across all scans
python cli/argus_cli.py triage
```

---

### `report` — export HTML or PDF vulnerability report (FR-11)

Reads directly from the SQLite database — **no dashboard required**.

```bash
# List scans to get the ID prefix
python cli/argus_cli.py scans

# HTML report (dark-mode, self-contained, opens in any browser)
python cli/argus_cli.py report --scan <prefix> --format html --output report.html

# PDF report (A4, Windows-native via xhtml2pdf)
python cli/argus_cli.py report --scan <prefix> --format pdf --output report.pdf

# Aggregate report across ALL scans
python cli/argus_cli.py report --format pdf --output full_audit.pdf
```

---

### `findings` / `scans` — inspect the database

```bash
# List findings sorted by severity
python cli/argus_cli.py findings

# Filter by scan and minimum severity score
python cli/argus_cli.py findings --scan <prefix> --min-severity 6.0

# List all recorded scans
python cli/argus_cli.py scans
```

---

## Custom YAML Rule Templates (FR-6)

Define your own HTTP request patterns and response matchers — similar to Nuclei templates.

```yaml
# templates/my_rule.yaml
id: my-custom-check
name: Exposed Admin Panel
description: Checks if /admin returns 200 without authentication
severity: misconfig        # RCE | SQLi | XSS | exposed_file | misconfig
confidence: suspected      # confirmed | suspected

request:
  method: GET
  path: /admin
  headers: {}
  body: null
  params: {}

matchers:
  - type: status
    values: [200]
  - type: word
    values: ["dashboard", "admin panel", "logout"]

matcher_condition: and     # and = ALL must pass | or = ANY is enough (default)
```

**Matcher types:** `status` · `word` · `regex` · `size_gt` · `size_lt` · `header`

Three ready-to-use templates ship in `templates/`:

| Template | Detects |
|---|---|
| `exposed_env.yaml` | Publicly readable `.env` file with credentials |
| `debug_endpoint.yaml` | Spring Actuator, Flask debugtoolbar, Django debug panel |
| `sql_error.yaml` | Error-based SQLi — 20+ DB error signatures (MySQL, Postgres, SQLite, MSSQL, Oracle) |

---

## Web Dashboard

```bash
python dashboard/app.py
# Open http://127.0.0.1:5050
```

Features: severity iris gauge · findings table with evidence · status management (open / fixed / false positive) · AI fix suggestion cards · scan selector.

---

## Project Structure

```
argus/
├── cli/
│   ├── argus_cli.py          CLI: scan, interactive, discover, triage, report, findings, scans
│   ├── interactive_cli.py    Interactive TUI: Claude Code-style wizard, arrow-key selectors
│   └── pixel_agents.py       Pixel-art ASCII agent sprites (Scout, Recon, Hacker, API Bot, Spider, Ruler)
├── core/
│   ├── auth_gate.py          FR-0  Scope enforcement, --i-own-this gate, rate limiter
│   ├── dir_enum.py           FR-1  Async directory/file enumeration + false-positive filter
│   ├── vhost.py              FR-2  Virtual host discovery via Host header fuzzing
│   ├── api_discovery.py      FR-3  4-phase API discovery (spec, JS, OPTIONS, wordlist)
│   ├── param_fuzz.py         FR-4  Schema-aware fuzzing (SQLi, XSS, IDOR, mass assign)
│   ├── subdomain.py          FR-5  crt.sh CT + AXFR + DNS brute-force + liveness check
│   ├── custom_rules.py       FR-6  Nuclei-style YAML rule template engine
│   ├── ai_triage.py          FR-8.1 Gemini/OpenAI fix suggestions + offline fallback
│   ├── db.py                 FR-9/10 SQLite store, CVSS-inspired scoring
│   └── report_gen.py         FR-11 HTML & PDF report exporter (xhtml2pdf)
├── dashboard/
│   ├── app.py                FR-7.4 Flask web dashboard
│   ├── static/style.css
│   └── templates/
├── templates/                FR-6  Bundled YAML rule templates
│   ├── exposed_env.yaml
│   ├── debug_endpoint.yaml
│   └── sql_error.yaml
├── scope/
│   └── scope.example.yaml    Copy → scope.yaml and fill in your targets
├── wordlists/
│   └── common.txt            Default directory enumeration wordlist
├── test_target.py            Local Flask target for testing
├── requirements.txt          All pinned dependencies
├── .gitignore
└── IMPLEMENTATION_STATUS.md  Detailed FR-by-FR progress tracker
```

---

## Severity Scoring

Scores are computed as `base_severity × confidence_multiplier` (CVSS-inspired):

| Vuln Type | Base Score | Confirmed | Suspected |
|---|---|---|---|
| RCE | 9.0 | **9.0** | 4.5 |
| SQLi | 8.5 | **8.5** | 4.25 |
| XSS | 6.0 | **6.0** | 3.0 |
| exposed_file | 5.0 | **5.0** | 2.5 |
| misconfig | 4.0 | **4.0** | 2.0 |

---

## Typical Demo Workflow

```bash
# Option A — Interactive TUI (recommended)
python cli/argus_cli.py
# Follow the wizard: select modules with arrow keys + space,
# watch pixel agents animate during each scan module,
# reports auto-saved when done.

# Option B — Direct CLI
# 1. Run a full scan
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml \
    --modules dir,api,subdomain \
    --templates templates/ \
    --i-own-this

# 2. Generate AI fix suggestions
python cli/argus_cli.py triage --scan <prefix>

# 3. Export PDF report
python cli/argus_cli.py report --scan <prefix> --format pdf --output demo_report.pdf

# 4. Open the dashboard
python dashboard/app.py   # → http://127.0.0.1:5050
```

---

## Roadmap

- **FR-7.2** VS Code Extension — inline diagnostics and AI fix suggestions in the editor
- **FR-7.3** Chrome Browser Extension — live request interception and response flagging during manual browsing
- **FR-8.2** ML-based finding prioritizer (scikit-learn classifier on suspected findings)

See [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for the full FR-by-FR breakdown.
