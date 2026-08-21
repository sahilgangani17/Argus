# Argus — Comprehensive Web Application Fuzzer & Security Engine

Argus is an integrated web application security testing engine that automates discovery and vulnerability testing across directories/files, virtual hosts, API endpoints, URL parameters, and subdomains — featuring AI-assisted remediation suggestions.

---

## 1. Quick Setup & Dependencies

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install httpx aiohttp click flask jinja2 pyyaml dnspython
```

---

## 2. Start a Test Target

Argus ships with a local test target (`test_target.py`) that mimics real-world false-positive traps (soft 404s returning HTTP 200) and hidden resources:

```bash
python test_target.py
# serves on http://127.0.0.1:8080
```

Alternatively, run DVWA via Docker:
```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

---

## 3. Configure Authorization Scope (`scope.yaml`)

`scope/scope.yaml` enforces authorized-use-only scanning at the request layer before a single packet is sent.

```yaml
authorized_targets:
  - 127.0.0.1
  - localhost
  - dvwa.local
```

---

## 4. Feature Modules & Usage Guide

### 4.1 Subdomain Enumeration (FR-5)
Discovers hidden subdomains (`admin.target.com`, `api.target.com`) via a 3-phase pipeline:
- **Passive CT Lookup**: Queries Certificate Transparency logs (`crt.sh`) without sending packets to the target.
- **AXFR Zone Transfer**: Attempts DNS zone transfer to catch server misconfigurations.
- **DNS Brute-Force**: High-concurrency async resolution across a built-in 105-word dictionary.
- **HTTP/HTTPS Liveness & Feedback Loop**: Probes live web services and automatically feeds live hosts into directory enumeration.

```bash
# Passive subdomain scan (No --i-own-this needed)
python cli/argus_cli.py scan target.com --scope scope/scope.yaml --modules subdomain

# Full active subdomain scan + DNS brute-force
python cli/argus_cli.py scan target.com --scope scope/scope.yaml --modules subdomain --i-own-this

# Subdomain + directory enumeration feedback loop
python cli/argus_cli.py scan target.com --scope scope/scope.yaml --modules subdomain,dir --i-own-this
```

---

### 4.2 API Endpoint Discovery & Schema-Aware Fuzzing (FR-3 & FR-4)
4-Phase discovery and vulnerability testing engine for REST, GraphQL, and microservice APIs:

```
                              ┌─────────────────────────┐
                              │    Target Base URL      │
                              └────────────┬────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        │                                     │
             [Path A: Spec Available]               [Path B: Spec Blocked / Hidden]
                        │                                     │
         Probe Spec Endpoints (OpenAPI/Swagger)      Passive JS Bundle Extraction (Regex)
                        │                                     │
         Parse Schema (Paths, Verbs, Body)           HTML / Form / Router Link Scraping
                        │                                     │
                        │                            API Path Wordlist Brute-Force
                        │                                     │
                        │                            Parameter Mining (Param Miner)
                        └──────────────────┬──────────────────┘
                                           │
                                           ▼
                            ┌─────────────────────────────┐
                            │ Normalized Endpoint Schema  │
                            │  (Method, Path, Params,     │
                            │   Header, JSON Body)        │
                            └──────────────┬──────────────┘
                                           │
                                           ▼
                            ┌─────────────────────────────┐
                            │ Targeted Vuln Payload       │
                            │ Injection (SQLi, XSS, IDOR, │
                            │ Mass Assign, Type Confusion)│
                            └─────────────────────────────┘
```

```bash
# Auto-discover endpoints and save to wordlist
python cli/argus_cli.py discover http://127.0.0.1:8080 --output wordlists/mytarget.txt

# Full API Discovery & Schema-Aware Fuzzing
python cli/argus_cli.py scan http://127.0.0.1:8080 --scope scope/scope.yaml --modules api --i-own-this

# Grey-Box API Scanning using a local OpenAPI spec file
python cli/argus_cli.py scan http://127.0.0.1:8080 --spec-file path/to/openapi.json --modules api --i-own-this
```

---

### 4.3 Directory & File Enumeration (FR-1) & VHost Fuzzing (FR-2)
```bash
# Directory/file enumeration with false-positive filtering
python cli/argus_cli.py scan http://127.0.0.1:8080 --scope scope/scope.yaml --modules dir

# Multi-module active scan (dir + vhost + api + subdomain)
python cli/argus_cli.py scan http://127.0.0.1:8080 --scope scope/scope.yaml --modules dir,vhost,api,subdomain --i-own-this
```

---

## 5. CLI Command Reference

```bash
# Review findings sorted by severity
python cli/argus_cli.py findings

# View recorded scans
python cli/argus_cli.py scans
```

### CLI `scan` Command Flags
| Flag | Default | Description |
|---|---|---|
| `--scope` | `scope/scope.yaml` | Path to authorization scope file |
| `--modules` | `dir` | Comma-separated: `dir`, `vhost`, `param`, `api`, `subdomain` |
| `--wordlist` | `wordlists/common.txt` | Wordlist path for directory enumeration |
| `--spec-file` | — | Path to a local `openapi.json` file for grey-box API scanning |
| `--auto-discover` | off | Auto-extract routes from OpenAPI spec before scanning |
| `--i-own-this` | off | Required to unlock active modules (`vhost`, `param`, `api`, `subdomain`) |
| `--rate` | `15.0` | Requests per second (rate limit) |
| `--param` | — | Parameter name to fuzz (required for legacy `param` module) |
| `--param-url` | — | Full URL with query param to fuzz |
| `--root-host` | — | Domain for vhost candidate generation |

---

## 6. AI-Assisted Triage (FR-8.1)

Generates code-level remediation suggestions for confirmed findings using **Google Gemini** (or OpenAI / offline fallback).

```bash
# Configure Gemini API Key (Optional)
export GEMINI_API_KEY="your-gemini-api-key"   # Or GOOGLE_API_KEY

# Run AI triage across confirmed findings
python cli/argus_cli.py triage --scan <scan_id_prefix>
# (Omit --scan to triage all confirmed findings across every scan)
```

*Note: If no API key is present or network times out (>10s), Argus automatically uses built-in offline remediation guidance.*

---

## 7. Web Dashboard UI (FR-10)

Launch the central web UI to inspect scan findings, severity metrics (Iris gauge), HTTP request/response evidence, and AI remediation recommendations:

```bash
python dashboard/app.py
# Open http://127.0.0.1:5000 in your browser
```

---

## Project Structure

```
core/auth_gate.py       Authorization gate: scope.yaml validation, --i-own-this, rate limiter (FR-0)
core/dir_enum.py        Directory & file enumeration + false-positive baseline filter (FR-1)
core/vhost.py           Virtual host discovery via Host header fuzzing (FR-2)
core/api_discovery.py   4-Phase API spec parser, JS scraper, and endpoint extractor (FR-3)
core/param_fuzz.py      Schema-aware API & parameter vulnerability fuzzing (FR-4)
core/subdomain.py       Subdomain enumeration: crt.sh, AXFR, DNS brute-force & feedback (FR-5)
core/ai_triage.py       Google Gemini LLM fix suggestion engine & offline fallback (FR-8.1)
core/db.py              SQLite central findings store & CVSS-inspired scoring (FR-9/10)
cli/argus_cli.py        CLI entry point: scan, discover, triage, findings, scans (FR-7.1)
dashboard/              Flask web dashboard UI (FR-10)
scope/scope.yaml        Authorized targets allowlist file
wordlists/              Wordlists for directory and API enumeration
test_target.py          Local Flask app for testing without Docker
IMPLEMENTATION_STATUS.md Audit breakdown of implemented vs. roadmap features
```

---

## Roadmap & Upcoming Features

- **FR-6**: Custom YAML test template executor (Nuclei-style matcher engine).
- **FR-11**: HTML & PDF report exporter (`core/report_gen.py`).
- **FR-7.2**: VS Code Extension (In-editor inline diagnostics & fix suggestions).
- **FR-7.3**: Chrome Browser Extension (Client-side request interception & live alerts).
