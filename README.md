# Argus — Setup & Run

## 1. Install dependencies
```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install httpx aiohttp click flask jinja2 pyyaml dnspython
```

## 2. Start a target to scan
This repo ships a local test target (`test_target.py`) that mimics DVWA's
false-positive trap (a custom 404 page that returns HTTP 200) plus a few
real hidden resources, so you can validate the tool without Docker/DVWA:
```bash
python test_target.py
# serves on http://127.0.0.1:8080
```
If you have Docker, use real DVWA instead:
```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

## 3. Edit scope.yaml
`scope/scope.yaml` already authorizes `127.0.0.1`, `localhost`, and
`dvwa.local`. Add any other target you're explicitly authorized to test.

## 4. API Discovery & Schema-Aware Fuzzing Pipeline Architecture

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

Argus features a 4-phase API discovery and targeted vulnerability fuzzing pipeline for REST, GraphQL, and microservice backends:

1. **Phase 1 (OpenAPI Specs)**: Probes `/openapi.json`, `/swagger.json` etc., or ingests a local `--spec-file`. Extracts HTTP methods, path params, query params, and JSON body schemas (`application/json`).
2. **Phase 2 (Passive Frontend Scraping & Form Mining)**: Downloads client-side JS bundles (`app.js`), parses HTML `<form>` tags, and performs parameter mining (`?id=`, `?search=`).
3. **Phase 3 (OPTIONS Method Probing)**: Probes discovered endpoints with `OPTIONS` to read `Allow:` headers and determine real HTTP verbs.
4. **Phase 4 (API Wordlist Brute-Force)**: Fallback brute-forcing using common API conventions (`/api/v1/users`, `/health`, `/graphql`).

```bash
# Auto-discover endpoints and save to wordlist
python cli/argus_cli.py discover http://127.0.0.1:8000 --output wordlists/mytarget.txt

# Full Schema-Aware API Discovery & Fuzzing (SQLi, XSS, IDOR, Mass Assignment, Type Confusion)
python cli/argus_cli.py scan http://127.0.0.1:8000 --scope scope/scope.yaml --modules api --i-own-this

# Scan target when live OpenAPI spec is hidden (Grey-Box mode with local spec file)
python cli/argus_cli.py scan http://127.0.0.1:8000 --spec-file path/to/openapi.json --modules api --i-own-this
```

## 5. Run scans via the CLI

> **Windows PowerShell note:** omit the `PYTHONPATH=.` prefix — it is not needed on Windows.

```bash
# Passive only (directory/file enumeration using default wordlist)
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml --modules dir

# Full active run: dir + vhost + api fuzzing
python cli/argus_cli.py scan http://127.0.0.1:8000 \
    --scope scope/scope.yaml --modules dir,vhost,api \
    --i-own-this --rate 20

# Single parameter fuzzing (Legacy mode)
python cli/argus_cli.py scan http://127.0.0.1:8080 \
    --scope scope/scope.yaml --modules param \
    --i-own-this --param q --param-url "http://127.0.0.1:8080/search?q=x"

# List findings / scans
python cli/argus_cli.py findings
python cli/argus_cli.py scans
```

### scan command flags
| Flag | Default | Description |
|---|---|---|
| `--scope` | `scope/scope.yaml` | Path to authorization scope file |
| `--modules` | `dir` | Comma-separated: `dir`, `vhost`, `param`, `api` |
| `--wordlist` | `wordlists/common.txt` | Wordlist path for directory enumeration |
| `--spec-file` | — | Path to a local `openapi.json` file for grey-box API scanning |
| `--auto-discover` | off | Auto-extract routes from OpenAPI spec before scanning |
| `--i-own-this` | off | Required to unlock active modules (`vhost`, `param`, `api`) |
| `--rate` | `15.0` | Requests per second (rate limit) |
| `--param` | — | Parameter name to fuzz (required for legacy `param` module) |
| `--param-url` | — | Full URL with query param to fuzz |
| `--root-host` | — | Domain for vhost candidate generation |

## 6. Generate AI fix suggestions
```bash
# Configure a provider (optional — without a key it uses built-in offline
# fallback guidance instead, so the feature never breaks mid-demo)
export ANTHROPIC_API_KEY=sk-ant-...        # or OPENAI_API_KEY, with ARGUS_LLM_PROVIDER=openai

python cli/argus_cli.py triage --scan <scan_id_prefix>
# omit --scan to triage all confirmed findings across every scan
```

## 7. View the dashboard
```bash
python dashboard/app.py
# open http://127.0.0.1:5050
```
It reads live from the same `argus.db` SQLite file the CLI writes to —
run a scan, refresh the dashboard, findings appear with no manual import.

## Project layout
```
core/db.py              SQLite schema + severity scoring (FR-9)
core/auth_gate.py       Authorization gate: scope.yaml, --i-own-this, rate limiter (FR-0)
core/dir_enum.py        Directory/file enumeration + false-positive filtering (FR-1)
core/vhost.py           VHost discovery (FR-2, active module)
core/param_fuzz.py      Schema-aware API & single-parameter fuzzing (FR-4, active module)
core/ai_triage.py       LLM fix-suggestion generation + offline fallback (FR-8.1)
core/api_discovery.py   4-phase API route & schema extractor (FR-3)
cli/argus_cli.py        CLI entry point: scan, discover, triage, findings, scans (FR-7.1)
dashboard/              Flask web dashboard (FR-10)
scope/scope.yaml        Authorized-targets allowlist
wordlists/              Wordlists for directory enumeration
  common.txt            Generic web paths (admin, .env, .git, backup, etc.)
  talk2tables.txt       Auto-generated by 'discover' command (OpenAPI routes)
test_target.py          Local Flask app for testing without Docker/DVWA
```

## Not yet built
Subdomain enumeration (FR-5), reporting engine (FR-11), VS Code extension,
browser extension. See `argus-prd.md` / `argus-solution.md` for the full
spec and build-tier priorities.
