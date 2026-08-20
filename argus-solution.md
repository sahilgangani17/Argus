# Argus — Comprehensive Web Application Fuzzer — Final Solution (SIH1750)

*Named for Argus Panoptes, the hundred-eyed giant of Greek myth who watched every direction at once — one tool watching every attack surface simultaneously.*

## Exact Problem

Web applications expose hidden attack surface — undocumented directories, virtual hosts, API endpoints, URL parameters, and subdomains — that standard testing misses. A single versatile tool is needed to automate discovery and vulnerability testing across all these surfaces, then produce a prioritized, evidence-backed report with remediation guidance.

## Why This, Not Just ffuf/Amass/sqlmap/ZAP/Burp

Every individual technique here mirrors a proven, well-documented open-source tool. We are not inventing new detection theory — we are **integrating known-good techniques into one recursive pipeline, delivered where developers already work, with unified reporting and AI-assisted triage**. That integration + delivery-surface + reporting layer is the differentiator, not the fuzzing logic itself.

| Existing Tool | Key Limitation |
|---|---|
| OWASP ZAP | No real-time feedback during coding; manual setup for custom test cases |
| Burp Suite | Complex interface for beginners; limited support for modern frameworks |
| AFL / American Fuzzy Lop | Requires significant expertise; not web-application-native |
| Wfuzz | CLI-only, limited UI; no AI-assisted triage or adaptive prioritization |

Our positioning: same underlying proven techniques as the tools above, but delivered as **one integrated workflow** (editor + CLI + dashboard) with **AI-assisted triage** instead of raw output the user has to manually interpret.

---

## Solution Architecture

Two things happen in parallel: **recursive backend fuzzing** (recon → fuzz → analyze → report) and **multi-surface delivery** (how developers and testers actually touch the tool).

```
Target URL/Domain
        |
        v
[0] Authorization Gate
        |
        v
[1] Recon Engine --> [2] Fuzzing Engines --> [3] Vuln Analyzer (+AI triage) --> [4] Report Generator
        ^                                            |                                |
        |____ recursive feedback (new subdomains) ___|                                v
                                                                                  [5] Log/Store (SQLite)
                                                                                        |
                                                                                        v
                                                                                 [6] Web Dashboard
                                                                                        ^
                        ___________________________________________________________  |
                       |                              |                             |
                [VS Code Extension]           [Browser Extension]              [CLI Tool]
                 in-editor findings          client-side request fuzzing      deep server-side scans
                 + AI fix suggestions          + malicious-JS detection        + custom test cases
```

The recursive loop is central: subdomain discovery → live-host check → feeds back into directory/vhost modules for further fuzzing on newly discovered hosts. The three developer-facing surfaces (VS Code extension, browser extension, CLI) all write to the same backend/database, so the dashboard is a single source of truth regardless of where a finding was made.

---

## 0. Authorization Gate (technical, not just a disclaimer)

Before any scan module fires:

- User must supply a **signed scope file** (`scope.yaml`) listing explicitly authorized targets (domains/IP ranges).
- Tool computes target hostname against an allowlist; anything outside scope is rejected at the request layer, not just warned about.
- A `--i-own-this` style explicit confirmation flag is required to unlock active modules (param fuzzing, vhost brute-force); passive-only modules (crt.sh lookups) can run without it.
- All requests are rate-limited by default (token-bucket limiter, configurable req/sec) to avoid accidental DoS during demos or real use.

This turns "please only test what you own" from a README line into an actual code path — which matters both ethically and for how the project reads to judges.

---

## Module Breakdown

### 1. Directory & File Enumeration
- **Method:** multi-threaded/async brute-force using wordlists (SecLists `common.txt` / `raft-large`).
- **Extension permutation:** automatically tests `.php`, `.bak`, `.env`, `.git`, `.zip` variants.
- **False-positive control:** filters by status code, content-length delta, and response-time anomaly to avoid custom-404 traps.
- **Tech:** Python + `httpx`/`aiohttp` for async requests.

### 2. Virtual Host (VHost) Discovery
- **Method:** fuzz the `Host` header with a subdomain wordlist while keeping the IP constant.
- **Detection:** diff response size/title against the baseline (unknown-vhost) response.

### 3. API Endpoint Discovery
- **Active:** pattern-based guessing (`/api/v1/`, `/graphql`, common REST verbs).
- **Passive:** parse JS files pulled from the site for endpoint strings via regex on `fetch()`, `axios.`, `.ajax()`.
- **Bonus:** auto-detect Swagger/OpenAPI specs at common paths.

### 4. Parameter Fuzzing
- **Payloads:** SQLi, XSS, and known RCE signature/heuristic test patterns injected into URL parameters.
- **Encoding variants:** URL, double-URL, Unicode to bypass naive WAF filters.
- **Detection:** differential response analysis, error-based SQLi signatures, timing-based blind SQLi via delay payloads.
- **Honest framing:** this is detection-only (signature/heuristic), not an exploitation engine like sqlmap — worth stating plainly in the pitch to preempt scrutiny.

### 5. Subdomain Enumeration
- DNS brute-force (wordlist + zone-transfer attempt) combined with passive sources (crt.sh certificate transparency API).
- Resolve → live-host check → feed back into directory/vhost modules for recursive fuzzing.

### 6. Custom Test Cases
- YAML/JSON config format so users define request templates and expected vulnerable-response signatures (similar to Nuclei templates).

### 7. Delivery Surfaces (multi-surface, one backend)
Rather than a CLI-only tool, expose the same engine through three surfaces so it fits naturally into a real dev/test workflow:

- **VS Code Extension** — in-editor findings as the developer writes code; surfaces AI-generated fix suggestions inline (see AI Layer below). This is the highest-leverage addition: it turns the tool from "something testers run after the fact" into "something developers see while coding," which is what actually reduces vulnerabilities shipped to production.
- **Browser Extension** — fuzzes client-side requests as a tester/developer browses the target app; flags suspicious injected scripts or malformed responses live in the browser. Useful for manual exploratory testing sessions, complementing the automated CLI scans.
- **CLI Tool** — the deep, automatable scan engine (everything in modules 1–6 above); this is what would run in CI/CD pipelines.

All three write findings to the same SQLite store, so the **Web Dashboard** (module 9) is a unified view regardless of entry point — no manually merging results from three disconnected tools.

### 8. AI-Assisted Triage (scoped, not oversold)
Two concrete, defensible AI additions — deliberately scoped down from "adaptive reinforcement-learning fuzzer" claims that are hard to demo credibly in a hackathon window:

- **LLM-assisted fix suggestions**: once a finding is confirmed (e.g., reflected XSS in a parameter), send the request/response pair + finding type to an LLM (e.g., Gemini/GPT-4 API) with a constrained prompt to generate a suggested code-level fix (e.g., "add output encoding here," "use parameterized queries"). This is shown inline in the VS Code extension and in the report — it's the single most demo-friendly AI feature because it's easy to show working end-to-end.
- **Lightweight ML prioritization classifier** (optional stretch): a small classifier (e.g., logistic regression / random forest) trained on finding features (vuln type, confidence, response patterns) to help order the queue of suspected findings for human review, reducing analyst fatigue. Keep this modest — it's a ranking aid, not a "predicts vulnerabilities before they exist" claim.

*Deliberately not included:* claims of reinforcement-learning-driven adaptive fuzzing strategies or decentralized/blockchain-style multi-node result validation. Both appeared in other teams' pitches for this same problem statement and sound impressive, but neither is buildable-and-demoable credibly in a 24–36 hour hackathon window, and unless you can explain the training data and validation methodology on the spot, claiming them is a real risk under judge questioning.

### 9. Web Dashboard
- Central hub aggregating findings from all three surfaces.
- Vulnerability list with severity, confidence, and status (open/fixed/false-positive).
- Chart view (findings by severity) for a quick visual summary during the demo.

### 10. Vulnerability Scoring (concrete formula)
Lightweight CVSS-inspired score, not just a label:

```
severity_score = base_severity[vuln_type] * confidence_multiplier

base_severity  = { RCE: 9.0, SQLi: 8.5, XSS: 6.0, exposed_file: 5.0, misconfig: 4.0 }
confidence_multiplier = { confirmed: 1.0, suspected: 0.5 }
```

Findings are sorted by `severity_score` descending in the report — gives judges a defensible, explainable ranking instead of a vague "high/medium/low" label.

### 11. Reporting Engine
- **Output:** HTML/PDF report with finding, evidence (request/response), remediation suggestion, and severity score.
- **Tech:** Jinja2 templates rendered to PDF via WeasyPrint.
- **Stretch:** scan history in SQLite + diff against previous scan (shows new/fixed findings over time — mirrors how OWASP ZAP baseline scans work in CI/CD).

---

## Suggested Technology Stack

| Layer | Choice |
|---|---|
| Core engine | Python — `asyncio`, `httpx` for high-concurrency requests |
| CLI tool | `argparse`/`click` |
| Web dashboard | Flask (server-rendered) for MVP; note React+Tailwind as a post-hackathon upgrade path, not MVP scope |
| VS Code extension | TypeScript, VS Code Extension API, calls backend over local HTTP |
| Browser extension | Chrome Extension (Manifest V3, `declarativeNetRequest`/`webRequest` APIs) for client-side request interception |
| AI layer | LLM API (Gemini or GPT-4) for fix-suggestion generation; optional scikit-learn classifier for finding prioritization |
| Storage | SQLite for scan results and findings history |
| Rate limiting | Token-bucket limiter, configurable requests/sec |
| Reporting | Jinja2 → WeasyPrint (PDF), HTML export |

*Note on scope discipline: a React dashboard, VS Code extension, and browser extension is a lot of surface area for a hackathon. See MVP Scope below for what's actually buildable in 24–36 hours vs. what's a stretch/demo-mockup.*

---

## MVP Scope (24–36 hours)

Given three delivery surfaces are now in the pitch, be explicit about what's real vs. demo-stubbed — judges will ask, and "one polished surface + honest roadmap" beats "three half-working surfaces."

**Core (must-have, fully working):**
1. CLI engine: directory/file enumeration + false-positive filtering
2. VHost discovery
3. Parameter fuzzing (SQLi/XSS heuristics)
4. Authorization gate (scope file + confirmation flag)
5. Flask dashboard showing live findings from the CLI engine, with severity scoring
6. LLM fix-suggestion for at least one finding type (e.g., reflected XSS) — this is the single AI feature to get fully working end-to-end, since it's the most demo-friendly

**Should-have (build if core finishes early):**
- Basic VS Code extension that calls the same backend and shows findings as inline diagnostics (even without full fix-suggestion UI, just surfacing "vulnerability found here" is a strong demo beat)
- Recursive subdomain → vhost/dir feedback loop
- PDF report export

**Stretch / explicitly label as roadmap in the pitch, not working demo:**
- Browser extension for client-side fuzzing
- Custom test case engine (YAML templates)
- Scan history + diff-against-previous-scan
- ML-based finding prioritization classifier

Being upfront in the pitch about which tier each feature is in ("built," "should-have," "roadmap") reads as more credible than implying all three surfaces are equally finished — judges who've seen a lot of decks notice when a "3 tools developed, 70% complete" claim doesn't hold up under a live demo request.

---

## Feasibility Assessment

**High.** Each component mirrors an existing, well-documented open-source tool, so the underlying techniques are proven — the engineering risk is in integration and noise reduction, not in inventing new detection methods. The MVP above is realistic within a hackathon timeframe; the custom-test-case engine and recursive subdomain fuzzing are reasonable stretch goals.

---

## Scope Note (pitch this up front, not as a footnote)

This is explicitly a **defensive / authorized-pentesting tool**. It technically enforces scope via a signed allowlist and requires explicit confirmation before active scanning — this is not just a disclaimer, it's a code-level gate. Build and demo only against systems you own or are authorized to test (e.g., a deliberately vulnerable app like DVWA or a local test server), and lead with this design choice in the pitch — it signals engineering maturity as much as it covers you legally.
