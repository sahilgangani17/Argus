# Product Requirements Document

## Argus — Comprehensive Web Application Fuzzer
**SIH1750 | Version 1.0 | Status: Draft for Hackathon Build**

---

## 1. Overview

### 1.1 Summary
Argus is an integrated web application security testing tool that automates discovery and vulnerability testing across directories/files, virtual hosts, API endpoints, URL parameters, and subdomains. It is delivered through three surfaces — a CLI engine, a VS Code extension, and a browser extension — that all report into a single web dashboard, with AI-assisted fix suggestions to shorten the gap between "finding" and "fixed."

### 1.2 Problem Statement
Web applications expose hidden attack surface that standard testing misses: undocumented directories, virtual hosts, API endpoints, URL parameters, and subdomains. Teams today stitch together 4–5 disconnected tools (ffuf, gobuster, Amass, Burp, sqlmap) and manually merge results, with no unified view of severity or remediation status, and no feedback loop into the developer's actual workflow.

### 1.3 Goals
- Automate discovery and vulnerability testing across all major web attack surfaces from one tool.
- Deliver findings where developers and testers already work (editor, browser, CLI/CI), not only in a standalone report.
- Produce a prioritized, evidence-backed report with actionable remediation guidance.
- Enforce authorized-use-only scanning by design, not by disclaimer.

### 1.4 Non-Goals
- Not an exploitation framework (no automated RCE/SQLi exploitation, credential dumping, or lateral movement — detection and reporting only).
- Not a WAF or runtime protection product — it finds issues, it does not block traffic in production.
- Not a replacement for manual penetration testing or code review — it is a triage and coverage accelerant.
- Not attempting full reinforcement-learning-driven adaptive fuzzing or decentralized multi-node result validation in v1 — flagged as unproven/unscoped for this build (see §9 Out of Scope).

---

## 2. Target Users & Personas

| Persona | Needs | How Argus Helps |
|---|---|---|
| **Application Developer** | Wants to catch security issues while coding, without context-switching to a separate tool | VS Code extension surfaces findings + AI fix suggestions inline |
| **Security Tester / Ethical Hacker** | Needs fast, comprehensive attack-surface coverage without juggling 5 tools | CLI engine automates recon + fuzzing + reporting in one run |
| **QA / Manual Tester** | Wants to catch client-side issues while exploring the app manually | Browser extension flags suspicious requests/responses live |
| **Engineering Lead / AppSec Owner** | Needs a single view of open findings, severity, and remediation status across the team | Web dashboard aggregates all findings from all surfaces |

---

## 3. User Stories

1. As a developer, I want to see a vulnerability flagged inline in VS Code as I write code, so I can fix it before committing.
2. As a security tester, I want to run one CLI command against an authorized target and get directory, vhost, API, parameter, and subdomain findings in a single report.
3. As a QA tester, I want the browser extension to warn me when a request/response looks suspicious while I click through the app manually.
4. As an AppSec lead, I want a dashboard showing all findings ranked by severity, so I know what to prioritize this sprint.
5. As any user, I want the tool to refuse to scan a target that isn't in my authorized scope file, so I can't accidentally test something I don't own.
6. As a developer, I want an AI-generated fix suggestion attached to a confirmed finding, so I don't have to research the remediation myself.
7. As a security tester, I want to define a custom test case (YAML) for application-specific logic the built-in payloads won't catch.

---

## 4. Functional Requirements

### FR-0: Authorization Gate
- FR-0.1: System must require a signed scope file (`scope.yaml`) listing explicitly authorized domains/IP ranges before any scan starts.
- FR-0.2: System must reject any target hostname not present in the scope file, at the request layer.
- FR-0.3: System must require an explicit confirmation flag (`--i-own-this`) to unlock active modules (parameter fuzzing, vhost brute-force); passive-only modules (e.g., crt.sh lookups) may run without it.
- FR-0.4: System must apply a configurable rate limit (requests/sec) by default on all outbound scan traffic.

### FR-1: Directory & File Enumeration
- FR-1.1: Multi-threaded/async brute-force against target using configurable wordlists (default: SecLists `common.txt`).
- FR-1.2: Automatic extension permutation (`.php`, `.bak`, `.env`, `.git`, `.zip`, configurable list).
- FR-1.3: False-positive filtering via status code, content-length delta, and response-time anomaly detection against a baseline (custom-404) request.

### FR-2: Virtual Host Discovery
- FR-2.1: Fuzz the `Host` header with a subdomain wordlist against a fixed target IP.
- FR-2.2: Detect valid vhosts via response size/title diffing against an unknown-vhost baseline.

### FR-3: API Endpoint Discovery
- FR-3.1: Active pattern-based guessing against common REST/GraphQL path conventions.
- FR-3.2: Passive extraction of endpoint strings from fetched JS files via regex on `fetch()`, `axios.`, `.ajax()` call sites.
- FR-3.3: Auto-detect and parse Swagger/OpenAPI specs at common paths (`/swagger.json`, `/openapi.yaml`, etc.).

### FR-4: Parameter Fuzzing
- FR-4.1: Inject SQLi, XSS, and RCE signature/heuristic payloads into discovered URL parameters.
- FR-4.2: Support payload encoding variants (URL, double-URL, Unicode).
- FR-4.3: Detect findings via differential response analysis, error-based SQLi signatures, and timing-based blind SQLi (delay payloads).
- FR-4.4: All parameter-fuzzing findings must be labeled `confirmed` or `suspected` based on detection method (signature match = confirmed; timing/heuristic only = suspected).

### FR-5: Subdomain Enumeration
- FR-5.1: DNS brute-force using a configurable wordlist, plus zone-transfer attempt.
- FR-5.2: Passive subdomain discovery via certificate transparency logs (crt.sh API).
- FR-5.3: Resolve discovered subdomains, check liveness, and feed live hosts back into FR-1/FR-2 for recursive fuzzing.

### FR-6: Custom Test Cases
- FR-6.1: Accept user-defined YAML/JSON templates specifying a request pattern and an expected vulnerable-response signature.
- FR-6.2: Execute custom test cases alongside standard fuzzing modules in the same run.

### FR-7: Delivery Surfaces
- FR-7.1 (CLI): Full access to all scan modules (FR-1 through FR-6) via command-line flags; suitable for CI/CD invocation.
- FR-7.2 (VS Code Extension): Display findings as inline diagnostics in the editor, scoped to the currently open project's known endpoints; show AI fix suggestion on click.
- FR-7.3 (Browser Extension): Intercept and fuzz client-side requests during manual browsing; flag suspicious responses/injected scripts in a browser action popup.
- FR-7.4: All three surfaces must write findings to the same backend store so the dashboard reflects a unified view regardless of entry point.

### FR-8: AI-Assisted Triage
- FR-8.1: For each `confirmed` finding, generate a fix suggestion via LLM API call (finding type + request/response context as input), returned as plain-language + code-snippet guidance.
- FR-8.2 (stretch): Rank `suspected` findings by a lightweight ML classifier trained on finding features (type, confidence signal, response pattern) to reduce manual review order fatigue.

### FR-9: Vulnerability Scoring
- FR-9.1: Compute `severity_score = base_severity[vuln_type] * confidence_multiplier` for every finding.
- FR-9.2: Default `base_severity` table: RCE 9.0, SQLi 8.5, XSS 6.0, exposed_file 5.0, misconfig 4.0 (configurable).
- FR-9.3: Default `confidence_multiplier`: confirmed 1.0, suspected 0.5.
- FR-9.4: Sort all findings by `severity_score` descending in every report/dashboard view by default.

### FR-10: Web Dashboard
- FR-10.1: List view of all findings with severity, confidence, source surface, and status (open/fixed/false-positive).
- FR-10.2: Chart view of findings-by-severity for at-a-glance summary.
- FR-10.3: Allow manual status change on a finding (mark fixed / false-positive).
- FR-10.4 (stretch): Scan history with diff view against the previous scan of the same target.

### FR-11: Reporting Engine
- FR-11.1: Generate an HTML/PDF report containing, per finding: type, severity score, evidence (request/response pair), and remediation suggestion.
- FR-11.2: Report generation must not require the web dashboard to be running (CLI-standalone report export).

---

## 5. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Performance** | Directory enumeration should sustain ≥50 concurrent requests/sec by default (configurable) without exceeding the rate limit |
| **Reliability** | A single module failure (e.g., DNS timeout) must not crash the overall scan run |
| **Security** | Scope file and any stored credentials must never be logged in plaintext to report output |
| **Usability** | VS Code and browser extension findings must appear within 5 seconds of the relevant scan completing |
| **Portability** | CLI tool must run on Linux and macOS at minimum (Windows via WSL acceptable for v1) |
| **Auditability** | Every request sent by the tool must be logged with timestamp, target, and module of origin |

---

## 6. System Architecture

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
```

### 6.1 Technology Stack

| Layer | Choice |
|---|---|
| Core engine | Python — `asyncio`, `httpx` for high-concurrency requests |
| CLI tool | `argparse`/`click` |
| Web dashboard | Flask (server-rendered) for MVP |
| VS Code extension | TypeScript, VS Code Extension API, local HTTP calls to backend |
| Browser extension | Chrome Extension (Manifest V3, `declarativeNetRequest`/`webRequest` APIs) |
| AI layer | LLM API (Gemini or GPT-4) for fix suggestions; optional scikit-learn classifier for prioritization |
| Storage | SQLite |
| Reporting | Jinja2 → WeasyPrint (PDF), HTML export |

---

## 7. Success Metrics

| Metric | Target (hackathon demo) |
|---|---|
| Attack surface coverage per scan | All 5 categories (dir/file, vhost, API, param, subdomain) exercised in one run |
| False-positive rate on directory enumeration | Visibly reduced vs. raw brute-force (demonstrable via before/after filter toggle) |
| Time from finding to fix-suggestion | < 10 seconds (LLM round-trip) for at least one finding type live in demo |
| Cross-surface consistency | A finding made via CLI appears in the dashboard without manual import |
| Scope enforcement | Attempting to scan an out-of-scope target is demonstrably blocked live |

---

## 8. Build Plan & Prioritization

### 8.1 Core (must-have, fully working for demo)
1. Authorization gate (scope file + confirmation flag)
2. CLI: directory/file enumeration with false-positive filtering
3. CLI: VHost discovery
4. CLI: Parameter fuzzing (SQLi/XSS heuristics)
5. Flask dashboard showing live findings with severity scoring
6. LLM fix-suggestion working end-to-end for at least one finding type (e.g., reflected XSS)

### 8.2 Should-have (build if core finishes early)
- Basic VS Code extension showing findings as inline diagnostics
- Recursive subdomain → vhost/dir feedback loop
- PDF report export

### 8.3 Stretch (roadmap items — explicitly label as not-yet-built in the pitch)
- Browser extension for client-side fuzzing
- Custom test case engine (YAML templates)
- Scan history + diff-against-previous-scan
- ML-based finding prioritization classifier

**Presentation discipline:** every feature claimed in the demo/pitch must be labeled by tier above. Claiming a stretch item as "done" when it isn't is the single biggest credibility risk under judge questioning.

---

## 9. Out of Scope (v1)

- Reinforcement-learning-driven adaptive fuzzing strategies (unproven feasibility within hackathon timeframe; hard to defend methodology live).
- Decentralized/blockchain-style multi-node validation of fuzzing results (adds complexity with no clear v1 benefit; revisit only if there's a concrete threat model requiring it).
- Automated exploitation or remediation deployment (the tool suggests fixes; it does not apply them to production code automatically).
- Mobile application fuzzing.
- Authenticated/session-aware fuzzing flows (v1 assumes unauthenticated or single static token; multi-step login flows are a v2 candidate).

---

## 10. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Tool used against unauthorized targets | Technical authorization gate (FR-0), not just a disclaimer |
| Demo accidentally rate-limited/blocked by target WAF | Default conservative rate limit; demo against a local DVWA/test instance |
| LLM fix suggestions are inaccurate or unsafe if applied blindly | Suggestions are advisory text/snippets only, never auto-applied to code |
| Scope creep across 3 delivery surfaces in a short build window | Explicit tiering in §8; only CLI + dashboard + one AI feature are demo-guaranteed |
| False positives erode trust in findings | FR-1.3 filtering; all findings carry a confidence label (confirmed/suspected) |

---

## 11. Comparison to Existing Tools

| Existing Tool | Key Limitation | Argus's Answer |
|---|---|---|
| OWASP ZAP | No real-time feedback during coding; manual setup for custom test cases | VS Code extension + inline AI fix suggestions |
| Burp Suite | Complex interface for beginners; limited modern framework support | Single unified dashboard, opinionated defaults |
| AFL | Requires significant expertise; not web-native | Web-application-specific modules out of the box |
| Wfuzz | CLI-only, no AI-assisted triage | AI-assisted fix suggestions + severity-ranked dashboard |

---

## 12. Open Questions

1. Which LLM provider/API key management approach for the hackathon demo (rate limits, cost, offline fallback if API is unreachable during judging)?
2. Should the browser extension be scoped to a mocked/stubbed demo if it doesn't reach "should-have" completion, or omitted from the live demo entirely?
3. What is the authorized demo target — a self-hosted DVWA instance is recommended over any live/public site.
