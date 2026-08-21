# Argus — Implementation Audit & Status Report (SIH1750)

**Date:** August 21, 2026  
**Status:** Core Backend & Fuzzing Pipeline Active | Multi-Surface Expansion Pending

---

## 1. Executive Summary

| Category | Total Requirements | Implemented | Pending | Completion Rate |
|---|---|---|---|---|
| **Core Fuzzing Engines** | 6 | 4 | 2 | **67%** |
| **Authorization & Control** | 4 | 4 | 0 | **100%** |
| **Delivery Surfaces & UI** | 4 | 2 | 2 | **50%** |
| **AI & Scoring Engine** | 3 | 2 | 1 | **67%** |
| **Reporting & Export** | 1 | 0 | 1 | **0%** |
| **Overall Project** | **18** | **12** | **6** | **67%** |

---

## 2. Detailed Requirement Breakdown

### FR-0: Authorization Gate & Control
- **[FR-0.1] Signed Scope File Validation**: ✅ **Implemented** ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Enforces `scope.yaml` loading and allowlist host/IP matching before any requests fire.
- **[FR-0.2] Target Host Rejection**: ✅ **Implemented** ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Hostnames not matching scope rules are immediately blocked at the request layer with `ScopeViolation`.
- **[FR-0.3] Active Scanning Confirmation Flag**: ✅ **Implemented** ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Requires `--i-own-this` CLI flag to unlock active fuzzing modules (vhost, param, api).
- **[FR-0.4] Default Token-Bucket Rate Limiter**: ✅ **Implemented** ([core/auth_gate.py](file:///d:/Project/SIH/Argus/core/auth_gate.py))
  - Configurable async rate limiting (`requests_per_second`, default 15 req/sec).

---

### FR-1: Directory & File Enumeration
- **[FR-1.1] Async Multi-Threaded Brute Force**: ✅ **Implemented** ([core/dir_enum.py](file:///d:/Project/SIH/Argus/core/dir_enum.py))
  - High-concurrency directory enumeration using `httpx` async client and customizable wordlists.
- **[FR-1.2] Automatic Extension Permutations**: ✅ **Implemented** ([core/dir_enum.py](file:///d:/Project/SIH/Argus/core/dir_enum.py))
  - Permutes targets with extensions (`.php`, `.bak`, `.env`, `.git`, `.zip`, etc.).
- **[FR-1.3] False-Positive Filtering (Custom-404 Detection)**: ✅ **Implemented** ([core/dir_enum.py](file:///d:/Project/SIH/Argus/core/dir_enum.py))
  - Establishes baseline responses to filter out soft-404 traps using status code, body size delta, and timing anomalies.

---

### FR-2: Virtual Host (VHost) Discovery
- **[FR-2.1] Host Header Fuzzing**: ✅ **Implemented** ([core/vhost.py](file:///d:/Project/SIH/Argus/core/vhost.py))
  - Fuzzes `Host` headers against target IP using subdomain wordlists.
- **[FR-2.2] Baseline Diff Detection**: ✅ **Implemented** ([core/vhost.py](file:///d:/Project/SIH/Argus/core/vhost.py))
  - Measures response size and page title against baseline invalid-vhost response to identify live virtual hosts.

---

### FR-3 & FR-4: API Endpoint Discovery & Schema-Aware Fuzzing
- **[FR-3.1 - FR-3.3] 4-Phase API Discovery**: ✅ **Implemented** ([core/api_discovery.py](file:///d:/Project/SIH/Argus/core/api_discovery.py))
  - Parses OpenAPI v2/v3 & Swagger specs (`/openapi.json`, `/swagger.json`).
  - Extracts endpoints passively from JS bundles using regex (`fetch`, `axios`, `$.ajax`, template literals).
  - Extracts endpoints from HTML forms and `<a>` links.
  - OPTIONS method probing & REST wordlist brute-forcing.
- **[FR-4.1 - FR-4.4] Targeted Vulnerability Fuzzing**: ✅ **Implemented** ([core/param_fuzz.py](file:///d:/Project/SIH/Argus/core/param_fuzz.py))
  - Fuzzes query parameters, JSON body fields, and HTTP headers.
  - Detects **SQL Injection** (error-based & delay timing), **Reflected XSS**, **IDOR/BOLA**, **Mass Assignment**, **Type Confusion**, and **Header Injection**.
  - Applies encoding variants (raw, URL, double-URL, Unicode) and assigns `confirmed` vs `suspected` labels.

---

### FR-5: Subdomain Enumeration
- **[FR-5.1] Active DNS Brute-Force & Zone Transfer**: ❌ **Pending** (`core/subdomain.py`)
  - Wordlist-based DNS resolution and `AXFR` zone-transfer attempts.
- **[FR-5.2] Passive Certificate Transparency Lookups**: ❌ **Pending** (`core/subdomain.py`)
  - Querying `crt.sh` API for historical certificates.
- **[FR-5.3] Liveness Verification & Recursive Feedback**: ❌ **Pending** (`core/subdomain.py`)
  - Resolving IP addresses, checking HTTP/HTTPS liveness, and feeding live subdomains back into directory & vhost enumeration.

---

### FR-6: Custom Test Cases (YAML Templates)
- **[FR-6.1 - FR-6.2] YAML Template Runner**: ❌ **Pending** (`core/custom_rules.py`)
  - Nuclei-style custom test case execution engine accepting YAML templates for user-defined HTTP request structures and matching criteria.

---

### FR-7: Delivery Surfaces
- **[FR-7.1] CLI Scan Engine**: ✅ **Implemented** ([cli/argus_cli.py](file:///d:/Project/SIH/Argus/cli/argus_cli.py))
  - Full-featured CLI for running single or combined modules, specifying scope, rate limits, and viewing results.
- **[FR-7.2] VS Code Extension**: ❌ **Pending** (`vscode-extension/`)
  - Editor extension surfacing inline security diagnostics and AI fix suggestions.
- **[FR-7.3] Chrome Browser Extension**: ❌ **Pending** (`browser-extension/`)
  - Manifest V3 extension for client-side request interception and live response alerts.
- **[FR-7.4] Central Web Dashboard**: ✅ **Implemented** ([dashboard/app.py](file:///d:/Project/SIH/Argus/dashboard/app.py))
  - Flask web application rendering live findings, severity metrics, detailed request/response evidence, and AI remediation cards.

---

### FR-8 & FR-9 & FR-10: AI Triage, Scoring & Database
- **[FR-8.1] LLM Fix Suggestions**: ✅ **Implemented** ([core/ai_triage.py](file:///d:/Project/SIH/Argus/core/ai_triage.py))
  - Generates code-level remediation suggestions using Gemini/OpenAI API calls (with offline rule-based fallback).
- **[FR-8.2] ML Prioritization Classifier**: ❌ **Pending** (Stretch Item)
  - Scikit-learn classifier for ordering suspected findings.
- **[FR-9 & FR-10] Vulnerability Scoring & SQLite Storage**: ✅ **Implemented** ([core/db.py](file:///d:/Project/SIH/Argus/core/db.py))
  - SQLite database storing findings with CVSS-inspired score math (`base_severity * confidence_multiplier`).

---

### FR-11: Reporting Engine
- **[FR-11.1] HTML & PDF Report Export**: ❌ **Pending** (`core/report_gen.py`)
  - Export engine generating standalone HTML and PDF vulnerability reports complete with executive charts, evidence, and remediation steps.

---

## 3. What Needs to Be Built Next (Roadmap)

```
[Phase 1 - Complete]    [Phase 2 - Current Next Step]    [Phase 3 - Multi-Surface Expansion]
   Auth Gate               Subdomain Enumeration            VS Code Extension
   Directory Enum          Custom YAML Templates            Browser Extension
   VHost Discovery         HTML/PDF Report Exporter         ML Prioritizer
   API Fuzzing
   AI Fix Triage
   Web Dashboard
```

### Next Implementation Priorities:
1. **Module FR-5**: Implement `core/subdomain.py` (crt.sh passive lookup + DNS brute-force + recursive liveness check).
2. **Module FR-6**: Implement `core/custom_rules.py` (YAML test template executor).
3. **Module FR-11**: Implement `core/report_gen.py` (HTML & PDF scan report generation).
4. **Surfaces**: Implement VS Code and Chrome Browser extensions.
