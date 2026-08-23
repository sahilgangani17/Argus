"""
Argus — HTML & PDF Report Generator (FR-11)

Generates a standalone, self-contained vulnerability report from the SQLite
database. The report does not require the web dashboard to be running — it
reads directly from argus.db and writes to the output file specified by the
caller.

Outputs:
  - HTML  : single self-contained file (all CSS inlined, no external deps)
  - PDF   : via xhtml2pdf (pure Python, works on Windows without GTK/pango)

Usage (from CLI):
  python cli/argus_cli.py report --scan <prefix> --format html --output report.html
  python cli/argus_cli.py report --scan <prefix> --format pdf  --output report.pdf
  python cli/argus_cli.py report --format html   # all scans, stdout HTML
"""

import datetime
import json
import math
import os
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, BaseLoader

from core import db

# ---------------------------------------------------------------------------
# Severity colour palette (matches dashboard/app.py)
# ---------------------------------------------------------------------------

VULN_TYPE_ORDER = ["RCE", "SQLi", "XSS", "exposed_file", "misconfig"]

VULN_TYPE_COLOR: Dict[str, str] = {
    "RCE":          "#D0454F",
    "SQLi":         "#E0674F",
    "XSS":          "#E8A33D",
    "exposed_file": "#D4B14A",
    "misconfig":    "#6B93B0",
}


# ---------------------------------------------------------------------------
# Template — all CSS is inlined so the HTML file is fully self-contained
# ---------------------------------------------------------------------------

_REPORT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Security Report — {{ meta.target }}</title>
<style>
/* ── Reset & base ─────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:           #0B0E11;
  --surface:      #12161C;
  --border:       #232933;
  --text:         #E7EAEE;
  --muted:        #8993A3;
  --amber:        #E8A33D;
  --teal:         #3FA9A0;
  --red:          #D0454F;
  --orange:       #E0674F;
  --blue:         #6B93B0;
  --font-display: 'Space Grotesk', system-ui, sans-serif;
  --font-body:    'Inter', system-ui, sans-serif;
  --font-mono:    'JetBrains Mono', 'Fira Mono', monospace;
}

@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

html { background: var(--bg); color: var(--text); font-family: var(--font-body); font-size: 14px; line-height: 1.6; }
body { max-width: 1100px; margin: 0 auto; padding: 48px 32px 80px; }

a { color: var(--amber); text-decoration: none; }

/* ── Cover page ────────────────────────────────────────────────────── */
.cover {
  min-height: 220px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 48px;
  padding-bottom: 40px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-eye { width: 28px; height: 28px; }

.brand-name {
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 22px;
  letter-spacing: 0.06em;
  color: var(--text);
}

.brand-sub {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted);
  margin-left: 4px;
}

.cover-title {
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 34px;
  line-height: 1.2;
  color: var(--text);
}

.cover-title span { color: var(--amber); }

.cover-meta {
  display: flex;
  gap: 36px;
  flex-wrap: wrap;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted);
}

.cover-meta strong { color: var(--text); font-weight: 500; }

/* ── Executive summary ─────────────────────────────────────────────── */
.exec-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 48px;
}

.exec-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 18px;
}

.exec-card .card-val {
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 36px;
  line-height: 1;
  margin-bottom: 6px;
}

.exec-card .card-lbl {
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--muted);
}

.card-critical .card-val { color: var(--red); }
.card-high     .card-val { color: var(--orange); }
.card-medium   .card-val { color: var(--amber); }
.card-low      .card-val { color: var(--blue); }
.card-total    .card-val { color: var(--teal); }

/* ── Severity bar chart ────────────────────────────────────────────── */
.chart-section { margin-bottom: 48px; }

.section-title {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin-bottom: 18px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

.bar-chart { display: flex; flex-direction: column; gap: 10px; }

.bar-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-family: var(--font-mono);
  font-size: 12px;
}

.bar-label { width: 100px; color: var(--text); text-align: right; flex-shrink: 0; }
.bar-track { flex: 1; background: var(--border); border-radius: 4px; height: 10px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 4px; min-width: 4px; }
.bar-count { width: 28px; color: var(--muted); text-align: right; flex-shrink: 0; }

/* ── Finding cards ─────────────────────────────────────────────────── */
.findings-section { margin-bottom: 48px; }

.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 20px;
  overflow: hidden;
}

.finding-header {
  display: flex;
  align-items: flex-start;
  gap: 16px;
  padding: 18px 20px;
  border-bottom: 1px solid var(--border);
}

.sev-badge {
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 16px;
  border: 2px solid;
  border-radius: 6px;
  padding: 4px 10px;
  flex-shrink: 0;
  line-height: 1.4;
}

.finding-meta { flex: 1; min-width: 0; }

.finding-type {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 16px;
  margin-bottom: 4px;
}

.finding-url {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.finding-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

.tag {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 3px 8px;
  border-radius: 100px;
  letter-spacing: 0.04em;
}

.tag-confidence-confirmed { background: #3FA9A01A; color: var(--teal); border: 1px solid #3FA9A033; }
.tag-confidence-suspected { background: #8993A31A; color: var(--muted); border: 1px solid #8993A333; }
.tag-module  { background: #E8A33D11; color: var(--amber); border: 1px solid #E8A33D33; }
.tag-status-open          { background: #D0454F11; color: var(--red);    border: 1px solid #D0454F33; }
.tag-status-fixed         { background: #3FA9A011; color: var(--teal);   border: 1px solid #3FA9A033; }
.tag-status-false_positive{ background: #8993A311; color: var(--muted);  border: 1px solid #8993A333; }

.finding-body { padding: 18px 20px; display: flex; flex-direction: column; gap: 14px; }

.finding-desc {
  font-size: 13px;
  color: var(--text);
  line-height: 1.65;
}

.evidence-block { display: flex; flex-direction: column; gap: 6px; }

.evidence-label {
  font-family: var(--font-mono);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
}

.evidence-pre {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.55;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-all;
  overflow-wrap: break-word;
  max-height: 220px;
  overflow-y: auto;
}

.fix-block {
  border-left: 3px solid var(--amber);
  padding: 12px 14px;
  background: #E8A33D08;
  border-radius: 0 6px 6px 0;
}

.fix-label {
  font-family: var(--font-mono);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--amber);
  margin-bottom: 8px;
}

.fix-text {
  font-size: 13px;
  color: var(--text);
  line-height: 1.65;
  white-space: pre-line;
}

/* ── Footer ─────────────────────────────────────────────────────────── */
.report-footer {
  border-top: 1px solid var(--border);
  padding-top: 20px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--muted);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}

/* ── Print styles ────────────────────────────────────────────────────── */
@media print {
  body { background: white; color: #111; padding: 0; }
  :root {
    --bg: #ffffff; --surface: #f5f5f5; --border: #e0e0e0;
    --text: #111111; --muted: #666666;
  }
  .finding-card { break-inside: avoid; }
  .evidence-pre { max-height: none; overflow: visible; }
}
</style>
</head>
<body>

<!-- ── Cover ──────────────────────────────────────────────────────────── -->
<div class="cover">
  <div class="brand">
    <svg class="brand-eye" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
      <ellipse cx="16" cy="16" rx="14" ry="8" stroke="#E8A33D" stroke-width="1.6"/>
      <circle cx="16" cy="16" r="4.5" fill="#E8A33D"/>
    </svg>
    <span class="brand-name">ARGUS</span>
    <span class="brand-sub">security scanner</span>
  </div>

  <h1 class="cover-title">
    Vulnerability Report<br>
    <span>{{ meta.target }}</span>
  </h1>

  <div class="cover-meta">
    <div><strong>Scan ID</strong>&nbsp;&nbsp;{{ meta.scan_id }}</div>
    <div><strong>Status</strong>&nbsp;&nbsp;{{ meta.scan_status }}</div>
    <div><strong>Started</strong>&nbsp;&nbsp;{{ meta.started_at }}</div>
    {% if meta.finished_at %}<div><strong>Finished</strong>&nbsp;&nbsp;{{ meta.finished_at }}</div>{% endif %}
    <div><strong>Generated</strong>&nbsp;&nbsp;{{ meta.generated_at }}</div>
    {% if meta.scope_file %}<div><strong>Scope file</strong>&nbsp;&nbsp;{{ meta.scope_file }}</div>{% endif %}
  </div>
</div>

<!-- ── Executive summary ───────────────────────────────────────────────── -->
<section>
  <h2 class="section-title">Executive Summary</h2>
  <div class="exec-grid">
    <div class="exec-card card-total">
      <div class="card-val">{{ summary.total }}</div>
      <div class="card-lbl">Total Findings</div>
    </div>
    <div class="exec-card card-critical">
      <div class="card-val">{{ summary.critical }}</div>
      <div class="card-lbl">Critical ≥ 8.0</div>
    </div>
    <div class="exec-card card-high">
      <div class="card-val">{{ summary.high }}</div>
      <div class="card-lbl">High 6.0–7.9</div>
    </div>
    <div class="exec-card card-medium">
      <div class="card-val">{{ summary.medium }}</div>
      <div class="card-lbl">Medium 4.0–5.9</div>
    </div>
    <div class="exec-card card-low">
      <div class="card-val">{{ summary.low }}</div>
      <div class="card-lbl">Low &lt; 4.0</div>
    </div>
    <div class="exec-card">
      <div class="card-val" style="color: var(--teal)">{{ summary.confirmed }}</div>
      <div class="card-lbl">Confirmed</div>
    </div>
    <div class="exec-card">
      <div class="card-val" style="color: var(--muted)">{{ summary.suspected }}</div>
      <div class="card-lbl">Suspected</div>
    </div>
    <div class="exec-card">
      <div class="card-val" style="color: var(--teal)">{{ summary.fixed }}</div>
      <div class="card-lbl">Fixed</div>
    </div>
  </div>
</section>

<!-- ── Severity distribution bar chart ─────────────────────────────────── -->
<section class="chart-section">
  <h2 class="section-title">Severity Distribution by Type</h2>
  <div class="bar-chart">
    {% for row in chart_rows %}
    <div class="bar-row">
      <span class="bar-label">{{ row.label }}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width:{{ row.pct }}%; background:{{ row.color }}"></div>
      </div>
      <span class="bar-count">{{ row.count }}</span>
    </div>
    {% endfor %}
  </div>
</section>

<!-- ── Findings ─────────────────────────────────────────────────────────── -->
<section class="findings-section">
  <h2 class="section-title">Findings ({{ findings|length }}, sorted by severity)</h2>

  {% if not findings %}
  <p style="color:var(--muted); font-family:var(--font-mono); font-size:13px;">No findings recorded for this scan.</p>
  {% endif %}

  {% for f in findings %}
  <div class="finding-card" id="finding-{{ loop.index }}">

    <div class="finding-header">
      <div class="sev-badge" style="border-color:{{ f.color }}; color:{{ f.color }}">
        {{ "%.1f"|format(f.severity_score) }}
      </div>
      <div class="finding-meta">
        <div class="finding-type">{{ f.vuln_type }}</div>
        <div class="finding-url" title="{{ f.url }}">{{ f.url or '—' }}</div>
        <div class="finding-tags">
          <span class="tag tag-confidence-{{ f.confidence }}">{{ f.confidence }}</span>
          <span class="tag tag-module">{{ f.module }}</span>
          {% if f.parameter %}<span class="tag tag-module">param: {{ f.parameter }}</span>{% endif %}
          <span class="tag tag-status-{{ f.status }}">{{ f.status }}</span>
        </div>
      </div>
    </div>

    <div class="finding-body">
      {% if f.description %}
      <p class="finding-desc">{{ f.description }}</p>
      {% endif %}

      {% if f.request_evidence %}
      <div class="evidence-block">
        <div class="evidence-label">Request Evidence</div>
        <pre class="evidence-pre">{{ f.request_evidence }}</pre>
      </div>
      {% endif %}

      {% if f.response_evidence %}
      <div class="evidence-block">
        <div class="evidence-label">Response Evidence</div>
        <pre class="evidence-pre">{{ f.response_evidence }}</pre>
      </div>
      {% endif %}

      {% if f.fix_suggestion %}
      <div class="fix-block">
        <div class="fix-label">&#9889; AI Fix Suggestion</div>
        <div class="fix-text">{{ f.fix_suggestion }}</div>
      </div>
      {% endif %}
    </div>

  </div>
  {% endfor %}
</section>

<!-- ── Footer ─────────────────────────────────────────────────────────── -->
<footer class="report-footer">
  <span>Generated by Argus Security Scanner — {{ meta.generated_at }}</span>
  <span>Target: {{ meta.target }} &nbsp;|&nbsp; {{ findings|length }} finding(s)</span>
</footer>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------------

def _color_for(finding: dict) -> str:
    return VULN_TYPE_COLOR.get(finding.get("vuln_type", ""), "#6B93B0")


def _ts(epoch: Optional[float]) -> str:
    if not epoch:
        return "—"
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def _build_context(scan: dict, findings: List[dict]) -> dict:
    # -- meta
    meta = {
        "scan_id":      scan["scan_id"],
        "target":       scan["target"],
        "scan_status":  scan.get("status", "unknown"),
        "started_at":   _ts(scan.get("started_at")),
        "finished_at":  _ts(scan.get("finished_at")),
        "scope_file":   scan.get("scope_file"),
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # -- summary
    total = len(findings)
    summary = {
        "total":     total,
        "critical":  sum(1 for f in findings if f["severity_score"] >= 8.0),
        "high":      sum(1 for f in findings if 6.0 <= f["severity_score"] < 8.0),
        "medium":    sum(1 for f in findings if 4.0 <= f["severity_score"] < 6.0),
        "low":       sum(1 for f in findings if f["severity_score"] < 4.0),
        "confirmed": sum(1 for f in findings if f["confidence"] == "confirmed"),
        "suspected": sum(1 for f in findings if f["confidence"] == "suspected"),
        "fixed":     sum(1 for f in findings if f["status"] == "fixed"),
    }

    # -- bar chart rows
    counts_by_type = {vt: sum(1 for f in findings if f["vuln_type"] == vt)
                      for vt in VULN_TYPE_ORDER}
    max_count = max(counts_by_type.values(), default=1) or 1
    chart_rows = [
        {
            "label": vt,
            "count": counts_by_type[vt],
            "pct":   round(counts_by_type[vt] / max_count * 100, 1),
            "color": VULN_TYPE_COLOR[vt],
        }
        for vt in VULN_TYPE_ORDER
    ]

    # -- enrich findings
    enriched = [
        {**f, "color": _color_for(f)}
        for f in findings
    ]

    return {
        "meta":       meta,
        "summary":    summary,
        "chart_rows": chart_rows,
        "findings":   enriched,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_html(scan_id: Optional[str] = None) -> str:
    """
    Render a full standalone HTML report string.

    If scan_id is None, aggregates all scans (useful for a full-project dump).
    Raises ValueError if no matching scan exists.
    """
    db.init_db()
    all_scans = db.get_scans()

    if scan_id:
        matches = [s for s in all_scans if s["scan_id"] == scan_id]
        if not matches:
            raise ValueError(f"Scan '{scan_id}' not found in database.")
        scan = matches[0]
        findings = db.get_findings(scan_id=scan_id, order_by_severity=True)
    else:
        # Aggregate: use a synthetic scan record
        scan = {
            "scan_id":     "all",
            "target":      "All targets",
            "status":      "aggregated",
            "started_at":  min((s["started_at"] for s in all_scans), default=None),
            "finished_at": max((s.get("finished_at") or 0 for s in all_scans), default=None),
            "scope_file":  None,
        }
        findings = db.get_findings(order_by_severity=True)

    ctx = _build_context(scan, findings)

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_REPORT_HTML)
    return tmpl.render(**ctx)


def export_html(output_path: str, scan_id: Optional[str] = None) -> None:
    """Write a self-contained HTML report to output_path."""
    html = render_html(scan_id=scan_id)
    Path(output_path).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# PDF-safe HTML template (simplified CSS for xhtml2pdf's ReportLab renderer)
# ---------------------------------------------------------------------------

_PDF_HTML = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Argus Report — {{ meta.target }}</title>
<style>
  @page { size: A4; margin: 2cm 2cm 2cm 2cm; }
  body  { font-family: Helvetica, Arial, sans-serif; font-size: 10pt; color: #1a1a1a; }
  h1    { font-size: 20pt; color: #1a1a1a; margin-bottom: 4pt; }
  h2    { font-size: 12pt; color: #444; text-transform: uppercase;
          letter-spacing: 1pt; border-bottom: 1pt solid #ccc;
          padding-bottom: 3pt; margin-top: 18pt; margin-bottom: 8pt; }
  h3    { font-size: 10pt; margin: 0 0 4pt 0; color: #222; }
  p     { margin: 0 0 6pt 0; }
  pre   { font-family: Courier, monospace; font-size: 7.5pt; background: #f4f4f4;
          border: 0.5pt solid #ccc; padding: 5pt; white-space: pre-wrap;
          word-wrap: break-word; margin: 4pt 0; }
  table { width: 100%; border-collapse: collapse; font-size: 9pt; margin-bottom: 12pt; }
  th    { background: #e8e8e8; text-align: left; padding: 4pt 6pt;
          border: 0.5pt solid #bbb; font-size: 8pt; text-transform: uppercase; }
  td    { padding: 4pt 6pt; border: 0.5pt solid #ddd; vertical-align: top; }
  .cover   { margin-bottom: 18pt; }
  .meta-tbl td { border: none; padding: 2pt 8pt 2pt 0; font-size: 9pt; }
  .meta-tbl td:first-child { color: #888; width: 90pt; }
  .card    { border: 0.5pt solid #ccc; padding: 8pt; margin-bottom: 10pt; }
  .card-hdr{ background: #f0f0f0; padding: 6pt 8pt; margin: -8pt -8pt 8pt -8pt;
             display: block; }
  .sev     { font-weight: bold; font-size: 11pt; }
  .sev-critical { color: #c0392b; }
  .sev-high     { color: #e67e22; }
  .sev-medium   { color: #f39c12; }
  .sev-low      { color: #2980b9; }
  .tag     { background: #eee; padding: 1pt 4pt; font-size: 7pt; margin-right: 3pt; }
  .fix     { background: #fffbf0; border-left: 3pt solid #e8a33d;
             padding: 5pt 8pt; margin-top: 6pt; font-size: 9pt; }
  .fix-lbl { color: #b87c1d; font-weight: bold; font-size: 7.5pt;
             text-transform: uppercase; display: block; margin-bottom: 3pt; }
  .summ-grid { width: 100%; margin-bottom: 14pt; }
  .summ-grid td { width: 12.5%; text-align: center; border: 0.5pt solid #ddd;
                  padding: 6pt 4pt; }
  .summ-val { font-size: 22pt; font-weight: bold; display: block; }
  .summ-lbl { font-size: 7pt; color: #888; text-transform: uppercase; display: block; }
  .bar-row  { margin-bottom: 5pt; font-size: 8.5pt; }
  .bar-label{ display: inline-block; width: 80pt; text-align: right;
              padding-right: 6pt; color: #444; }
  .bar-count{ color: #888; padding-left: 5pt; }
  page-break { page-break-before: always; }
</style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <h1>Argus Vulnerability Report</h1>
  <p style="font-size:13pt; color:#555">{{ meta.target }}</p>
  <table class="meta-tbl"><tbody>
    <tr><td>Scan ID</td><td>{{ meta.scan_id }}</td></tr>
    <tr><td>Status</td><td>{{ meta.scan_status }}</td></tr>
    <tr><td>Started</td><td>{{ meta.started_at }}</td></tr>
    {% if meta.finished_at != '\u2014' %}<tr><td>Finished</td><td>{{ meta.finished_at }}</td></tr>{% endif %}
    <tr><td>Generated</td><td>{{ meta.generated_at }}</td></tr>
    {% if meta.scope_file %}<tr><td>Scope file</td><td>{{ meta.scope_file }}</td></tr>{% endif %}
  </tbody></table>
</div>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<table class="summ-grid"><tr>
  <td><span class="summ-val" style="color:#2ecc71">{{ summary.total }}</span><span class="summ-lbl">Total</span></td>
  <td><span class="summ-val" style="color:#c0392b">{{ summary.critical }}</span><span class="summ-lbl">Critical &#8805;8</span></td>
  <td><span class="summ-val" style="color:#e67e22">{{ summary.high }}</span><span class="summ-lbl">High 6-8</span></td>
  <td><span class="summ-val" style="color:#f39c12">{{ summary.medium }}</span><span class="summ-lbl">Medium 4-6</span></td>
  <td><span class="summ-val" style="color:#2980b9">{{ summary.low }}</span><span class="summ-lbl">Low &lt;4</span></td>
  <td><span class="summ-val" style="color:#16a085">{{ summary.confirmed }}</span><span class="summ-lbl">Confirmed</span></td>
  <td><span class="summ-val" style="color:#7f8c8d">{{ summary.suspected }}</span><span class="summ-lbl">Suspected</span></td>
  <td><span class="summ-val" style="color:#27ae60">{{ summary.fixed }}</span><span class="summ-lbl">Fixed</span></td>
</tr></table>

<!-- Severity breakdown -->
<h2>Severity Distribution by Type</h2>
<table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>
{% for row in chart_rows %}
<tr><td>{{ row.label }}</td><td>{{ row.count }}</td></tr>
{% endfor %}
</tbody></table>

<!-- Findings -->
<h2>Findings ({{ findings|length }}, sorted by severity)</h2>
{% if not findings %}
<p>No findings recorded for this scan.</p>
{% endif %}
{% for f in findings %}
<div class="card">
  <span class="card-hdr">
    {% if f.severity_score >= 8.0 %}
    <span class="sev sev-critical">{{ "%.1f"|format(f.severity_score) }}</span>
    {% elif f.severity_score >= 6.0 %}
    <span class="sev sev-high">{{ "%.1f"|format(f.severity_score) }}</span>
    {% elif f.severity_score >= 4.0 %}
    <span class="sev sev-medium">{{ "%.1f"|format(f.severity_score) }}</span>
    {% else %}
    <span class="sev sev-low">{{ "%.1f"|format(f.severity_score) }}</span>
    {% endif %}
    &nbsp;&nbsp;<strong>{{ f.vuln_type }}</strong>
    &nbsp;&nbsp;<span style="font-size:8.5pt; color:#555">{{ f.url or '' }}</span>
  </span>

  <span class="tag">{{ f.confidence }}</span>
  <span class="tag">{{ f.module }}</span>
  {% if f.parameter %}<span class="tag">param: {{ f.parameter }}</span>{% endif %}
  <span class="tag">{{ f.status }}</span>

  {% if f.description %}<p style="margin-top:6pt">{{ f.description }}</p>{% endif %}

  {% if f.request_evidence %}
  <p style="font-size:8pt; color:#888; margin-top:6pt; margin-bottom:2pt;">REQUEST EVIDENCE</p>
  <pre>{{ f.request_evidence }}</pre>
  {% endif %}

  {% if f.response_evidence %}
  <p style="font-size:8pt; color:#888; margin-bottom:2pt;">RESPONSE EVIDENCE</p>
  <pre>{{ f.response_evidence }}</pre>
  {% endif %}

  {% if f.fix_suggestion %}
  <div class="fix">
    <span class="fix-lbl">AI Fix Suggestion</span>
    {{ f.fix_suggestion }}
  </div>
  {% endif %}
</div>
{% endfor %}

<p style="font-size:8pt; color:#aaa; margin-top:24pt; border-top:0.5pt solid #ccc; padding-top:6pt">
  Generated by Argus Security Scanner &mdash; {{ meta.generated_at }}
</p>
</body>
</html>"""


def _render_pdf_html(scan_id: Optional[str] = None) -> str:
    """Render a PDF-optimised (xhtml2pdf-compatible) HTML string."""
    db.init_db()
    all_scans = db.get_scans()

    if scan_id:
        matches = [s for s in all_scans if s["scan_id"] == scan_id]
        if not matches:
            raise ValueError(f"Scan '{scan_id}' not found in database.")
        scan = matches[0]
        findings = db.get_findings(scan_id=scan_id, order_by_severity=True)
    else:
        scan = {
            "scan_id":     "all",
            "target":      "All targets",
            "status":      "aggregated",
            "started_at":  min((s["started_at"] for s in all_scans), default=None),
            "finished_at": max((s.get("finished_at") or 0 for s in all_scans), default=None),
            "scope_file":  None,
        }
        findings = db.get_findings(order_by_severity=True)

    ctx = _build_context(scan, findings)
    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_PDF_HTML)
    return tmpl.render(**ctx)


def export_pdf(output_path: str, scan_id: Optional[str] = None) -> None:
    """
    Write a PDF report to output_path using xhtml2pdf (pure Python, Windows-safe).

    Raises ImportError with a helpful message if xhtml2pdf is not installed.
    """
    try:
        from xhtml2pdf import pisa
    except ImportError as exc:
        raise ImportError(
            "xhtml2pdf is required for PDF export. Install it with:\n"
            "  pip install xhtml2pdf"
        ) from exc

    html = _render_pdf_html(scan_id=scan_id)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(out, "wb") as fh:
        result = pisa.CreatePDF(html, dest=fh, encoding="utf-8")

    if result.err:
        raise RuntimeError(
            f"xhtml2pdf reported {result.err} error(s) while generating the PDF. "
            f"The output file may be incomplete."
        )
