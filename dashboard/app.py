"""
Argus — Web Dashboard (FR-10)

Central hub aggregating findings from all three delivery surfaces (CLI,
VS Code extension, browser extension), all reading from the same SQLite
store (core/db.py) -- so this view is a unified single source of truth
regardless of where a finding was made.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, redirect, url_for

from core import db

app = Flask(__name__)

# Fixed display order for the severity gauge -- highest to lowest base severity.
VULN_TYPE_ORDER = ["RCE", "SQLi", "XSS", "exposed_file", "misconfig"]

VULN_TYPE_COLOR = {
    "RCE": "#D0454F",
    "SQLi": "#E0674F",
    "XSS": "#E8A33D",
    "exposed_file": "#D4B14A",
    "misconfig": "#6B93B0",
}


@app.route("/")
def index():
    db.init_db()
    scan_filter = request.args.get("scan")
    status_filter = request.args.get("status", "all")

    all_scans = db.get_scans()
    findings = db.get_findings(scan_id=_resolve_scan_id(scan_filter, all_scans))

    if status_filter != "all":
        findings = [f for f in findings if f["status"] == status_filter]

    counts_by_type = {vt: 0 for vt in VULN_TYPE_ORDER}
    for f in findings:
        if f["vuln_type"] in counts_by_type:
            counts_by_type[f["vuln_type"]] += 1

    total = sum(counts_by_type.values())
    open_count = sum(1 for f in findings if f["status"] == "open")
    fixed_count = sum(1 for f in findings if f["status"] == "fixed")
    fp_count = sum(1 for f in findings if f["status"] == "false_positive")

    # Highest-severity OPEN finding determines the gauge's center "pupil" color.
    open_findings = [f for f in findings if f["status"] == "open"]
    if open_findings:
        top = max(open_findings, key=lambda f: f["severity_score"])
        pupil_color = VULN_TYPE_COLOR.get(top["vuln_type"], "#3FA9A0")
    else:
        pupil_color = "#3FA9A0"  # calm teal -- nothing open

    gauge_rings = _build_gauge_rings(counts_by_type, total)

    return render_template(
        "index.html",
        findings=findings,
        scans=all_scans,
        selected_scan=scan_filter,
        status_filter=status_filter,
        counts_by_type=counts_by_type,
        vuln_type_order=VULN_TYPE_ORDER,
        vuln_type_color=VULN_TYPE_COLOR,
        total=total,
        open_count=open_count,
        fixed_count=fixed_count,
        fp_count=fp_count,
        gauge_rings=gauge_rings,
        pupil_color=pupil_color,
    )


def _resolve_scan_id(prefix, all_scans):
    if not prefix or prefix == "all":
        return None
    for s in all_scans:
        if s["scan_id"].startswith(prefix):
            return s["scan_id"]
    return None


def _build_gauge_rings(counts_by_type, total):
    """
    Builds concentric ring geometry for the severity iris gauge: one ring per
    vuln category, radius increasing outward from center, with stroke-dasharray
    proportional to that category's share of total findings. This is real
    information (relative severity distribution at a glance), not decoration.
    """
    rings = []
    base_radius = 28
    radius_step = 16
    circumference_factor = 2 * 3.14159265

    for i, vuln_type in enumerate(VULN_TYPE_ORDER):
        radius = base_radius + i * radius_step
        circumference = circumference_factor * radius
        count = counts_by_type.get(vuln_type, 0)
        fraction = (count / total) if total > 0 else 0
        # Minimum visible sliver so a present-but-small category isn't invisible
        dash = max(circumference * fraction, 4 if count > 0 else 0)
        rings.append({
            "vuln_type": vuln_type,
            "radius": radius,
            "circumference": circumference,
            "dash": dash,
            "color": VULN_TYPE_COLOR[vuln_type],
            "count": count,
        })
    return rings


@app.route("/finding/<finding_id>/status", methods=["POST"])
def update_status(finding_id):
    new_status = request.form.get("status")
    if new_status in ("open", "fixed", "false_positive"):
        db.update_finding_status(finding_id, new_status)
    return redirect(request.referrer or url_for("index"))


if __name__ == "__main__":
    db.init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
