"""
Argus — Central SQLite store.

All three delivery surfaces (CLI, VS Code extension, browser extension) write
findings here. The dashboard reads from this single source of truth.
"""

import sqlite3
import json
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "argus.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    scope_file TEXT,
    status TEXT DEFAULT 'running'   -- running | completed | failed
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    target TEXT NOT NULL,
    module TEXT NOT NULL,           -- dir_enum | vhost | api_discovery | param_fuzz | subdomain
    vuln_type TEXT NOT NULL,        -- RCE | SQLi | XSS | exposed_file | misconfig
    confidence TEXT NOT NULL,       -- confirmed | suspected
    severity_score REAL NOT NULL,
    url TEXT,
    parameter TEXT,
    request_evidence TEXT,          -- raw request (headers/body) as text
    response_evidence TEXT,         -- raw response (status/headers/body snippet) as text
    description TEXT,
    fix_suggestion TEXT,            -- filled in later by the AI triage layer
    source_surface TEXT NOT NULL,   -- cli | vscode | browser
    status TEXT DEFAULT 'open',     -- open | fixed | false_positive
    created_at REAL NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);

CREATE TABLE IF NOT EXISTS request_log (
    log_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    method TEXT,
    url TEXT,
    status_code INTEGER
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity_score DESC);
CREATE INDEX IF NOT EXISTS idx_request_log_scan ON request_log(scan_id);
"""


def init_db(db_path: Path = DB_PATH) -> None:
    """Create tables if they don't exist. Safe to call every run."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def get_conn(db_path: Path = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# --- Severity scoring (matches PRD FR-9) -----------------------------------

BASE_SEVERITY = {
    "RCE": 9.0,
    "SQLi": 8.5,
    "XSS": 6.0,
    "exposed_file": 5.0,
    "misconfig": 4.0,
}

CONFIDENCE_MULTIPLIER = {
    "confirmed": 1.0,
    "suspected": 0.5,
}


def compute_severity(vuln_type: str, confidence: str) -> float:
    base = BASE_SEVERITY.get(vuln_type, 3.0)  # unknown types default low-ish
    mult = CONFIDENCE_MULTIPLIER.get(confidence, 0.5)
    return round(base * mult, 2)


# --- Write helpers -----------------------------------------------------------

def start_scan(target: str, scope_file: str = None) -> str:
    scan_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, target, started_at, scope_file, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, target, time.time(), scope_file, "running"),
        )
    return scan_id


def finish_scan(scan_id: str, status: str = "completed") -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET finished_at = ?, status = ? WHERE scan_id = ?",
            (time.time(), status, scan_id),
        )


def add_finding(
    scan_id: str,
    target: str,
    module: str,
    vuln_type: str,
    confidence: str,
    url: str = None,
    parameter: str = None,
    request_evidence: str = None,
    response_evidence: str = None,
    description: str = None,
    source_surface: str = "cli",
) -> str:
    finding_id = str(uuid.uuid4())
    severity_score = compute_severity(vuln_type, confidence)
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO findings (
                finding_id, scan_id, target, module, vuln_type, confidence,
                severity_score, url, parameter, request_evidence,
                response_evidence, description, source_surface, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id, scan_id, target, module, vuln_type, confidence,
                severity_score, url, parameter, request_evidence,
                response_evidence, description, source_surface, "open", time.time(),
            ),
        )
    return finding_id


def log_request(scan_id: str, target: str, module: str, method: str, url: str, status_code: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO request_log (log_id, scan_id, timestamp, target, module, method, url, status_code) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), scan_id, time.time(), target, module, method, url, status_code),
        )


def get_findings(scan_id: str = None, order_by_severity: bool = True):
    query = "SELECT * FROM findings"
    params = ()
    if scan_id:
        query += " WHERE scan_id = ?"
        params = (scan_id,)
    if order_by_severity:
        query += " ORDER BY severity_score DESC"
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_scans():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]


def update_finding_status(finding_id: str, status: str) -> None:
    assert status in ("open", "fixed", "false_positive")
    with get_conn() as conn:
        conn.execute("UPDATE findings SET status = ? WHERE finding_id = ?", (status, finding_id))


def set_fix_suggestion(finding_id: str, suggestion: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE findings SET fix_suggestion = ? WHERE finding_id = ?",
            (suggestion, finding_id),
        )


if __name__ == "__main__":
    init_db()
    print(f"Initialized Argus DB at {DB_PATH}")
