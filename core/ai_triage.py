"""
Argus — AI-Assisted Triage: LLM Fix Suggestions (FR-8.1)

For each CONFIRMED finding, generate a fix suggestion via LLM API call
(finding type + request/response context as input), returned as
plain-language + code-snippet guidance (FR-8.1).

Deliberately scoped down (per solution.md's own framing): this is a single,
well-executed AI feature, not an "adaptive fuzzer" or multi-model pipeline.

Design choices worth knowing about:

  - CONFIRMED findings only, never 'suspected' -- generating confident-sounding
    fix advice for a heuristic-only timing signal risks being actively
    misleading (PRD risk table: "LLM fix suggestions are inaccurate or unsafe
    if applied blindly" -- advisory text only, never auto-applied).

  - Offline fallback is NOT an afterthought. PRD open question #1 flags LLM
    availability during judging as a real risk. Every vuln_type this module
    knows about has a static, pre-written fallback suggestion, so a judge
    pulling the network cable mid-demo doesn't break the feature -- it just
    silently drops from "AI-generated" to "built-in guidance". The CLI/dashboard
    don't need to know which path fired.

  - Provider is swappable. PRD suggests Gemini or GPT-4; this reference
    implementation calls Anthropic's Messages API by default since it's the
    provider reachable/testable in this build environment, but the call site
    is isolated in one function (`_call_llm`) so swapping providers is a
    localized change.
"""

import os
import textwrap
import httpx

from core import db

# --- Provider config -----------------------------------------------------

LLM_PROVIDER = os.environ.get("ARGUS_LLM_PROVIDER", "anthropic")  # anthropic | openai | offline
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
LLM_TIMEOUT_SECONDS = 10.0  # PRD success metric: <10s finding-to-fix-suggestion round trip

# --- Offline fallback library ---------------------------------------------
# One pre-written, defensible suggestion per vuln_type. This is what fires
# when no API key is configured, the API errors, or the call times out --
# never leave a confirmed finding without SOME actionable guidance.

FALLBACK_SUGGESTIONS = {
    "XSS": textwrap.dedent("""\
        Reflected XSS: the injected payload was echoed back into the response
        without encoding. Fix by HTML-encoding all user-controlled output at
        render time (e.g. Python: `markupsafe.escape(user_input)`, or use a
        templating engine with autoescaping enabled, like Jinja2's default).
        Never build HTML via raw string concatenation with user input.
        Example (Flask/Jinja2, autoescaping on by default):
          return render_template('results.html', query=user_input)  # safe
        Avoid:
          return f"<html>Results for: {user_input}</html>"  # unsafe"""),
    "SQLi": textwrap.dedent("""\
        SQL Injection: user input reached a SQL query without proper
        parameterization. Fix by using parameterized queries / prepared
        statements exclusively -- never build SQL via string formatting.
        Example (Python, psycopg2/sqlite3-style):
          cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # safe
        Avoid:
          cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # unsafe
        If using an ORM (SQLAlchemy, Django ORM), use its query builder
        rather than raw SQL strings wherever possible."""),
    "RCE": textwrap.dedent("""\
        Remote Code Execution risk: user input appears to reach a code-
        execution sink (eval, exec, subprocess with shell=True, deserialization
        of untrusted data, etc). Fix by eliminating dynamic code execution on
        user input entirely where possible. If a subprocess call is required,
        use an argument list (never shell=True with interpolated strings) and
        validate/allowlist input against an expected pattern before use."""),
    "exposed_file": textwrap.dedent("""\
        Sensitive file exposure: a file that should not be publicly accessible
        (e.g. .env, .git/config, backup archive) is being served. Fix by moving
        sensitive files outside the web server's document root, adding explicit
        deny rules in your web server config (nginx: `location ~ /\\.git { deny all; }`),
        and ensuring build/deploy processes don't copy dev artifacts (.env, .git,
        .bak files) into the production directory in the first place."""),
    "misconfig": textwrap.dedent("""\
        Misconfiguration: an endpoint or virtual host is accessible that likely
        shouldn't be exposed without authentication or at all in this environment.
        Fix by adding authentication/authorization middleware in front of
        administrative or internal-only routes, and auditing your routing/vhost
        config to ensure only intended hosts are served."""),
}

DEFAULT_FALLBACK = (
    "No specific automated guidance available for this finding type. "
    "Manually review the request/response evidence and apply standard "
    "input validation, output encoding, and least-privilege access controls."
)


def _build_prompt(finding: dict) -> str:
    """Constrained prompt: finding type + request/response context -> fix guidance."""
    return textwrap.dedent(f"""\
        You are a security remediation assistant. A web application scanner
        found the following CONFIRMED vulnerability. Provide a concise fix:
        1-2 sentences explaining the issue, then a short code snippet showing
        the fix. Keep the total response under 150 words. Do not add caveats
        about needing more context -- give your best concrete recommendation
        based on the evidence provided.

        Vulnerability type: {finding.get('vuln_type')}
        Module: {finding.get('module')}
        Parameter: {finding.get('parameter') or 'N/A'}
        URL: {finding.get('url')}
        Description: {finding.get('description')}
        Request evidence: {finding.get('request_evidence')}
        Response evidence: {finding.get('response_evidence')}
        """)


def _call_llm(prompt: str) -> str:
    """
    Isolated call site -- swap provider here without touching callers.
    Raises on failure; callers are responsible for falling back.
    """
    if LLM_PROVIDER == "anthropic":
        if not ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=LLM_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        return "\n".join(text_blocks).strip()

    elif LLM_PROVIDER == "openai":
        if not OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY not set")
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "content-type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=LLM_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()

    else:
        raise RuntimeError(f"Unknown or offline provider: {LLM_PROVIDER}")


def generate_fix_suggestion(finding: dict) -> tuple[str, str]:
    """
    Returns (suggestion_text, source) where source is 'llm' or 'fallback'.
    Never raises -- always returns something actionable.
    """
    try:
        prompt = _build_prompt(finding)
        suggestion = _call_llm(prompt)
        if suggestion:
            return suggestion, "llm"
    except Exception:
        pass  # fall through to offline fallback -- a judge losing wifi shouldn't break the demo

    fallback = FALLBACK_SUGGESTIONS.get(finding.get("vuln_type"), DEFAULT_FALLBACK)
    return fallback, "fallback"


def triage_scan(scan_id: str = None) -> int:
    """
    Runs fix-suggestion generation over all CONFIRMED findings that don't
    already have one, optionally scoped to a single scan. Returns count
    of findings updated.
    """
    findings = db.get_findings(scan_id=scan_id)
    confirmed_unsuggested = [
        f for f in findings
        if f["confidence"] == "confirmed" and not f.get("fix_suggestion")
    ]

    count = 0
    for finding in confirmed_unsuggested:
        suggestion, source = generate_fix_suggestion(finding)
        tagged = suggestion if source == "llm" else f"[offline guidance] {suggestion}"
        db.set_fix_suggestion(finding["finding_id"], tagged)
        count += 1

    return count


if __name__ == "__main__":
    import sys
    scan_arg = sys.argv[1] if len(sys.argv) > 1 else None

    db.init_db()
    print(f"LLM provider: {LLM_PROVIDER} "
          f"(key configured: {bool(ANTHROPIC_API_KEY or OPENAI_API_KEY)})")
    n = triage_scan(scan_id=scan_arg)
    print(f"Generated {n} fix suggestion(s).")
