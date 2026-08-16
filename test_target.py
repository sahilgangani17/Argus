"""
A minimal local HTTP target for validating Argus modules without needing
Docker/DVWA in this environment. Mimics the exact conditions the false-positive
filter is designed to handle:

  - A custom "not found" page that returns HTTP 200 instead of 404 for
    truly unknown paths (this is what breaks naive brute-forcers).
  - A few real hidden resources: /admin, /.env, /.git/config, /backup.zip
  - A vhost-only page served when Host header == internal.dvwa.local
  - A vulnerable-looking search param for later param-fuzzing tests.

Run with: python test_target.py
"""

from flask import Flask, request, Response

app = Flask(__name__)

REAL_PATHS = {
    "/admin": "Admin Panel - restricted",
    "/.env": "DB_PASSWORD=supersecret123\nAPI_KEY=abcd1234",
    "/.git/config": "[core]\n\trepositoryformatversion = 0",
    "/backup.zip": "PK\x03\x04 (fake zip bytes)",
    "/config.php": "<?php // leaked config",
}


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    full_path = "/" + path

    # VHost-specific content
    if request.headers.get("Host", "").startswith("internal.dvwa.local"):
        return Response("Internal admin vhost - secret content", status=200)

    if full_path in REAL_PATHS:
        return Response(REAL_PATHS[full_path], status=200)

    # Simulate a reflected-XSS-ish search param for later param fuzzing tests
    if full_path == "/search":
        q = request.args.get("q", "")
        return Response(f"<html><body>Results for: {q}</body></html>", status=200)

    # Custom 404 page that still returns HTTP 200 (the classic false-positive trap).
    # Fixed content, static length -- this is what a real catch-all 404 page looks like.
    return Response(
        "<html><body><h1>Oops! Page not found</h1></body></html>",
        status=200,
    )


if __name__ == "__main__":
    # threaded=True: Flask's dev server is single-threaded by default and will
    # serialize/corrupt concurrent connections under load, which is exactly
    # what a high-concurrency fuzzer throws at it. Real targets don't have
    # this problem, but our local test harness needs it for accurate testing.
    app.run(host="127.0.0.1", port=8080, threaded=True)
