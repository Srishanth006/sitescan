"""Local Flask target for the test suite.

Profiles:
  vulnerable - deliberately misconfigured in every way sitescan checks
  hardened   - the well-configured counterpart (used for negative tests)
  redirect   - plain-HTTP front door that 301s everything to ``https_url``

Run standalone (for the sample report):
    python -m tests.target_app.app --profile vulnerable --port 8080
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, abort, redirect, request
from werkzeug.serving import WSGIRequestHandler


class TargetRequestHandler(WSGIRequestHandler):
    """Drop werkzeug's own `Server: Werkzeug/x Python/y` header so the app's
    Server header is the only one (as it would be behind a real web server)."""

    def send_header(self, keyword, value):
        if keyword.lower() == "server" and value == self.version_string():
            return
        super().send_header(keyword, value)

VULN_HTML = """<!doctype html>
<html><head>
<title>Acme Legacy Portal</title>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<link rel="stylesheet" href="http://cdn.legacy.test/theme.css">
<script src="/static/js/jquery-1.12.4.min.js"></script>
<script src="/static/js/app.js"></script>
<script src="http://cdn.legacy.test/analytics.js"></script>
</head><body>
<h1>Acme Legacy Portal</h1>
<img src="http://cdn.legacy.test/logo.png" alt="logo">
<iframe src="http://widgets.legacy.test/chat"></iframe>
<form action="http://legacy.test/login" method="post"><input name="u"></form>
</body></html>
"""

GOOD_HTML = """<!doctype html>
<html><head>
<title>Acme Portal</title>
<script src="/static/js/jquery-3.7.1.min.js" nonce="r4nd0m"></script>
</head><body>
<h1>Acme Portal</h1>
<img src="/static/logo.png" alt="logo">
<a href="http://example.test/">plain links are not mixed content</a>
</body></html>
"""

VERBOSE_404 = """<html><body><h1>Internal error</h1><pre>
Traceback (most recent call last):
  File "/srv/app/views.py", line 42, in dispatch
    return handlers[path]()
KeyError: '{path}'
</pre><p>DEBUG = True</p></body></html>"""

DIR_LISTING = """<html><head><title>Index of /uploads</title></head><body>
<h1>Index of /uploads</h1><pre><a href="../">../</a>
<a href="invoice-2023.pdf">invoice-2023.pdf</a>
</pre></body></html>"""

VULN_ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /internal-api/\n"
GOOD_ROBOTS = "User-agent: *\nDisallow: /search\nSitemap: /sitemap.xml\n"
SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://127.0.0.1/</loc></url><url><loc>https://127.0.0.1/about</loc></url>
</urlset>"""

EXPOSED = {"/.git/config", "/.env", "/backup.sql", "/phpinfo.php", "/.DS_Store"}


def create_app(profile: str = "vulnerable", https_url: str | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)

    if profile == "redirect":
        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def to_https(path):
            return redirect(https_url.rstrip("/") + "/" + path, code=301)

        @app.after_request
        def srv(resp):
            resp.headers["Server"] = "nginx"
            return resp

        return app

    vulnerable = profile == "vulnerable"

    @app.after_request
    def headers(resp: Response):
        if vulnerable:
            resp.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
            resp.headers["X-Powered-By"] = "PHP/7.2.3"
        else:
            resp.headers["Server"] = "nginx"
        return resp

    @app.route("/")
    def index():
        if vulnerable:
            r = Response(VULN_HTML, mimetype="text/html")
            r.headers["Content-Security-Policy"] = (
                "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"
            )
            r.headers["Strict-Transport-Security"] = "max-age=600"
            r.headers["Referrer-Policy"] = "unsafe-url"
            r.headers.add("Set-Cookie", "PHPSESSID=8f3a1c9e; Path=/")
            r.headers.add("Set-Cookie", "tracking=xyz; Path=/; SameSite=None")
            return r
        r = Response(GOOD_HTML, mimetype="text/html")
        r.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        r.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        r.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        r.headers.add("Set-Cookie", "session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax")
        return r

    @app.route("/static/js/<name>")
    def js(name):
        if vulnerable and name == "jquery-1.12.4.min.js":
            body = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(){}();"
        elif vulnerable and name == "app.js":
            body = "/*!\n * AngularJS v1.5.8\n * (c) 2010-2016 Google, Inc.\n */\nvar x=1;"
        elif not vulnerable and name == "jquery-3.7.1.min.js":
            body = "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors */\n!function(){}();"
        else:
            abort(404)
        return Response(body, mimetype="application/javascript")

    @app.route("/robots.txt")
    def robots():
        return Response(VULN_ROBOTS if vulnerable else GOOD_ROBOTS, mimetype="text/plain")

    @app.route("/sitemap.xml")
    def sitemap():
        if vulnerable:
            abort(404)
        return Response(SITEMAP, mimetype="application/xml")

    @app.route("/.well-known/security.txt")
    def security_txt():
        if vulnerable:
            abort(404)
        expires = (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = (
            "Contact: mailto:security@acme.test\n"
            f"Expires: {expires}\n"
            "Preferred-Languages: en\n"
            "Policy: https://acme.test/security-policy\n"
        )
        return Response(body, mimetype="text/plain")

    @app.route("/uploads/")
    def uploads():
        if vulnerable:
            return Response(DIR_LISTING, mimetype="text/html")
        abort(404)

    @app.route("/admin")
    def admin():
        if vulnerable:
            return Response("auth required", status=401, headers={"WWW-Authenticate": 'Basic realm="admin"'})
        abort(404)

    @app.route("/<path:anything>")
    def catch_all(anything):
        path = "/" + anything
        if vulnerable and path in EXPOSED:
            # Content is a marker only; sitescan must never download it (HEAD only).
            return Response("SENSITIVE-CONTENT-MARKER", mimetype="application/octet-stream")
        abort(404)

    @app.errorhandler(404)
    def not_found(_e):
        if vulnerable:
            return Response(VERBOSE_404.format(path=request.path), status=404, mimetype="text/html")
        return Response("Not Found", status=404, mimetype="text/plain")

    return app


if __name__ == "__main__":  # pragma: no cover
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="vulnerable")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    create_app(a.profile).run("127.0.0.1", a.port, request_handler=TargetRequestHandler)
