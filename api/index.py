"""Vercel entrypoint: serves the deliberately misconfigured practice site
(tests/target_app, profile "vulnerable") as a Python serverless function.

This is a demo target for sitescan. It holds no real data or secrets: the
"exposed" files only return a placeholder marker.

vercel.json rewrites every request to /api/index?__path=<original path>,
because the rewrite replaces the request path. The small WSGI wrapper below
restores the original path before Flask routes the request.
"""
import os
import sys
from urllib.parse import parse_qsl, urlencode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.target_app.app import create_app  # noqa: E402

flask_app = create_app("vulnerable")


def app(environ, start_response):
    pairs = parse_qsl(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    original = [v for k, v in pairs if k == "__path"]
    if original:
        environ["PATH_INFO"] = "/" + original[0].lstrip("/")
        environ["QUERY_STRING"] = urlencode([(k, v) for k, v in pairs if k != "__path"])
    return flask_app(environ, start_response)
