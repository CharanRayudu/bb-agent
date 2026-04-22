#!/usr/bin/env python3
"""
Mirage LLM Proxy
================
Run this on your local machine (where Codex CLI is authenticated).
It forwards LLM requests from the Mirage server through your local
Codex auth token, bypassing OpenAI's server-IP allowlist restriction.

Setup (two steps):

  1. On your local machine — start this proxy:
       pip3 install requests
       python3 mirage-proxy.py

  2. On your local machine — open a reverse SSH tunnel to the server:
       ssh -R 8765:localhost:8765 root@<SERVER_IP>
     Keep this terminal open. The tunnel stays alive as long as SSH runs.

  3. On the server — add to .env and restart the backend:
       LLM_PROXY_URL=http://localhost:8765

Environment variables (optional):
  CODEX_HOME     Path to codex config dir (default: ~/.codex)
  PROXY_PORT     Port to listen on (default: 8765)
  PROXY_SECRET   If set, clients must send X-Proxy-Secret: <value>
"""

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is not installed. Run: pip3 install requests")
    sys.exit(1)

CODEX_HOME   = os.environ.get("CODEX_HOME", os.path.expanduser("~/.codex"))
AUTH_FILE    = os.path.join(CODEX_HOME, "auth.json")
CODEX_URL    = "https://chatgpt.com/backend-api/codex/responses"
PROXY_PORT   = int(os.environ.get("PROXY_PORT", "8765"))
PROXY_SECRET = os.environ.get("PROXY_SECRET", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
log = logging.getLogger("mirage-proxy")


def load_token() -> str:
    """Read the Codex access token from auth.json."""
    try:
        with open(AUTH_FILE) as f:
            auth = json.load(f)
    except FileNotFoundError:
        raise RuntimeError(
            f"Codex auth file not found at {AUTH_FILE}. Run 'codex login' first."
        )

    tokens = auth.get("tokens") or {}
    token = (
        tokens.get("access_token")
        or tokens.get("id_token")
        or auth.get("access_token", "")
    )
    if not token:
        raise RuntimeError(
            f"No access token found in {AUTH_FILE}. Run 'codex login' to re-authenticate."
        )
    return token


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info(fmt % args)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","proxy":"mirage-llm-proxy"}')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # Optional shared-secret check
        if PROXY_SECRET:
            if self.headers.get("X-Proxy-Secret", "") != PROXY_SECRET:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")
                return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        # Load auth token
        try:
            token = load_token()
        except RuntimeError as e:
            log.error("Auth error: %s", e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())
            return

        headers = {
            "Authorization":  f"Bearer {token}",
            "Content-Type":   "application/json",
            "Accept":         "text/event-stream",
            "User-Agent":     "codex-cli/0.122.0",
            "OpenAI-Beta":    "responses=v1",
        }

        log.info("→ Forwarding %d-byte request to Codex", len(body))
        try:
            resp = requests.post(
                CODEX_URL,
                data=body,
                headers=headers,
                stream=True,
                timeout=180,
            )
            log.info("← Codex HTTP %d", resp.status_code)

            self.send_response(resp.status_code)
            for key, val in resp.headers.items():
                if key.lower() in ("content-type", "transfer-encoding",
                                   "cache-control", "x-request-id"):
                    self.send_header(key, val)
            self.end_headers()

            for chunk in resp.iter_content(chunk_size=512):
                if chunk:
                    self.wfile.write(chunk)
                    self.wfile.flush()

        except requests.exceptions.ConnectionError as e:
            log.error("Connection error: %s", e)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Proxy connection error")
        except Exception as e:
            log.error("Proxy error: %s", e)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())


if __name__ == "__main__":
    server = HTTPServer(("localhost", PROXY_PORT), ProxyHandler)
    log.info("=" * 55)
    log.info("  Mirage LLM Proxy  —  listening on localhost:%d", PROXY_PORT)
    log.info("  Auth file : %s", AUTH_FILE)
    if PROXY_SECRET:
        log.info("  Secret    : configured")
    log.info("=" * 55)
    log.info("Now open the reverse SSH tunnel from this machine:")
    log.info("  ssh -R %d:localhost:%d root@SERVER_IP", PROXY_PORT, PROXY_PORT)
    log.info("Then add to server .env:  LLM_PROXY_URL=http://localhost:%d", PROXY_PORT)
    log.info("=" * 55)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Proxy stopped.")
