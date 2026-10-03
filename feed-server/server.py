"""Stand-in for the external signature system (Phase 0 stub; Phase 1D extends).

Serves the newest bundle in BUNDLE_DIR at GET /bundle.json, with its digest at GET /bundle.sha256.
Stdlib only, so the container needs no dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BUNDLE_DIR = Path(os.environ.get("BUNDLE_DIR", Path(__file__).parent / "bundles"))


def canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def current_bundle() -> dict | None:
    bundles = sorted(BUNDLE_DIR.glob("*.json"))
    if not bundles:
        return None
    best = max((json.loads(p.read_text(encoding="utf-8")) for p in bundles), key=lambda b: b["bundle_version"])
    body = {k: v for k, v in best.items() if k != "signature"}
    best["signature"] = {"alg": "sha256", "key_id": None, "value": hashlib.sha256(canonical(body).encode()).hexdigest()}
    return best


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            return self._send(200, b'{"status":"ok"}')
        bundle = current_bundle()
        if bundle is None:
            return self._send(404, b'{"error":"no bundle"}')
        if self.path == "/bundle.json":
            return self._send(200, json.dumps(bundle, ensure_ascii=False).encode())
        if self.path == "/bundle.sha256":
            return self._send(200, bundle["signature"]["value"].encode(), "text/plain")
        return self._send(404, b'{"error":"not found"}')

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"feed-server: {fmt % args}", flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"feed-server on :{port}, bundles from {BUNDLE_DIR}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()  # noqa: S104
