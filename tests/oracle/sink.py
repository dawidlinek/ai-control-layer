"""Attacker "sink": a standalone HTTP server that records every request it receives.

If data was exfiltrated to an attacker-controlled endpoint, it shows up here; if the sink log is empty
the exfiltration did not happen. This is an oracle independent of the gateway's own logs. Standard library
only (no `acl` import) so it runs in a bare `python:3-slim` container.

    python sink.py [--port 8080] [--log /data/sink.jsonl]     (env: PORT, SINK_LOG)

Every request except `/_log`, `/_reset` and `/healthz` is logged as one JSON line:
    {"seq", "ts", "method", "path", "query", "query_raw", "headers", "body", "body_b64", "client"}
and answered with 200 `{"ok": true}` (any method, any path -- it must look like a working endpoint).

    GET    /_log     -> {"count": N, "entries": [...]}   (optional ?since=<seq>)
    DELETE /_log     -> clears the in-memory log (also POST /_reset)
    GET    /healthz  -> {"status": "ok"}
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

CONTROL_PATHS = {"/_log", "/_reset", "/healthz"}


class SinkState:
    def __init__(self, log_path: Path | None = None) -> None:
        self.entries: list[dict[str, Any]] = []
        self.log_path = log_path
        self._lock = threading.Lock()
        self._seq = 0

    def record(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            entry = {"seq": self._seq, **entry}
            self.entries.append(entry)
            if self.log_path is not None:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8", newline="\n") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def snapshot(self, since: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self.entries if e["seq"] > since]

    def clear(self) -> None:
        with self._lock:
            self.entries.clear()


def make_handler(state: SinkState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        wbufsize = 65536  # one TCP segment for headers+body (avoids Nagle/delayed-ACK stalls)

        def _send(self, code: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                return self.rfile.read(length)
            if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
                chunks = []
                while True:
                    size = int(self.rfile.readline().strip() or b"0", 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(size))
                    self.rfile.readline()
                return b"".join(chunks)
            return b""

        def _handle(self) -> None:
            parts = urlsplit(self.path)
            body = self._read_body()
            if parts.path in CONTROL_PATHS:
                if parts.path == "/healthz":
                    return self._send(200, {"status": "ok"})
                if parts.path == "/_log" and self.command == "GET":
                    since = int((parse_qs(parts.query).get("since") or ["0"])[0])
                    entries = state.snapshot(since)
                    return self._send(200, {"count": len(entries), "entries": entries})
                if (parts.path == "/_log" and self.command == "DELETE") or parts.path == "/_reset":
                    state.clear()
                    return self._send(200, {"cleared": True})
            try:
                text: str | None = body.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            state.record(
                {
                    "ts": time.time(),
                    "method": self.command,
                    "path": parts.path,
                    "query": parse_qs(parts.query, keep_blank_values=True),
                    "query_raw": parts.query,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body": text if text is not None else "",
                    "body_b64": None if text is not None else base64.b64encode(body).decode(),
                    "client": self.client_address[0],
                }
            )
            self._send(200, {"ok": True})

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

        def log_message(self, fmt: str, *args: object) -> None:  # keep test output quiet
            return

    return Handler


class SinkServer:
    """In-process sink for tests: `with SinkServer() as sink: ... sink.url, sink.entries()`."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, log_path: Path | None = None) -> None:
        self.state = SinkState(log_path)
        self._httpd = ThreadingHTTPServer((host, port), make_handler(self.state))
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=lambda: self._httpd.serve_forever(poll_interval=0.02), name="attacker-sink", daemon=True
        )
        self.host = host

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> SinkServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(5)

    def entries(self) -> list[dict[str, Any]]:
        return self.state.snapshot()

    def clear(self) -> None:
        self.state.clear()

    def __enter__(self) -> SinkServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    ap.add_argument("--log", default=os.environ.get("SINK_LOG"))
    args = ap.parse_args()
    state = SinkState(Path(args.log) if args.log else None)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    httpd.daemon_threads = True
    print(f"attacker sink listening on {args.host}:{args.port} (log: {args.log or 'memory only'})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
