"""E2E helpers against a throw-away fake stack: token grant, SSE listener, stack detection (no docker needed)."""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from e2e.helpers import E2E_CLIENT_ID, SseListener, Stack, StackConfig, TokenError, stack_status


class FakeStack(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    token_requests: list[dict[str, list[str]]] = []
    release = threading.Event()

    def _json(self, code: int, body: object) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/healthz" or self.path.endswith("openid-configuration"):
            return self._json(200, {"status": "ok"})
        if self.path == "/admin/v1/events/stream":
            if self.headers.get("Authorization") != "Bearer tok-adam":
                return self._json(401, {"detail": "no"})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b": keepalive\n\n")
            self.wfile.flush()
            for i, user in enumerate(["jan", "anna"]):
                ev = {"event_id": f"evt-{i}", "username": user, "event_type": "decision", "action": "allow"}
                self.wfile.write(f"event: decision\ndata: {json.dumps(ev)}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.05)
            self.release.wait(5)  # keep the stream open until the test closes it
            return None
        return self._json(404, {})

    def do_POST(self) -> None:
        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
        FakeStack.token_requests.append(form)
        ok = form.get("grant_type") == ["password"] and form.get("client_id") == [E2E_CLIENT_ID]
        if not ok:
            return self._json(401, {"error": "invalid_client"})
        self._json(200, {"access_token": f"tok-{form['username'][0]}", "expires_in": 60})

    def log_message(self, *a: object) -> None:
        return


@pytest.fixture
def fake_stack(monkeypatch):
    FakeStack.token_requests = []
    FakeStack.release = threading.Event()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeStack)
    httpd.daemon_threads = True
    threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.02), daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    monkeypatch.setenv("DEMO_USER_PASSWORD", "not-a-real-password")
    stack = Stack(StackConfig(gateway=url, keycloak=url, feed=url))
    yield stack
    FakeStack.release.set()
    stack.close()
    httpd.shutdown()
    httpd.server_close()


def test_password_grant_uses_the_e2e_client_and_caches(fake_stack: Stack) -> None:
    assert fake_stack.token("adam") == "tok-adam"
    assert fake_stack.token("adam") == "tok-adam"
    assert len(FakeStack.token_requests) == 1
    form = FakeStack.token_requests[0]
    assert form["client_id"] == [E2E_CLIENT_ID] and form["username"] == ["adam"]


def test_missing_password_is_a_clear_error_without_leaking(monkeypatch, fake_stack: Stack) -> None:
    monkeypatch.delenv("DEMO_USER_PASSWORD")
    monkeypatch.setattr("e2e.helpers.find_dotenv", lambda: None)
    with pytest.raises(TokenError, match="DEMO_USER_PASSWORD"):
        fake_stack.token("jan")


def test_sse_listener_collects_events_and_stops(fake_stack: Stack) -> None:
    sse = SseListener(fake_stack).start()
    try:
        ev = sse.wait_for(lambda e: e.data.get("username") == "anna", timeout=2)
        assert ev is not None and ev.event == "decision" and ev.data["event_id"] == "evt-1"
        assert [e.data["username"] for e in sse.events] == ["jan", "anna"]  # keepalive comment ignored
        assert sse.wait_for(lambda e: e.data.get("username") == "nobody", timeout=0.2) is None
    finally:
        t0 = time.monotonic()
        sse.stop()
        assert time.monotonic() - t0 < 2


def test_sse_listener_reports_refusal(fake_stack: Stack) -> None:
    with pytest.raises(RuntimeError, match="HTTP 401"):
        SseListener(fake_stack, user="jan").start()  # jan's token is not accepted by the fake admin stream


def test_stack_detection(fake_stack: Stack) -> None:
    assert stack_status(fake_stack.cfg) == (True, "ok")
    with socket.socket() as s:  # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        dead = f"http://127.0.0.1:{s.getsockname()[1]}"
    ok, reason = stack_status(StackConfig(gateway=dead, keycloak=dead, feed=dead))
    assert not ok and "gateway not reachable" in reason


def test_chat_and_admin_helpers_send_bearer(fake_stack: Stack) -> None:
    assert fake_stack.auth("adam") == {"Authorization": "Bearer tok-adam"}
    r = fake_stack.admin("GET", "/nothing")  # fake returns 404, proves the URL prefix and auth plumbing work
    assert r.status_code == 404
