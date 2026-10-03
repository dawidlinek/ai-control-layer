"""E2E helpers: stack discovery, Keycloak password-grant tokens, gateway/admin client, SSE listener.

Secrets come from the process environment or the repo's `.env` (searched from this checkout upwards, so a
git worktree finds the main checkout's `.env`). They are never printed or put in assertion messages.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[2]
E2E_CLIENT_ID = "acl-e2e"
PESEL_EXAMPLE = "44051401359"  # the well-known synthetic checksum-valid test PESEL; not a real person


def find_dotenv() -> Path | None:
    for base in (ROOT, *ROOT.parents):
        cand = base / ".env"
        if cand.is_file() and (base / "deploy" / "docker-compose.yml").is_file():
            return cand
    return None


def env_value(name: str, default: str | None = None) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    path = find_dotenv()
    if path is not None:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1].strip() or default
    return default


@dataclass(frozen=True)
class StackConfig:
    gateway: str = field(default_factory=lambda: os.environ.get("ACL_E2E_GATEWAY_URL") or _local("GATEWAY_PORT", 8000))
    keycloak: str = field(
        default_factory=lambda: os.environ.get("ACL_E2E_KEYCLOAK_URL") or _local("KEYCLOAK_PORT", 8180)
    )
    feed: str = field(default_factory=lambda: os.environ.get("ACL_E2E_FEED_URL") or _local("FEED_PORT", 8090))
    realm: str = "acl"
    policy_dir: Path = field(default_factory=lambda: Path(os.environ.get("ACL_E2E_POLICY_DIR") or ROOT / "policy"))


def _local(port_var: str, default: int) -> str:
    return f"http://localhost:{env_value(port_var, str(default))}"


def reachable(url: str, timeout: float = 1.5) -> bool:
    try:
        return httpx.get(url, timeout=timeout).status_code < 500
    except httpx.HTTPError:
        return False


def stack_status(cfg: StackConfig) -> tuple[bool, str]:
    """(usable, reason). The stack is usable when the gateway and Keycloak both answer."""
    if not reachable(f"{cfg.gateway}/healthz"):
        return False, f"gateway not reachable at {cfg.gateway} (run `make up`)"
    if not reachable(f"{cfg.keycloak}/realms/{cfg.realm}/.well-known/openid-configuration"):
        return False, f"Keycloak realm {cfg.realm!r} not reachable at {cfg.keycloak}"
    return True, "ok"


class TokenError(RuntimeError):
    pass


class Stack:
    """Gateway + Keycloak + feed-server endpoints with per-user tokens (password grant via client `acl-e2e`)."""

    def __init__(self, cfg: StackConfig | None = None) -> None:
        self.cfg = cfg or StackConfig()
        self._tokens: dict[str, tuple[str, float]] = {}
        self.http = httpx.Client(timeout=30)

    def close(self) -> None:
        self.http.close()

    # ---------------------------------------------------------------- tokens

    def token(self, username: str) -> str:
        cached = self._tokens.get(username)
        if cached and cached[1] > time.monotonic() + 10:
            return cached[0]
        password = env_value("DEMO_USER_PASSWORD")
        if not password:
            raise TokenError("DEMO_USER_PASSWORD is not set (run `make env`)")
        r = self.http.post(
            f"{self.cfg.keycloak}/realms/{self.cfg.realm}/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": E2E_CLIENT_ID, "username": username, "password": password},
        )
        if r.status_code != 200:
            hint = " (is the test-only `acl-e2e` client in the realm import?)" if r.status_code in (400, 401) else ""
            raise TokenError(f"token request for {username!r} failed: HTTP {r.status_code}{hint}")
        body = r.json()
        self._tokens[username] = (body["access_token"], time.monotonic() + float(body.get("expires_in", 60)))
        return body["access_token"]

    def auth(self, username: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(username)}"}

    # ---------------------------------------------------------------- gateway

    def chat(self, username: str, content: str, *, model: str = "auto", **body: Any) -> httpx.Response:
        payload = {"model": model, "messages": [{"role": "user", "content": content}], **body}
        return self.http.post(
            f"{self.cfg.gateway}/v1/chat/completions", json=payload, headers=self.auth(username), timeout=60
        )

    def admin(self, method: str, path: str, *, user: str = "adam", **kw: Any) -> httpx.Response:
        return self.http.request(method, f"{self.cfg.gateway}/admin/v1{path}", headers=self.auth(user), **kw)

    def async_client(self, username: str) -> httpx.AsyncClient:
        """Async client for `ScriptedAgent` against the live stack."""
        return httpx.AsyncClient(base_url=self.cfg.gateway, headers=self.auth(username), timeout=60)


# ---------------------------------------------------------------- SSE


@dataclass
class SseEvent:
    t: float  # time.monotonic() when the event was received
    event: str
    data: Any


class SseListener:
    """Background reader of `/admin/v1/events/stream`. Start it BEFORE the request that should produce events."""

    def __init__(self, stack: Stack, user: str = "adam", path: str = "/admin/v1/events/stream") -> None:
        self.stack = stack
        self.user = user
        self.path = path
        self.events: list[SseEvent] = []
        self.error: str | None = None
        self.connected = threading.Event()
        self._cond = threading.Condition()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False

    def start(self, timeout: float = 5.0) -> SseListener:
        headers = {**self.stack.auth(self.user), "Accept": "text/event-stream"}  # fetch the token on this thread
        self._thread = threading.Thread(target=self._run, args=(headers,), name="sse-listener", daemon=True)
        self._thread.start()
        if not self.connected.wait(timeout):
            self.stop()
            raise RuntimeError(f"SSE stream did not connect within {timeout}s: {self.error or 'no response'}")
        if self.error:
            self.stop()
            raise RuntimeError(f"SSE stream refused: {self.error}")
        return self

    def _run(self, headers: dict[str, str]) -> None:
        """Raw-socket SSE reader. HTTP/1.0 keeps servers from chunk-framing the stream, and short socket
        timeouts let `stop()` end the thread promptly (closing a socket under a blocked recv does not on Windows)."""
        parts = urlsplit(self.stack.cfg.gateway)
        host, port = parts.hostname or "localhost", parts.port or 80
        try:
            sock = socket.create_connection((host, port), timeout=5)
            self._sock = sock
            head = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            sock.sendall(f"GET {self.path} HTTP/1.0\r\nHost: {host}:{port}\r\n{head}\r\n".encode())
            sock.settimeout(0.2)
            buf, in_body = b"", False
            event, data = "message", []
            while not self._stop:
                try:
                    chunk = sock.recv(65536)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                buf += chunk
                if not in_body:
                    if b"\r\n\r\n" not in buf:
                        continue
                    header, _, buf = buf.partition(b"\r\n\r\n")
                    status = header.split(b"\r\n", 1)[0].decode("latin-1")
                    if " 200" not in status:
                        self.error = "HTTP " + (status.split(" ")[1] if " " in status else status)
                        return
                    in_body = True
                    self.connected.set()
                while b"\n" in buf:
                    raw, _, buf = buf.partition(b"\n")
                    line = raw.decode("utf-8", errors="replace").rstrip("\r")
                    if line == "":
                        if data:
                            self._push(event, "\n".join(data))
                        event, data = "message", []
                    elif line.startswith("event:"):
                        event = line[6:].strip()
                    elif line.startswith("data:"):
                        data.append(line[5:].lstrip())
        except (OSError, ValueError) as exc:
            if not self._stop:
                self.error = self.error or f"{type(exc).__name__}: {exc}"
        finally:
            self.connected.set()

    def _push(self, event: str, raw: str) -> None:
        try:
            data: Any = json.loads(raw)
        except ValueError:
            data = raw
        with self._cond:
            self.events.append(SseEvent(time.monotonic(), event, data))
            self._cond.notify_all()

    def wait_for(self, predicate, timeout: float = 1.0) -> SseEvent | None:  # type: ignore[no-untyped-def]
        """First received event matching `predicate(SseEvent)`; waits up to `timeout` seconds."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for ev in self.events:
                    if isinstance(ev.data, dict) and predicate(ev):
                        return ev
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self._cond.wait(left)

    def stop(self) -> None:
        self._stop = True
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._sock.close()
        if self._thread is not None:
            self._thread.join(2)


# ---------------------------------------------------------------- feed server


def add_feed_rule(stack: Stack, entry: dict[str, Any]) -> bool:
    """Publish a signature entry through the feed server's admin endpoint.

    ASSUMED interface (Phase 1D extends the stand-in feed server): `POST {feed}/admin/rules` with a
    `SignatureEntry` JSON body publishes a new bundle version containing it; `DELETE {feed}/admin/rules/{id}`
    removes it again. Returns False when the feed server offers no such endpoint (the test then skips).
    """
    r = stack.http.post(f"{stack.cfg.feed}/admin/rules", json=entry)
    return r.status_code in (200, 201, 202, 204)


def remove_feed_rule(stack: Stack, rule_id: str) -> None:
    with contextlib.suppress(httpx.HTTPError):
        stack.http.delete(f"{stack.cfg.feed}/admin/rules/{rule_id}")
