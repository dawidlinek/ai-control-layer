"""CP2 clients: locked OpenCode container + guard plugin, and LibreChat behind Keycloak (concept section 5, 10).

Needs the stack plus the clients profile (see deploy/README-clients.md):

    COMPOSE_PROFILES=clients uv run python scripts/dev.py up        # then: make e2e

and the gateway attached to the `acl-clients-internal` network (alias `gateway`). Every test skips cleanly when the
clients profile is not running. What is real here: the real OpenCode CLI (driven through its HTTP server, the same
code path as the TUI), the real plugin, real Keycloak (device-code and authorization-code logins, approved by a
scripted browser stand-in), the real LibreChat. What is not: nobody types into the TUI. Tool calls are provoked
with the deterministic mock model's `[[mock:tool ...]]` directive, so those parts need ACL_DETERMINISTIC=1 on the
gateway (they skip otherwise).

Secrets (demo password) are read from the environment / .env and never appear in assertion messages.
"""

from __future__ import annotations

import base64
import html
import json
import re
import subprocess
import threading
import time
import uuid
from urllib.parse import urljoin, urlsplit

import httpx
import pytest
from e2e.helpers import Stack, env_value

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(300)]  # first OpenCode start + device login are slow

LIBRECHAT_URL = "http://localhost:3080"
OPENCODE_PORT = 4097
CANARY = "ACL-CANARY-SSHKEY-9f2c71d4e8a3b605"
_RULE = r"[A-Z][A-Z0-9]*(?:-[A-Z0-9_.]+)+"
RULE_ID_IN_MESSAGE = re.compile(rf"\[{_RULE}(?:, {_RULE})*\]")  # one or more rule ids, e.g. [SIG-..., SEC-TOOL-01]
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


# ---------------------------------------------------------------------------------------------- docker helpers


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _container(service: str) -> str | None:
    try:
        out = _docker(
            "ps",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--filter",
            "label=com.docker.compose.project=acl",
            "--format",
            "{{.Names}}",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    names = out.stdout.split()
    return names[0] if out.returncode == 0 and names else None


class Exec:
    """`docker exec` into the locked OpenCode container."""

    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, *cmd: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return _docker("exec", self.name, *cmd, timeout=timeout)

    def curl(self, *args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        return self.run("curl", "-sS", "-m", str(int(timeout)), *args, timeout=timeout + 10)

    def sh(self, script: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return self.run("sh", "-c", script, timeout=timeout)


@pytest.fixture(scope="module")
def oc() -> Exec:
    name = _container("opencode")
    if name is None:
        pytest.skip("clients profile not running (COMPOSE_PROFILES=clients ... up): no `opencode` container")
    return Exec(name)


@pytest.fixture(scope="module")
def librechat_up() -> None:
    if _container("librechat") is None:
        pytest.skip("clients profile not running: no `librechat` container")
    try:
        ok = httpx.get(f"{LIBRECHAT_URL}/api/config", timeout=5).status_code < 500
    except httpx.HTTPError:
        ok = False
    if not ok:
        pytest.skip(f"LibreChat not answering at {LIBRECHAT_URL}")


# ---------------------------------------------------------------------------------------------- browser stand-in


class MiniBrowser:
    """Just enough browser for Keycloak + LibreChat logins: redirects, forms, and cookies.

    Cookies are tracked by hand because Keycloak and LibreChat mark them `Secure` while we speak plain http to
    localhost (browsers allow that for localhost, httpx does not).
    """

    def __init__(self) -> None:
        self.http = httpx.Client(follow_redirects=False, timeout=30, headers={"User-Agent": BROWSER_UA})
        self.jars: dict[str, dict[str, str]] = {}

    def close(self) -> None:
        self.http.close()

    def request(self, method: str, url: str, **kw) -> tuple[httpx.Response, str]:  # type: ignore[no-untyped-def]
        for _ in range(15):
            jar = self.jars.setdefault(urlsplit(url).netloc, {})
            headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())} | kw.pop("headers", {})
            r = self.http.request(method, url, headers=headers, **kw)
            for sc in r.headers.get_list("set-cookie"):
                name, _, rest = sc.partition("=")
                value = rest.split(";", 1)[0]
                if value == "" or "Max-Age=0" in sc or "1970" in sc:
                    jar.pop(name, None)
                else:
                    jar[name] = value
            if r.is_redirect:
                url, method, kw = urljoin(url, r.headers["location"]), "GET", {}
                continue
            return r, url
        raise AssertionError("too many redirects")

    def keycloak_login(self, page: httpx.Response, url: str, username: str) -> tuple[httpx.Response, str]:
        """Fill and submit the Keycloak login form (and the consent form, if shown)."""
        password = env_value("DEMO_USER_PASSWORD")
        assert password, "DEMO_USER_PASSWORD is not set (run `make env`)"
        for _ in range(4):
            form = re.search(r'<form[^>]+action="([^"]+)"', page.text)
            if not form:
                return page, url
            action = urljoin(url, html.unescape(form.group(1)))
            if 'name="username"' in page.text:
                data = {"username": username, "password": password, "credentialId": ""}
            else:  # consent ("Grant access") page
                data = {}
                for tag in re.findall(r"<input[^>]+>", page.text):
                    n = re.search(r'name="([^"]+)"', tag)
                    v = re.search(r'value="([^"]*)"', tag)
                    if n and ('type="hidden"' in tag or 'type="submit"' in tag):
                        data[n.group(1)] = html.unescape(v.group(1)) if v else ""
            page, url = self.request("POST", action, data=data)
        return page, url


def _jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# ---------------------------------------------------------------------------------------------- layer 4: network


def test_container_has_no_route_to_llm_providers_but_reaches_gateway(oc: Exec) -> None:
    """Concept section 10, layer 4: `curl api.openai.com` fails, the gateway answers."""
    for url in ("https://api.openai.com", "https://generativelanguage.googleapis.com", "https://api.anthropic.com"):
        r = oc.curl("-o", "/dev/null", "-w", "%{http_code}", url, timeout=8)
        assert r.returncode != 0, f"{url} must be unreachable from the locked container (got HTTP {r.stdout})"
    # not even by IP literal (an internal network has no gateway route)
    assert oc.curl("-o", "/dev/null", "https://1.1.1.1", timeout=8).returncode != 0
    # the exfiltration target from the poisoned README is on another network
    assert oc.curl("http://attacker-sink:8080/healthz", timeout=8).returncode != 0

    r = oc.curl("-o", "/dev/null", "-w", "%{http_code}", "http://gateway:8000/healthz", timeout=10)
    assert r.returncode == 0 and r.stdout.strip() == "200", (
        "gateway not reachable from the OpenCode container: attach the gateway service to the "
        "`acl-clients-internal` network with alias `gateway` (deploy/compose.clients.yml header)"
    )


def test_idp_gate_exposes_only_device_and_token_endpoints(oc: Exec) -> None:
    base = "http://keycloak:8080/realms/acl"
    for path in ("/.well-known/openid-configuration", "/protocol/openid-connect/certs", "/account/"):
        r = oc.curl("-o", "/dev/null", "-w", "%{http_code}", base + path)
        assert r.stdout.strip() == "403", f"{path} must be refused by idp-gate, got {r.stdout!r}"
    assert (
        oc.curl("-o", "/dev/null", "-w", "%{http_code}", "http://keycloak:8080/admin/master/console/").stdout.strip()
        == "403"
    )
    assert (
        oc.curl("-o", "/dev/null", "-w", "%{http_code}", f"{base}/protocol/openid-connect/token").stdout.strip()
        == "403"
    )  # GET
    r = oc.curl(
        "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "-d", "client_id=opencode",
        f"{base}/protocol/openid-connect/auth/device",
    )  # fmt: skip
    assert r.stdout.strip() == "200"


# ------------------------------------------------------------------------------ layer 3: container + config


def test_container_is_locked_down(oc: Exec) -> None:
    assert oc.run("id", "-u").stdout.strip() not in ("", "0"), "must not run as root"
    for target in (
        "/etc/opencode/opencode.json",
        "/etc/opencode/evil.json",
        "/usr/local/bin/opencode",
        "/opt/opencode-guard/dist/index.js",
    ):
        r = oc.sh(f"echo x >> {target}")
        assert r.returncode != 0, f"{target} must not be writable"
    assert oc.sh("touch /usr/lib/x").returncode != 0, "root filesystem must be read-only"
    assert oc.sh("touch /workspace/.write-test && rm /workspace/.write-test").returncode == 0, (
        "workspace volume must be writable"
    )
    # the canary the poisoned README points at is present (so the demo is meaningful) but is not a real key
    key = oc.sh("cat /home/dev/.ssh/id_rsa").stdout
    assert CANARY in key
    assert "payments-cli" in oc.sh("cat /workspace/demo-repo/README.md").stdout
    assert "~/.ssh/id_rsa" in oc.sh("cat /workspace/demo-repo/README.md").stdout, "the poisoned README must be in place"


def test_managed_config_matches_concept_5_1(oc: Exec) -> None:
    cfg = json.loads(oc.sh("cat /etc/opencode/opencode.json").stdout)
    assert cfg["enabled_providers"] == ["company"]
    assert list(cfg["provider"]) == ["company"]
    company = cfg["provider"]["company"]
    assert company["npm"] == "@ai-sdk/openai-compatible"
    assert company["options"]["baseURL"] == "http://gateway:8000/v1"
    assert {"auto", "local-coder"} <= set(company["models"])
    assert cfg["model"] == "company/auto"
    assert cfg["share"] == "disabled"
    assert cfg["autoupdate"] is False
    assert cfg["permission"]["webfetch"] == "deny"
    assert cfg["plugin"] == ["file:///opt/opencode-guard"]
    assert cfg["mcp"], "fixed MCP list expected"
    for name, server in cfg["mcp"].items():
        assert server["url"] == f"http://gateway:8000/mcp/{name}", "MCP servers must point at the gateway proxy"
        assert "headers" not in server, "no static credentials in the managed config"
    assert not any(k in json.dumps(cfg).lower() for k in ("apikey", "api_key", "secret", "token"))


# ---------------------------------------------------------------------------------------------- real OpenCode


class OpenCodeServer:
    """The real OpenCode server inside the container (the TUI is a client of this same server)."""

    def __init__(self, oc: Exec, port: int) -> None:
        self.oc, self.port = oc, port

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def call(self, method: str, path: str, body: object | None = None, timeout: float = 120) -> object:
        args = ["-X", method, "-H", "content-type: application/json"]
        if body is not None:
            args += ["-d", json.dumps(body)]
        r = self.oc.curl(*args, self.base + path, timeout=timeout)
        assert r.returncode == 0, f"opencode server call failed: {r.stderr[:200]}"
        try:
            return json.loads(r.stdout)
        except ValueError:
            return r.stdout

    def login(self, username: str) -> None:
        """Company SSO device-code login, with Keycloak's verification page approved by a scripted browser."""
        started = self.call("POST", "/provider/company/oauth/authorize", {"method": 0}, timeout=30)
        assert isinstance(started, dict) and "user_code=" in started["url"], f"unexpected authorize result: {started!r}"
        assert started["method"] == "auto"
        assert urlsplit(started["url"]).netloc.startswith("localhost:"), "verification URL must be browser-reachable"
        result: dict[str, object] = {}
        t = threading.Thread(
            target=lambda: result.setdefault(
                "cb", self.call("POST", "/provider/company/oauth/callback", {"method": 0}, timeout=100)
            )
        )
        t.start()
        browser = MiniBrowser()
        try:
            page, url = browser.request("GET", started["url"])
            page, _ = browser.keycloak_login(page, url, username)
            assert "Successful" in re.sub(r"<[^>]+>", " ", page.text), "device login was not confirmed by Keycloak"
        finally:
            browser.close()
        t.join(60)
        assert result.get("cb") is True, f"opencode did not complete the login (callback returned {result.get('cb')!r})"

    def chat(self, prompt: str, model: str = "auto") -> list[dict]:
        sess = self.call("POST", "/session", {"title": "e2e"})
        assert isinstance(sess, dict)
        self.call(
            "POST",
            f"/session/{sess['id']}/message",
            {"model": {"providerID": "company", "modelID": model}, "parts": [{"type": "text", "text": prompt}]},
            timeout=150,
        )
        msgs = self.call("GET", f"/session/{sess['id']}/message")
        assert isinstance(msgs, list)
        return msgs

    @staticmethod
    def tool_parts(msgs: list[dict]) -> list[dict]:
        return [p for m in msgs for p in m.get("parts", []) if p.get("type") == "tool"]

    @staticmethod
    def texts(msgs: list[dict]) -> str:
        return "\n".join(p.get("text", "") for m in msgs for p in m.get("parts", []) if p.get("type") == "text")


@pytest.fixture(scope="module")
def opencode(oc: Exec, stack: Stack) -> OpenCodeServer:
    """`opencode serve` in the container, logged in as jan through the real device-code flow."""
    server = OpenCodeServer(oc, OPENCODE_PORT)
    oc.sh("pkill -f 'opencode serve' || true")
    subprocess.Popen(
        [
            "docker",
            "exec",
            oc.name,
            "sh",
            "-c",
            f"opencode serve --hostname 127.0.0.1 --port {OPENCODE_PORT} > /tmp/serve.log 2>&1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        r = oc.curl(f"http://127.0.0.1:{OPENCODE_PORT}/provider/auth", timeout=10)
        if r.returncode == 0 and "company" in r.stdout:
            break
        time.sleep(2)
    else:
        pytest.fail("opencode serve did not come up inside the container")
    server.login("jan")
    yield server
    oc.sh("pkill -f 'opencode serve' || true")


def test_device_login_stores_a_gateway_audience_token_and_model_calls_are_attributed(
    opencode: OpenCodeServer, oc: Exec, stack: Stack
) -> None:
    # the stored credential: a Keycloak token for jan, issued to client `opencode`, audience `gateway` (never printed)
    raw = oc.sh("cat /state/data/opencode/auth.json").stdout
    entry = json.loads(raw)["company"]
    claims = _jwt_claims(entry["access"])
    assert claims["azp"] == "opencode" and claims["preferred_username"] == "jan"
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    assert "gateway" in aud
    assert entry["refresh"], "a refresh token is stored so the loader can renew the session"

    token = f"{uuid.uuid4().hex[:8]}"
    msgs = opencode.chat(f"hello {token}")
    reply = opencode.texts(msgs)
    assert token in reply, f"no model answer through the gateway: {reply[:200]!r}"

    # the gateway authenticated the request as jan (session ids are principal-namespaced and carry the OpenCode id)
    events = stack.admin("GET", "/events?limit=20").json()
    mine = [
        e
        for e in events
        if e.get("username") == "jan" and (e.get("session_id") or "").split(":")[-1].startswith("ses_")
    ]
    assert mine, "no audit event attributed to jan with an OpenCode session id"


def test_poisoned_readme_read_of_ssh_key_is_not_executed(opencode: OpenCodeServer, stack: Stack) -> None:
    """The mock model asks OpenCode to read ~/.ssh/id_rsa; the guard must stop it (rule id once /v1/decide is live)."""
    msgs = opencode.chat('[[mock:tool read {"filePath":"/home/dev/.ssh/id_rsa"}]]')
    parts = opencode.tool_parts(msgs)
    if not parts:
        pytest.skip("mock tool directive not honoured (gateway is not in deterministic mode)")
    part = parts[0]
    assert part["tool"] == "read"
    state = part["state"]
    assert state["status"] == "error", "the read of ~/.ssh/id_rsa must not complete"
    assert CANARY not in json.dumps(msgs), "canary content reached the model/transcript"
    message = state.get("error", "")
    if _decide_implemented(stack):
        assert RULE_ID_IN_MESSAGE.search(message), f"block message must name the rule id: {message!r}"
    else:
        assert "blocked" in message.lower(), (
            f"fail-closed message expected while /v1/decide is not implemented: {message!r}"
        )


def _decide_implemented(stack: Stack) -> bool:
    r = stack.http.post(
        f"{stack.cfg.gateway}/v1/decide",
        json={
            "session_id": "probe",
            "action": {"tool": "opencode.read", "arguments": {"filePath": "/workspace/demo-repo/README.md"}},
        },
        headers=stack.auth("anna"),
    )
    return r.status_code != 501


def test_plugin_decide_request_for_forbidden_read_is_blocked_with_rule_id(stack: Stack) -> None:
    """Drives /v1/decide exactly as the plugin does (same body, bearer token, attribution headers)."""
    body = {
        "session_id": f"ses_e2e_{uuid.uuid4().hex[:8]}",
        "action": {
            "kind": "tool_call",
            "tool": "opencode.read",
            "arguments": {"filePath": "/home/dev/.ssh/id_rsa"},
            "tool_call_id": "call_e2e_1",
            "cwd": "/workspace/demo-repo",
            "workspace_root": "/workspace/demo-repo",
        },
        "client": {"app": "opencode", "version": "opencode-1.18.34", "device_id": "dev-e2e-0001"},
    }
    headers = {**stack.auth("anna"), "X-Device-Id": "dev-e2e-0001", "X-Client-App": "opencode"}
    r = stack.http.post(f"{stack.cfg.gateway}/v1/decide", json=body, headers=headers)
    if r.status_code == 501:
        pytest.skip("/v1/decide is not implemented yet (Phase 2B); the plugin fails closed meanwhile (covered above)")
    assert r.status_code == 200, f"/v1/decide: HTTP {r.status_code}"
    decision = r.json()
    assert decision["action"] not in ("allow", "monitor", "redact"), (
        f"read of ~/.ssh/id_rsa must not be allowed: {decision['action']}"
    )
    assert decision["rule_ids"], "a blocking decision must carry rule ids"
    assert all(RULE_ID_IN_MESSAGE.fullmatch(f"[{rid}]") for rid in decision["rule_ids"])

    ok = {
        **body,
        "action": {
            **body["action"],
            "arguments": {"filePath": "/workspace/demo-repo/README.md"},
            "tool_call_id": "call_e2e_2",
        },
    }
    r2 = stack.http.post(f"{stack.cfg.gateway}/v1/decide", json=ok, headers=headers)
    assert r2.status_code == 200 and r2.json()["action"] in ("allow", "monitor"), (
        "reading a file in the workspace is allowed"
    )


def test_fail_closed_without_credentials(stack: Stack) -> None:
    """No/invalid bearer token at /v1/decide: never a 200 'allow' (the plugin treats any non-200 as blocked)."""
    body = {"session_id": "s", "action": {"tool": "opencode.read", "arguments": {}}}
    assert stack.http.post(f"{stack.cfg.gateway}/v1/decide", json=body).status_code == 401
    r = stack.http.post(f"{stack.cfg.gateway}/v1/decide", json=body, headers={"Authorization": "Bearer not-a-token"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------------------------- LibreChat


def test_librechat_oidc_discovery_and_redirect_go_to_keycloak(librechat_up: None, stack: Stack) -> None:
    disc = httpx.get(f"{stack.cfg.keycloak}/realms/acl/.well-known/openid-configuration", timeout=10).json()
    assert disc["issuer"] == f"{stack.cfg.keycloak}/realms/acl"
    r = httpx.get(
        f"{LIBRECHAT_URL}/oauth/openid", follow_redirects=False, timeout=10, headers={"User-Agent": BROWSER_UA}
    )
    assert r.status_code in (301, 302, 303, 307), f"LibreChat should redirect to Keycloak, got HTTP {r.status_code}"
    target = urlsplit(r.headers["location"])
    assert f"{target.scheme}://{target.netloc}" == stack.cfg.keycloak
    assert target.path == "/realms/acl/protocol/openid-connect/auth"
    query = dict(p.split("=", 1) for p in target.query.split("&"))
    assert query["client_id"] == "librechat"
    assert "localhost%3A3080%2Foauth%2Fopenid%2Fcallback" in query["redirect_uri"]
    assert query.get("code_challenge_method") == "S256"
    # email/password registration is off: Keycloak is the only way in
    cfg = httpx.get(f"{LIBRECHAT_URL}/api/config", timeout=10, headers={"User-Agent": BROWSER_UA}).json()
    assert cfg.get("openidLoginEnabled") is True
    assert not cfg.get("emailLoginEnabled") and not cfg.get("registrationEnabled")


class LibreChatSession:
    def __init__(self, username: str) -> None:
        self.browser = MiniBrowser()
        page, url = self.browser.request("GET", f"{LIBRECHAT_URL}/oauth/openid")
        page, url = self.browser.keycloak_login(page, url, username)
        assert urlsplit(url).netloc == "localhost:3080" and "error=" not in url, f"LibreChat login failed: {url}"
        r, _ = self.browser.request("POST", f"{LIBRECHAT_URL}/api/auth/refresh")
        assert r.status_code == 200, f"no LibreChat session after OIDC login (HTTP {r.status_code})"
        self.auth = r.json()
        self.headers = {"Authorization": f"Bearer {self.auth['token']}"}

    def get(self, path: str) -> httpx.Response:
        return self.browser.request("GET", f"{LIBRECHAT_URL}{path}", headers=self.headers)[0]

    def close(self) -> None:
        self.browser.close()


@pytest.fixture
def lc_login(librechat_up: None):  # type: ignore[no-untyped-def]
    sessions: list[LibreChatSession] = []

    def login(username: str) -> LibreChatSession:
        s = LibreChatSession(username)
        sessions.append(s)
        return s

    yield login
    for s in sessions:
        s.close()


def test_librechat_login_via_keycloak(lc_login) -> None:  # type: ignore[no-untyped-def]
    s = lc_login("jan")
    assert s.auth["user"]["provider"] == "openid"
    assert s.auth["user"]["email"] == "jan.kowalski@corp.example"
    assert list(s.get("/api/endpoints").json()) == ["Company AI"], "the gateway must be the only endpoint"


def test_librechat_forwards_each_users_own_token_so_model_lists_are_personalised(lc_login, stack: Stack) -> None:  # type: ignore[no-untyped-def]
    """LibreChat -> gateway uses the signed-in user's OIDC access token (OPENID_REUSE_TOKENS +
    `Authorization: Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}`), proven by /v1/models being per-user."""
    seen: dict[str, list[str]] = {}
    for user in ("jan", "anna"):
        s = lc_login(user)
        models = s.get("/api/models").json()["Company AI"]
        expected = [
            m["id"] for m in stack.http.get(f"{stack.cfg.gateway}/v1/models", headers=stack.auth(user)).json()["data"]
        ]
        assert models == expected, f"{user}: LibreChat shows {models}, the gateway offers {expected}"
        seen[user] = models
    assert seen["jan"] != seen["anna"], "different groups must see different model lists"


def test_librechat_chat_reaches_the_gateway_as_the_signed_in_user(lc_login, stack: Stack) -> None:  # type: ignore[no-untyped-def]
    s = lc_login("jan")
    marker = uuid.uuid4().hex[:10]
    payload = {
        "text": f"ping {marker}",
        "endpoint": "Company AI",
        "endpointType": "custom",
        "model": "auto",
        "conversationId": "new",
        "parentMessageId": "00000000-0000-0000-0000-000000000000",
        "messageId": str(uuid.uuid4()),
        "isTemporary": True,
    }
    r, _ = s.browser.request(
        "POST",
        f"{LIBRECHAT_URL}/api/agents/chat/Company%20AI",
        headers=s.headers | {"content-type": "application/json"},
        content=json.dumps(payload),
    )
    assert r.status_code == 200, f"chat request refused: HTTP {r.status_code}"
    conversation = r.json()["conversationId"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        events = stack.admin("GET", "/events?limit=30").json()
        if any(e.get("username") == "jan" and (e.get("session_id") or "").endswith(conversation) for e in events):
            return
        time.sleep(1)
    pytest.fail("no audit event attributed to jan for the LibreChat conversation (token not forwarded?)")
