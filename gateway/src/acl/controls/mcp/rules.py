"""Deterministic MCP protocol checks shared by SEC-MCP-02 and the proxy pre-flight (no I/O, value-free results).

* `check_headers`    MCP 2026-07-28 `Mcp-Method` / `Mcp-Name` headers must agree with the JSON-RPC body: a mismatch is
                     an attack signal (route/pre-check on headers, execute the body).
* `oauth_url_problem` OAuth metadata URLs advertised by a server: https only, no shell metacharacters, no userinfo
                     (CVE-2025-6514, mcp-remote command injection).
* `find_oauth_urls`  every OAuth-ish URL inside a params/metadata object.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

HEADER_METHOD = "mcp-method"
HEADER_NAME = "mcp-name"

# methods whose JSON-RPC params carry the name that `Mcp-Name` mirrors
NAME_KEYS: dict[str, str] = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

OAUTH_KEYS = frozenset(
    {
        "resource_metadata",
        "resource_metadata_url",
        "oauth_metadata_url",
        "authorization_server",
        "authorization_servers",
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "device_authorization_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "issuer",
    }
)

_SHELL_META = re.compile(r"[;|&$`<>(){}\\'\"\s\x00-\x1f\x7f]")
_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})


@dataclass(frozen=True, slots=True)
class Violation:
    code: str  # stable identifier, also used as the finding entity type
    reason: str  # value-free explanation


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def check_headers(method: str, params: Mapping[str, Any] | None, headers: Mapping[str, str]) -> list[Violation]:
    h = _lower_headers(headers)
    out: list[Violation] = []
    claimed_method = h.get(HEADER_METHOD)
    if claimed_method is not None and claimed_method != method:
        out.append(Violation("MCP_HEADER_MISMATCH", "Mcp-Method header does not match the JSON-RPC method"))
    claimed_name = h.get(HEADER_NAME)
    key = NAME_KEYS.get(method)
    if claimed_name is not None:
        body_name = (params or {}).get(key) if key else None
        if not isinstance(body_name, str) or body_name != claimed_name:
            out.append(Violation("MCP_HEADER_MISMATCH", "Mcp-Name header does not match the JSON-RPC params"))
    return out


def oauth_url_problem(url: Any, *, allow_http_localhost: bool = False) -> str | None:
    """Why `url` must not be used as an OAuth metadata URL (stable code), or None when acceptable."""
    if not isinstance(url, str) or not url:
        return "not_a_string"
    if len(url) > 2048:
        return "too_long"
    for candidate in (url, unquote(url)):
        if _SHELL_META.search(candidate):
            return "shell_metacharacters"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "unparsable"
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme != "https" and not (allow_http_localhost and scheme == "http" and host in _LOCAL_HOSTS):
        return "scheme_not_https"
    if not host or not (_HOST.match(host) or host in _LOCAL_HOSTS or re.fullmatch(r"[0-9a-f:.]+", host)):
        return "bad_host"
    if parts.username or parts.password:
        return "userinfo"
    return None


def find_oauth_urls(node: Any, depth: int = 0) -> Iterator[tuple[str, Any]]:
    """(key, value) pairs of OAuth-related URL fields anywhere inside a mapping / list (strings only)."""
    if depth > 8:
        return
    if isinstance(node, Mapping):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in OAUTH_KEYS:
                if isinstance(v, list):
                    for item in v:
                        yield k, item
                else:
                    yield k, v
            else:
                yield from find_oauth_urls(v, depth + 1)
    elif isinstance(node, list):
        for item in node:
            yield from find_oauth_urls(item, depth + 1)


def check_oauth(params: Mapping[str, Any] | None, *, allow_http_localhost: bool = False) -> list[Violation]:
    out: list[Violation] = []
    for key, value in find_oauth_urls(params or {}):
        problem = oauth_url_problem(value, allow_http_localhost=allow_http_localhost)
        if problem:
            out.append(Violation("MCP_OAUTH_URL", f"OAuth metadata field '{key}' rejected: {problem}"))
    return out
