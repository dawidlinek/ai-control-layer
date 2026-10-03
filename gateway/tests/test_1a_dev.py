"""1A: dev-only principal override helper and the mock directive grammar."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI
from starlette.requests import Request

from acl.api.dev_principal import dev_principal_from_headers
from acl.routing.connectors.mock import MockConnector


def _request(app: Any, headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "app": app,
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


def test_dev_principal_headers_only_in_dev_mode() -> None:
    app = FastAPI()
    hdrs = {"X-ACL-Dev-User": "anna", "X-ACL-Dev-Groups": "developers, admins", "X-ACL-Dev-Roles": "acl-analyst"}
    app.state.allow_anonymous_dev = False
    assert dev_principal_from_headers(_request(app, hdrs)) is None  # production: never
    app.state.allow_anonymous_dev = True
    p = dev_principal_from_headers(_request(app, hdrs))
    assert p is not None and p.username == "anna" and p.groups == ["developers", "admins"]
    assert p.roles == ["acl-analyst"]
    assert dev_principal_from_headers(_request(app, {**hdrs, "Authorization": "Bearer x"})) is None
    assert dev_principal_from_headers(_request(app, {})) is None


async def test_mock_directive_arguments_may_contain_brackets() -> None:
    out = await MockConnector().chat(
        "m", {"messages": [{"role": "user", "content": '[[mock:tool x {"a": [1,2]}]]'}]}
    )
    call = out.body["choices"][0]["message"]["tool_calls"][0]
    assert json.loads(call["function"]["arguments"]) == {"a": [1, 2]}
