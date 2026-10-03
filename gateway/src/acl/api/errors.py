"""OpenAI-style errors for the `/v1` gateway routes.

{"error": {"message": ..., "type": "policy_violation", "code": "<rule id>", "trace_id": ...}}

Request-validation errors also carry `param` (the offending request field), as OpenAI does:
{"error": {"type": "invalid_request_error", "code": "unsupported_parameter", "param": "prediction", ...}}
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class GatewayError(Exception):
    def __init__(
        self,
        status: int,
        type_: str,
        message: str,
        *,
        code: str | None = None,
        trace_id: str | None = None,
        headers: dict[str, str] | None = None,
        param: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.type = type_
        self.message = message
        self.code = code
        self.trace_id = trace_id
        self.headers = headers or {}
        self.param = param

    def body(self) -> dict[str, Any]:
        return error_body(self.message, self.type, self.code, self.trace_id, param=self.param)


def error_body(
    message: str, type_: str, code: str | None, trace_id: str | None, *, param: str | None = None
) -> dict[str, Any]:
    err: dict[str, Any] = {"message": message, "type": type_, "code": code, "trace_id": trace_id}
    if param is not None:
        err["param"] = param
    return {"error": err}


async def _handle(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, GatewayError)
    headers = dict(exc.headers)
    if exc.trace_id:
        headers.setdefault("x-acl-trace-id", exc.trace_id)
    return JSONResponse(exc.body(), status_code=exc.status, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(GatewayError, _handle)
