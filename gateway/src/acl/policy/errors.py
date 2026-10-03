"""Errors raised by the policy service; the admin router maps them to `ErrorResponse` bodies."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from acl.contracts.admin import ErrorResponse, PolicyError
from acl.policy.locks import LockViolation


class PolicyServiceError(Exception):
    status_code = 500
    code = "policy_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def details(self) -> dict[str, object]:
        return {}


class InvalidFileName(PolicyServiceError):
    status_code = 422
    code = "invalid_file_name"

    def __init__(self, name: str) -> None:
        super().__init__("policy file names must match ^[a-z0-9_-]+\\.yaml$")
        self.name = name


class FileNotFound(PolicyServiceError):
    status_code = 404
    code = "not_found"

    def __init__(self, what: str) -> None:
        super().__init__(f"{what} not found")


class StaleVersion(PolicyServiceError):
    status_code = 409
    code = "stale_version"

    def __init__(self, name: str, current: str) -> None:
        super().__init__(f"{name} changed since version {current[:12]} was read; reload and re-apply your edit")
        self.name = name
        self.current = current

    def details(self) -> dict[str, object]:
        return {"file": self.name, "current_version": self.current}


class ValidationFailed(PolicyServiceError):
    status_code = 422
    code = "validation_failed"

    def __init__(self, errors: list[PolicyError]) -> None:
        super().__init__(f"policy is invalid ({len(errors)} error{'s' if len(errors) != 1 else ''})")
        self.errors = errors

    def details(self) -> dict[str, object]:
        return {"errors": [e.model_dump(mode="json") for e in self.errors]}


class LockedControl(PolicyServiceError):
    status_code = 422
    code = "locked_control"

    def __init__(self, violations: list[LockViolation]) -> None:
        super().__init__(
            "locked controls cannot be disabled, removed or changed from the panel: " + "; ".join(map(str, violations))
        )
        self.violations = violations

    def details(self) -> dict[str, object]:
        return {"violations": [v.as_dict() for v in self.violations]}


class Unavailable(PolicyServiceError):
    status_code = 503
    code = "unavailable"


async def handle_policy_error(_request: Request, exc: Exception) -> JSONResponse:
    """FastAPI exception handler: `PolicyServiceError` -> `ErrorResponse` with its HTTP status."""
    assert isinstance(exc, PolicyServiceError)
    body = ErrorResponse(error=exc.code, message=exc.message, details=exc.details())
    return JSONResponse(status_code=exc.status_code, content=body.model_dump(mode="json"))
