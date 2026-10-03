"""Test helpers for identity: throwaway RSA/EC keys, JWKS documents, signed tokens, policy patching.

Used by the gateway unit tests (`gateway/tests/test_1c_*.py`) and e2e fixtures. Nothing here is used at runtime.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from acl.policy.loader import load_policy_dir
from acl.policy.models import Policy

ISSUER = "http://kc.test/realms/acl"
AUDIENCE = "gateway"


@dataclass
class TestKey:
    """A signing key pair plus its JWKS entry."""

    __test__ = False  # not a pytest class

    kid: str
    alg: str = "RS256"
    private: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.private is None:
            self.private = (
                ec.generate_private_key(ec.SECP256R1())
                if self.alg == "ES256"
                else rsa.generate_private_key(public_exponent=65537, key_size=2048)
            )

    @property
    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def jwk(self) -> dict[str, Any]:
        algo = ECAlgorithm(ECAlgorithm.SHA256) if self.alg == "ES256" else RSAAlgorithm(RSAAlgorithm.SHA256)
        data = json.loads(algo.to_jwk(self.private.public_key()))
        data.update({"kid": self.kid, "use": "sig", "alg": self.alg})
        return data

    def sign(self, claims: dict[str, Any], *, kid: str | None = None, alg: str | None = None) -> str:
        return jwt.encode(claims, self.private, algorithm=alg or self.alg, headers={"kid": kid or self.kid})


def jwks_document(*keys: TestKey, extra: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"keys": [k.jwk() for k in keys] + list(extra or [])}


def claims(
    sub: str = "user-1",
    *,
    username: str = "anna",
    groups: list[str] | None = None,
    roles: list[str] | None = None,
    issuer: str = ISSUER,
    audience: str | list[str] = AUDIENCE,
    azp: str = "opencode",
    exp_in: float = 900,
    nbf_in: float | None = None,
    now: float | None = None,
    **extra: Any,
) -> dict[str, Any]:
    t = now if now is not None else time.time()
    out: dict[str, Any] = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "azp": azp,
        "iat": int(t),
        "exp": int(t + exp_in),
        "preferred_username": username,
        "groups": ["/developers"] if groups is None else groups,
        "realm_access": {"roles": ["acl-user"] if roles is None else roles},
    }
    if nbf_in is not None:
        out["nbf"] = int(t + nbf_in)
    out.update(extra)
    return out


def unsigned_token(payload: dict[str, Any]) -> str:
    """A syntactically valid JWT with `alg: none` (must always be rejected)."""

    def b64(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(payload)}."


# ---------------------------------------------------------------- policy helpers


def load_repo_policy(policy_dir: Path) -> Policy:
    return load_policy_dir(policy_dir).policy


def patch_policy(policy: Policy, patch: Callable[[dict[str, Any]], None]) -> Policy:
    """Round-trip the policy through a dict, let `patch` mutate it, validate again."""
    data = policy.model_dump(by_alias=True, mode="json")
    patch(data)
    return Policy.model_validate(data)


class FakeClock:
    """Shared, manually advanced clock for deterministic expiry tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self.t = start or datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
        self.mono = 0.0

    def now(self) -> datetime:
        return self.t

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)
        self.mono += seconds
