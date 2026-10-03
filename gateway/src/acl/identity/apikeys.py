"""Personal API keys: `acl_<8-char prefix>_<secret>`. Only HMAC-SHA256(pepper, key) and the prefix are stored."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from acl.contracts.admin import ApiKey, ApiKeyCreated
from acl.contracts.common import AuthMethod, PrincipalKind
from acl.contracts.inspection import Principal
from acl.identity.db_models import ApiKeyRow, UserRow, utcnow
from acl.identity.tokens import AuthError
from acl.identity.users import SessionMaker

KEY_PREFIX = "acl"
LAST_USED_RESOLUTION = timedelta(seconds=30)  # avoid a DB write on every request


def looks_like_api_key(token: str) -> bool:
    return token.startswith(f"{KEY_PREFIX}_")


def parse_key(token: str) -> tuple[str, str] | None:
    """`acl_<prefix>_<secret>` → (prefix, secret); None when the shape is wrong."""
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != KEY_PREFIX or len(parts[1]) != 8 or not parts[2]:
        return None
    return parts[1], parts[2]


def generate_key() -> tuple[str, str]:
    prefix = secrets.token_hex(4)
    return prefix, f"{KEY_PREFIX}_{prefix}_{secrets.token_urlsafe(32)}"


def hash_key(pepper: bytes, key: str) -> str:
    return hmac.new(pepper, key.encode("utf-8"), hashlib.sha256).hexdigest()


def key_from_row(row: ApiKeyRow) -> ApiKey:
    return ApiKey(
        id=row.id,
        user_id=row.user_id,
        name=row.name,
        prefix=f"{KEY_PREFIX}_{row.prefix}",
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
    )


class ApiKeyService:
    def __init__(self, sessions: SessionMaker, pepper: bytes) -> None:
        self._sessions = sessions
        self._pepper = pepper

    async def create(self, user: UserRow, name: str, expires_at: datetime | None) -> ApiKeyCreated:
        for _ in range(5):
            prefix, key = generate_key()
            row = ApiKeyRow(
                id=str(uuid.uuid4()),
                user_id=user.id,
                name=name,
                prefix=prefix,
                key_hash=hash_key(self._pepper, key),
                created_at=utcnow(),
                expires_at=expires_at,
            )
            try:
                async with self._sessions()() as s, s.begin():
                    s.add(row)
            except IntegrityError:  # prefix collision (vanishingly rare): draw again
                continue
            return ApiKeyCreated(**key_from_row(row).model_dump(), key=key)
        raise RuntimeError("could not allocate an API key prefix")

    async def list_for_user(self, user_id: str) -> list[ApiKey]:
        async with self._sessions()() as s:
            rows = (
                await s.execute(select(ApiKeyRow).where(ApiKeyRow.user_id == user_id).order_by(ApiKeyRow.created_at))
            ).scalars()
            return [key_from_row(r) for r in rows]

    async def revoke(self, key_id: str) -> ApiKeyRow | None:
        async with self._sessions()() as s, s.begin():
            row = await s.get(ApiKeyRow, key_id)
            if row is None:
                return None
            if row.revoked_at is None:
                row.revoked_at = utcnow()
            return row

    async def authenticate(self, token: str) -> tuple[Principal, ApiKeyRow]:
        """Resolve a presented key to its owner. Raises AuthError with a stable reason code."""
        parsed = parse_key(token)
        if parsed is None:
            raise AuthError("malformed_api_key")
        prefix, _secret = parsed
        presented = hash_key(self._pepper, token)
        async with self._sessions()() as s, s.begin():
            row = (await s.execute(select(ApiKeyRow).where(ApiKeyRow.prefix == prefix))).scalar_one_or_none()
            # Always compare something, so unknown prefixes and wrong secrets cost the same.
            expected = row.key_hash if row is not None else hash_key(self._pepper, "unknown-prefix")
            if not hmac.compare_digest(presented, expected) or row is None:
                raise AuthError("invalid_api_key")
            now = utcnow()
            if row.revoked_at is not None:
                raise AuthError("api_key_revoked")
            if row.expires_at is not None and row.expires_at <= now:
                raise AuthError("api_key_expired")
            user = await s.get(UserRow, row.user_id)
            if user is None or user.disabled:
                raise AuthError("account_disabled")
            if row.last_used_at is None or now - row.last_used_at >= LAST_USED_RESOLUTION:
                row.last_used_at = now
            principal = Principal(
                subject=user.subject,
                kind=PrincipalKind(user.kind),
                username=user.username,
                groups=list(user.groups or []),
                roles=list(user.roles or []),
                auth_method=AuthMethod.api_key,
                api_key_id=row.id,
            )
            return principal, row
