"""Canonical JSON + hashing rules shared by the audit chain and feed bundles (contract)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from pydantic import BaseModel


def canonical_json(obj: Any) -> str:
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json", by_alias=True)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def audit_record_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """sha256(prev_hash + "\\n" + canonical_json(record minus "hash"))."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256((prev_hash + "\n" + canonical_json(body)).encode("utf-8")).hexdigest()


def bundle_digest(bundle: dict[str, Any]) -> str:
    """sha256 over canonical_json(bundle minus "signature")."""
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def value_hash(value: str, salt: str, length: int = 16) -> str:
    """Salted (HMAC-SHA256) hash of a sensitive value, truncated; for correlation in logs only."""
    return hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:length]
