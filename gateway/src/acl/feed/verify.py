"""Signature-bundle verification (contract: `acl.contracts.feed`).

The digest is `sha256(canonical_json(bundle without "signature"))`, computed over the *received* JSON
(not a re-serialised model), so server and gateway agree byte-for-byte.

* `sha256`: `signature.value` is the hex digest (integrity only).
* `ed25519`: `signature.value` is the base64 signature over `canonical_json(bundle without "signature")`
  (UTF-8), verified against the configured public key (base64 raw 32 bytes, hex, or PEM/DER SPKI).

The configured mode (`signatures.feed.verify`) must equal the bundle's `alg`: a bundle cannot downgrade
the verification the operator asked for.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
from pydantic import ValidationError

from acl.contracts.canonical import bundle_digest, canonical_json
from acl.contracts.feed import FeedBundle


class FeedVerifyError(Exception):
    """Verification failed. `code` is stable and value-free (it ends up in audit events)."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def parse_public_key(value: str) -> Ed25519PublicKey:
    v = value.strip()
    try:
        if "BEGIN PUBLIC KEY" in v:
            key = load_pem_public_key(v.encode())
        else:
            if re.fullmatch(r"[0-9a-fA-F]{64}", v):  # 64 hex chars are also valid base64: hex wins
                raw = bytes.fromhex(v)
            else:
                try:
                    raw = base64.b64decode(v, validate=True)
                except (binascii.Error, ValueError):
                    raw = bytes.fromhex(v)
            key = Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32 else load_der_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise FeedVerifyError("bad_public_key", "feed public key is not a valid Ed25519 key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise FeedVerifyError("bad_public_key", "feed public key is not an Ed25519 key")
    return key


def verify_bundle(raw: Mapping[str, Any], *, mode: str = "sha256", public_key: str | None = None) -> FeedBundle:
    """Validate schema + integrity/authenticity; returns the parsed bundle or raises `FeedVerifyError`."""
    try:
        bundle = FeedBundle.model_validate(raw)
    except ValidationError as exc:
        raise FeedVerifyError("schema", "bundle does not match the feed schema") from exc
    sig = bundle.signature
    if sig.alg != mode:
        raise FeedVerifyError("alg_mismatch", f"bundle signed with {sig.alg}, policy requires {mode}")
    if mode == "sha256":
        if not hmac.compare_digest(sig.value.lower(), bundle_digest(dict(raw))):
            raise FeedVerifyError("digest_mismatch", "bundle digest does not match its content")
        return bundle
    if not public_key:
        raise FeedVerifyError("no_public_key", "ed25519 verification needs signatures.feed.public_key")
    key = parse_public_key(public_key)
    body = {k: v for k, v in raw.items() if k != "signature"}
    try:
        key.verify(base64.b64decode(sig.value, validate=True), canonical_json(body).encode("utf-8"))
    except (InvalidSignature, binascii.Error, ValueError) as exc:
        raise FeedVerifyError("bad_signature", "ed25519 signature check failed") from exc
    return bundle
