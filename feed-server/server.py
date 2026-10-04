"""Stand-in for the external signature system (concept §9.2). Stdlib only, so the container needs no packages.

Serving
    GET  /healthz            liveness
    GET  /bundle.json        the highest-version bundle, signed on the fly
    GET  /bundle.sha256      the bundle's signature value
    GET  /entries            entries of the current bundle (read-only listing)

Live editing (demo: "a judge adds a rule and the very next request is blocked")
    POST   /entries          upsert one entry (object), a list, or {"entries": [...]} → writes a new bundle with
                             bundle_version = highest + 1.  Header: `Authorization: Bearer $FEED_ADMIN_TOKEN`
    DELETE /entries/{id}     remove an entry the same way
    Without FEED_ADMIN_TOKEN both answer 403 (editing disabled).

Bundles are JSON files: `bundles/*.json` (read-only seed, shipped in the image) plus `$STATE_DIR/*.json`
(live edits, writable volume). The server picks the highest `bundle_version` of all files.

Signing
    default                  alg `sha256` over canonical JSON (checksum: integrity, not authenticity)
    FEED_SIGNING_KEY=<32-byte seed, base64 or hex>   alg `ed25519` (pure-Python signer in ed25519.py, so the
                             image stays dependency-free). `python server.py keygen` prints a fresh seed +
                             public key; `python server.py pubkey` prints the public key of FEED_SIGNING_KEY.
                             Give the public key to the gateway as `signatures.feed.public_key` (env:…) and
                             set `verify: ed25519`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import ed25519  # noqa: E402

BUNDLE_DIR = Path(os.environ.get("BUNDLE_DIR", HERE / "bundles"))
STATE_DIR = Path(os.environ.get("STATE_DIR", HERE / "state"))
MAX_BODY = 256 * 1024

SIGNATURE_TYPES = {
    "regex",
    "yara",
    "package_version",
    "url_path",
    "tool_desc_hash",
    "manifest_hash",
    "opcode",
    "arg_pattern",
    "ioc_domain",
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
ACTIONS = {
    "allow",
    "monitor",
    "redact",
    "pseudonymise",
    "sanitize",
    "route_local",
    "downgrade",
    "require_approval",
    "block",
}
STAGES = {
    "ingress",
    "egress",
    "tool_call",
    "tool_result",
    "embeddings",
    "agent_message",
    "artifact_load",
    "mcp_initialize",
    "mcp_tools_list",
}
ENTRY_FIELDS = {
    "id",
    "type",
    "pattern",
    "severity",
    "action",
    "stages",
    "description",
    "atlas_technique",
    "owasp",
    "cve",
    "source",
    "expires",
    "metadata",
}
_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$")  # SIG-… (curated) or FEED-LOCAL-0001 (added in the panel)
_REGEX_TYPES = {"regex", "arg_pattern", "url_path"}


def canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ----------------------------------------------------------------------------- entries


def validate_entry(obj: object) -> dict:
    """Return a complete entry dict (defaults applied) or raise ValueError with a client-safe message."""
    if not isinstance(obj, dict):
        raise ValueError("entry must be a JSON object")
    unknown = set(obj) - ENTRY_FIELDS
    if unknown:
        raise ValueError(f"unknown entry fields: {sorted(unknown)}")
    eid = obj.get("id")
    if not isinstance(eid, str) or not _ID.match(eid):
        raise ValueError("id must match ^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$")
    if obj.get("type") not in SIGNATURE_TYPES:
        raise ValueError(f"type must be one of {sorted(SIGNATURE_TYPES)}")
    pattern = obj.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    if obj["type"] in _REGEX_TYPES:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"pattern is not a valid regex: {exc}") from exc
    sev = obj.get("severity", "high")
    act = obj.get("action", "block")
    if sev not in SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
    if act not in ACTIONS:
        raise ValueError(f"action must be one of {sorted(ACTIONS)}")
    stages = obj.get("stages", [])
    if not isinstance(stages, list) or not set(stages) <= STAGES:
        raise ValueError(f"stages must be a list drawn from {sorted(STAGES)}")
    expires = obj.get("expires")
    if expires is not None:
        try:
            datetime.fromisoformat(str(expires))
        except ValueError as exc:
            raise ValueError("expires must be an ISO-8601 timestamp or null") from exc
    meta = obj.get("metadata", {})
    if not isinstance(meta, dict):
        raise ValueError("metadata must be an object")
    for key in ("atlas_technique", "owasp", "cve"):
        v = obj.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ValueError(f"{key} must be a list of strings")
    return {
        "id": eid,
        "type": obj["type"],
        "pattern": pattern,
        "severity": sev,
        "action": act,
        "stages": list(stages),
        "description": str(obj.get("description", "")),
        "atlas_technique": list(obj.get("atlas_technique", [])),
        "owasp": list(obj.get("owasp", [])),
        "cve": list(obj.get("cve", [])),
        "source": str(obj.get("source", "internal")),
        "expires": expires,
        "metadata": meta,
    }


# ----------------------------------------------------------------------------- bundle store


class BundleStore:
    def __init__(self, bundle_dir: Path, state_dir: Path, signing_seed: bytes | None = None, key_id: str | None = None):
        self.bundle_dir = bundle_dir
        self.state_dir = state_dir
        self.signing_seed = signing_seed
        self.key_id = key_id
        self._lock = threading.Lock()
        self._sig_cache: dict[tuple[int, str], dict] = {}

    # -- reading
    def _raw_bundles(self) -> list[dict]:
        out = []
        for d in (self.bundle_dir, self.state_dir):
            if d.is_dir():
                for p in sorted(d.glob("*.json")):
                    try:
                        out.append(json.loads(p.read_text(encoding="utf-8")))
                    except (OSError, ValueError):
                        print(f"feed-server: skipping unreadable bundle {p.name}", flush=True)
        return [b for b in out if isinstance(b, dict) and isinstance(b.get("bundle_version"), int)]

    def raw_current(self) -> dict | None:
        bundles = self._raw_bundles()
        if not bundles:
            return None
        best = dict(max(bundles, key=lambda b: b["bundle_version"]))
        best.pop("signature", None)
        return best

    def signed_current(self) -> dict | None:
        raw = self.raw_current()
        if raw is None:
            return None
        return self.sign(raw)

    def sign(self, raw: dict) -> dict:
        body = {k: v for k, v in raw.items() if k != "signature"}
        text = canonical(body)
        if self.signing_seed is not None:
            sig = {
                "alg": "ed25519",
                "key_id": self.key_id,
                "value": base64.b64encode(ed25519.sign(self.signing_seed, text.encode("utf-8"))).decode("ascii"),
            }
        else:
            sig = {"alg": "sha256", "key_id": None, "value": hashlib.sha256(text.encode("utf-8")).hexdigest()}
        return {**body, "signature": sig}

    # -- writing
    def _write_new_version(self, base: dict, entries: list[dict]) -> dict:
        version = max((b["bundle_version"] for b in self._raw_bundles()), default=0) + 1
        bundle = {
            "schema_version": "1.0",
            "bundle_version": version,
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "issuer": base.get("issuer", "acl-feed-server"),
            "entries": entries,
        }
        self.state_dir.mkdir(parents=True, exist_ok=True)
        path = self.state_dir / f"{version:04d}-live.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        tmp.replace(path)
        return bundle

    def upsert(self, new_entries: list[dict]) -> dict:
        with self._lock:
            base = self.raw_current() or {"entries": []}
            by_id = {e["id"]: e for e in base["entries"]}
            for e in new_entries:
                by_id[e["id"]] = e
            return self._write_new_version(base, list(by_id.values()))

    def delete(self, entry_id: str) -> dict | None:
        with self._lock:
            base = self.raw_current()
            if base is None or not any(e["id"] == entry_id for e in base["entries"]):
                return None
            return self._write_new_version(base, [e for e in base["entries"] if e["id"] != entry_id])


# ----------------------------------------------------------------------------- HTTP


class Handler(BaseHTTPRequestHandler):
    server_version = "acl-feed/1"

    @property
    def store(self) -> BundleStore:
        return self.server.store  # type: ignore[attr-defined]

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: object) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _authorised(self) -> bool:
        token = self.server.admin_token  # type: ignore[attr-defined]
        if not token:
            self._json(403, {"error": "editing disabled: FEED_ADMIN_TOKEN is not set"})
            return False
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.lower().startswith("bearer ") else ""
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            self._json(401, {"error": "invalid or missing bearer token"})
            return False
        return True

    def do_GET(self) -> None:
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        bundle = self.store.signed_current()
        if bundle is None:
            return self._json(404, {"error": "no bundle"})
        if self.path == "/bundle.json":
            return self._json(200, bundle)
        if self.path == "/bundle.sha256":
            return self._send(200, bundle["signature"]["value"].encode(), "text/plain")
        if self.path == "/entries":
            return self._json(200, {"bundle_version": bundle["bundle_version"], "entries": bundle["entries"]})
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/entries":
            return self._json(404, {"error": "not found"})
        if not self._authorised():
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                return self._json(413, {"error": "body missing or too large"})
            payload = json.loads(self.rfile.read(length))
            items = payload["entries"] if isinstance(payload, dict) and "entries" in payload else payload
            items = items if isinstance(items, list) else [items]
            entries = [validate_entry(i) for i in items]
            if not entries:
                raise ValueError("no entries supplied")
        except (ValueError, KeyError) as exc:
            return self._json(422, {"error": str(exc)})
        try:
            bundle = self.store.upsert(entries)
        except OSError:
            return self._json(500, {"error": "could not persist the new bundle (state dir not writable?)"})
        print(f"feed-server: bundle v{bundle['bundle_version']} ({len(entries)} entry upserted)", flush=True)
        return self._json(
            201,
            {
                "bundle_version": bundle["bundle_version"],
                "entries": len(bundle["entries"]),
                "upserted": [e["id"] for e in entries],
            },
        )

    def do_DELETE(self) -> None:
        if not self.path.startswith("/entries/"):
            return self._json(404, {"error": "not found"})
        if not self._authorised():
            return None
        entry_id = self.path[len("/entries/") :]
        try:
            bundle = self.store.delete(entry_id)
        except OSError:
            return self._json(500, {"error": "could not persist the new bundle"})
        if bundle is None:
            return self._json(404, {"error": "no such entry"})
        return self._json(200, {"bundle_version": bundle["bundle_version"], "entries": len(bundle["entries"])})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"feed-server: {fmt % args}", flush=True)


def parse_seed(value: str) -> bytes:
    v = value.strip()
    try:
        raw = bytes.fromhex(v) if re.fullmatch(r"[0-9a-fA-F]{64}", v) else base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit("FEED_SIGNING_KEY must be a 32-byte seed in base64 or hex") from exc
    if len(raw) != 32:
        raise SystemExit("FEED_SIGNING_KEY must decode to 32 bytes")
    return raw


def make_server(
    host: str = "0.0.0.0",  # noqa: S104
    port: int = 8080,
    *,
    bundle_dir: Path | None = None,
    state_dir: Path | None = None,
    admin_token: str | None = None,
    signing_seed: bytes | None = None,
    key_id: str | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.store = BundleStore(bundle_dir or BUNDLE_DIR, state_dir or STATE_DIR, signing_seed, key_id)  # type: ignore[attr-defined]
    server.admin_token = admin_token  # type: ignore[attr-defined]
    return server


def main(argv: list[str]) -> int:
    seed_env = os.environ.get("FEED_SIGNING_KEY")
    if argv[1:2] == ["keygen"]:
        seed = secrets.token_bytes(32)
        print("FEED_SIGNING_KEY=" + base64.b64encode(seed).decode())
        print("FEED_PUBLIC_KEY=" + base64.b64encode(ed25519.public_key(seed)).decode())
        return 0
    if argv[1:2] == ["pubkey"]:
        if not seed_env:
            raise SystemExit("set FEED_SIGNING_KEY")
        print(base64.b64encode(ed25519.public_key(parse_seed(seed_env))).decode())
        return 0
    port = int(os.environ.get("PORT", "8080"))
    seed = parse_seed(seed_env) if seed_env else None
    server = make_server(
        port=port,
        admin_token=os.environ.get("FEED_ADMIN_TOKEN") or None,
        signing_seed=seed,
        key_id=os.environ.get("FEED_KEY_ID") or ("feed-key-1" if seed else None),
    )
    mode = "ed25519" if seed else "sha256"
    editing = "enabled" if server.admin_token else "disabled"  # type: ignore[attr-defined]
    print(f"feed-server on :{port}; signing={mode}; live editing {editing}; seed bundles {BUNDLE_DIR}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
