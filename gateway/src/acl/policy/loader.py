"""Minimal policy loader (Phase 0). Phase 1B replaces this with watcher/compiler/versioning.

Public API kept stable for later phases:
    load_policy_dir(path) -> LoadedPolicy
    parse_documents({name: text}) -> LoadedPolicy   (used by validate / dry-run)
    PolicyLoadError(errors: list[PolicyError])
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from acl.contracts.admin import PolicyError
from acl.policy.models import SECTIONS, Policy, PolicyDocument

POLICY_GLOB = "*.yaml"


class PolicyLoadError(Exception):
    def __init__(self, errors: list[PolicyError]) -> None:
        super().__init__("; ".join(f"{e.file or '?'}: {e.path or ''} {e.message}".strip() for e in errors))
        self.errors = errors


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    version: str
    files: dict[str, str]  # name -> content hash


def _yaml() -> YAML:
    y = YAML(typ="safe", pure=True)
    return y


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_version(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode())
        h.update(b"\0")
        h.update(files[name].encode())
        h.update(b"\0")
    return h.hexdigest()[:12]


def _loc(err: dict[str, Any]) -> str:
    return ".".join(str(p) for p in err.get("loc", ()))


def parse_documents(texts: dict[str, str]) -> LoadedPolicy:
    errors: list[PolicyError] = []
    merged: dict[str, Any] = {}
    owner: dict[str, str] = {}
    for name in sorted(texts):
        try:
            raw = _yaml().load(io.StringIO(texts[name])) or {}
        except YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            errors.append(
                PolicyError(
                    file=name,
                    line=(mark.line + 1) if mark else None,
                    column=(mark.column + 1) if mark else None,
                    message=f"YAML syntax error: {getattr(exc, 'problem', exc)}",
                )
            )
            continue
        if not isinstance(raw, dict):
            errors.append(PolicyError(file=name, message="top level must be a mapping"))
            continue
        try:
            doc = PolicyDocument.model_validate(raw)
        except ValidationError as exc:
            errors.extend(PolicyError(file=name, path=_loc(e), message=e["msg"]) for e in exc.errors())
            continue
        dumped = doc.model_dump(by_alias=True, exclude_none=True, exclude={"schema_"})
        for section in dumped:
            if section in owner:
                errors.append(
                    PolicyError(file=name, path=section, message=f"section already defined in {owner[section]}")
                )
                continue
            owner[section] = name
            merged[section] = raw[section]
    if errors:
        raise PolicyLoadError(errors)
    unknown = set(merged) - {PolicyDocument.model_fields[s].alias or s for s in SECTIONS}
    if unknown:  # pragma: no cover - PolicyDocument already forbids extras
        raise PolicyLoadError([PolicyError(message=f"unknown sections {sorted(unknown)}")])
    try:
        policy = Policy.model_validate(merged)
    except ValidationError as exc:
        raise PolicyLoadError(
            [
                PolicyError(file=owner.get(str(e["loc"][0])) if e["loc"] else None, path=_loc(e), message=e["msg"])
                for e in exc.errors()
            ]
        ) from exc
    return LoadedPolicy(
        policy=policy, version=compute_version(texts), files={n: content_hash(t) for n, t in texts.items()}
    )


def read_policy_dir(path: Path) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(path.glob(POLICY_GLOB))}


def load_policy_dir(path: Path) -> LoadedPolicy:
    texts = read_policy_dir(path)
    if not texts:
        raise PolicyLoadError([PolicyError(file=str(path), message="no policy files found")])
    return parse_documents(texts)
