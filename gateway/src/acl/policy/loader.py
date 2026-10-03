"""Policy loader: YAML texts -> merged, cross-validated `Policy` (phase 1B).

Public API (stable; used by `main.py`, tests, the compiler and the writer):
    load_policy_dir(path) -> LoadedPolicy
    parse_documents({name: text}) -> LoadedPolicy   (used by validate / dry-run / reload)
    read_policy_dir(path) -> {name: text}
    PolicyLoadError(errors: list[PolicyError])

Every error carries `file`, `path` and, where it can be determined, `line`/`column` (1-based). Error
messages never contain document content (pydantic messages describe the problem, not the input).
"""

from __future__ import annotations

import hashlib
import io
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from acl.contracts.admin import PolicyError
from acl.policy.models import SECTIONS, Policy, PolicyDocument
from acl.policy.yamledit import Locator

POLICY_GLOB = "*.yaml"
FILE_NAME_RE = re.compile(r"^[a-z0-9_-]+\.yaml$")

# YAML key of every section (aliases, e.g. `global_` -> `global`).
_SECTION_KEYS: frozenset[str] = frozenset(PolicyDocument.model_fields[s].alias or s for s in SECTIONS)
_PATH_PREFIX = re.compile(r"^(?P<path>[A-Za-z_]\w*(?:\[[^\]]*\]|\.[A-Za-z_]\w*)*)(?::| )")
_TOKEN = re.compile(r"\[([^\]]*)\]|([A-Za-z_]\w*)")


class PolicyLoadError(Exception):
    def __init__(self, errors: list[PolicyError]) -> None:
        super().__init__("; ".join(f"{e.file or '?'}: {e.path or ''} {e.message}".strip() for e in errors))
        self.errors = errors


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    version: str
    files: dict[str, str]  # name -> content hash
    sections: dict[str, str] = field(default_factory=dict)  # top-level section -> defining file


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


def _clean(msg: str) -> str:
    return msg.removeprefix("Value error, ").strip()


class _Collector:
    """Collects errors with a path tuple and resolves line/column per file at the end."""

    def __init__(self, texts: dict[str, str]) -> None:
        self._texts = texts
        self._items: list[tuple[PolicyError, tuple[Any, ...]]] = []
        self._locators: dict[str, Locator] = {}

    def add(self, error: PolicyError, loc: Sequence[Any] = ()) -> None:
        self._items.append((error, tuple(loc)))

    def __bool__(self) -> bool:
        return bool(self._items)

    def result(self) -> list[PolicyError]:
        out: list[PolicyError] = []
        for err, loc in self._items:
            if err.line is None and err.file in self._texts:
                loc_obj = self._locators.get(err.file)
                if loc_obj is None:
                    loc_obj = self._locators[err.file] = Locator(self._texts[err.file])
                pos = loc_obj.locate(loc) if loc else None
                if pos is not None:
                    err = err.model_copy(update={"line": pos[0], "column": pos[1]})
            out.append(err)
        return out


def _path_tokens(path: str) -> list[str]:
    """`groups[developers].models` -> ['groups', 'developers', 'models']."""
    return [a or b for a, b in _TOKEN.findall(path)]


def _cross_errors(message: str, owner: dict[str, str]) -> list[tuple[PolicyError, tuple[str, ...]]]:
    """Split the `Policy` cross-validation error (one joined string) into located errors."""
    out: list[tuple[PolicyError, tuple[str, ...]]] = []
    for part in message.split("; "):
        part = _clean(part)
        if not part:
            continue
        m = _PATH_PREFIX.match(part)
        tokens = _path_tokens(m.group("path")) if m else []
        if tokens and tokens[0] in _SECTION_KEYS:
            path = m.group("path") if m else ""
            out.append((PolicyError(file=owner.get(tokens[0]), path=path, message=part), tuple(tokens)))
        else:
            out.append((PolicyError(message=part), ()))
    return out


def parse_documents(texts: dict[str, str]) -> LoadedPolicy:
    errors = _Collector(texts)
    merged: dict[str, Any] = {}
    owner: dict[str, str] = {}
    for name in sorted(texts):
        try:
            raw = _yaml().load(io.StringIO(texts[name])) or {}
        except YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            errors.add(
                PolicyError(
                    file=name,
                    line=(mark.line + 1) if mark else None,
                    column=(mark.column + 1) if mark else None,
                    message=f"YAML syntax error: {getattr(exc, 'problem', exc)}",
                )
            )
            continue
        if not isinstance(raw, dict):
            errors.add(PolicyError(file=name, message="top level must be a mapping"))
            continue
        try:
            doc = PolicyDocument.model_validate(raw)
        except ValidationError as exc:
            for e in exc.errors():
                errors.add(PolicyError(file=name, path=_loc(e), message=e["msg"]), e["loc"])
            continue
        dumped = doc.model_dump(by_alias=True, exclude_none=True, exclude={"schema_"})
        for section in dumped:
            if section in owner:
                errors.add(
                    PolicyError(file=name, path=section, message=f"section already defined in {owner[section]}"),
                    (section,),
                )
                continue
            owner[section] = name
            merged[section] = raw[section]
    if errors:
        raise PolicyLoadError(errors.result())
    unknown = set(merged) - _SECTION_KEYS
    if unknown:  # pragma: no cover - PolicyDocument already forbids extras
        raise PolicyLoadError([PolicyError(message=f"unknown sections {sorted(unknown)}")])
    try:
        policy = Policy.model_validate(merged)
    except ValidationError as exc:
        for e in exc.errors():
            if e["type"] == "value_error" and not e["loc"]:
                for err, loc in _cross_errors(e["msg"], owner):
                    errors.add(err, loc)
            else:
                first = str(e["loc"][0]) if e["loc"] else None
                errors.add(
                    PolicyError(file=owner.get(first) if first else None, path=_loc(e), message=e["msg"]), e["loc"]
                )
        raise PolicyLoadError(errors.result()) from exc
    return LoadedPolicy(
        policy=policy,
        version=compute_version(texts),
        files={n: content_hash(t) for n, t in texts.items()},
        sections=dict(owner),
    )


def read_policy_dir(path: Path) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(path.glob(POLICY_GLOB))}


def load_policy_dir(path: Path) -> LoadedPolicy:
    texts = read_policy_dir(path)
    if not texts:
        raise PolicyLoadError([PolicyError(file=str(path), message="no policy files found")])
    return parse_documents(texts)
