"""Resolution of `env:NAME` references in policy values (never stored resolved)."""

from __future__ import annotations

import os
from collections.abc import Mapping

ENV_PREFIX = "env:"


class MissingEnv(LookupError):
    def __init__(self, name: str) -> None:
        super().__init__(f"environment variable {name} is not set")
        self.name = name


def is_ref(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(ENV_PREFIX)


def resolve(value: str | None, environ: Mapping[str, str] | None = None, *, required: bool = True) -> str | None:
    """Resolve `env:NAME` → value; plain strings pass through. Empty/missing → MissingEnv (or None)."""
    if value is None or not is_ref(value):
        return value
    name = value[len(ENV_PREFIX) :]
    got = (environ if environ is not None else os.environ).get(name) or None
    if got is None and required:
        raise MissingEnv(name)
    return got
