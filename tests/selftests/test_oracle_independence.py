"""The oracles must not share code with the system under test: nothing under tests/oracle may import `acl`."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ORACLE_DIR = Path(__file__).resolve().parents[1] / "oracle"
FILES = sorted(ORACLE_DIR.glob("*.py"))
FORBIDDEN_ROOTS = {"acl"}
# Also keep the oracle free of the harness (which imports acl) and of third-party code that could mask bugs.
FORBIDDEN_LOCAL = {"harness", "e2e", "selftests"}


def imported_modules(source: str) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import: stays inside tests/oracle, fine
                continue
            mods.add(node.module or "")
        elif (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", getattr(node.func, "attr", "")) in ("__import__", "import_module")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            mods.add(node.args[0].value)
    return mods


def test_oracle_files_are_found() -> None:
    names = {f.name for f in FILES}
    assert {"leak.py", "sink.py"} <= names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_oracle_does_not_import_the_gateway(path: Path) -> None:
    roots = {m.split(".")[0] for m in imported_modules(path.read_text(encoding="utf-8"))}
    bad = roots & (FORBIDDEN_ROOTS | FORBIDDEN_LOCAL)
    assert not bad, f"{path.name} imports {sorted(bad)}: oracles must be independent of the system under test"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_oracle_uses_only_the_standard_library(path: Path) -> None:
    import sys

    roots = {m.split(".")[0] for m in imported_modules(path.read_text(encoding="utf-8"))} - {""}
    third_party = {r for r in roots if r not in sys.stdlib_module_names and r != "__future__"}
    assert not third_party, f"{path.name} imports non-stdlib modules {sorted(third_party)}"


def test_detector_catches_a_planted_import() -> None:
    assert "acl" in {m.split(".")[0] for m in imported_modules("from acl.engine import text")}
    assert "acl" in {m.split(".")[0] for m in imported_modules("import acl.contracts")}
    assert "acl.engine" in imported_modules("import importlib\nimportlib.import_module('acl.engine')")
    assert "acl" not in imported_modules("import json\nfrom pathlib import Path")
