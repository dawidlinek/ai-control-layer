"""Phase 1B: round-trip YAML edits, located loader errors, file source, org-lock comparison."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from acl.policy.loader import PolicyLoadError, load_policy_dir, parse_documents, read_policy_dir
from acl.policy.locks import locked_violations
from acl.policy.source import FileSource, PolicySource, valid_file_name
from acl.policy.yamledit import Locator, PatchError, PathOp, patch_text, rt_yaml

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"

DOC = """\
# header comment
global:
  mode: enforce          # trailing comment
  default_preset: balanced
items:
  # about a
  - id: a
    value: 1             # keep me
  - id: b
    value: "two"
    tags: [x, y]
"""


@pytest.mark.parametrize("path", sorted(POLICY_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_round_trip_of_seed_files_is_byte_identical(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    buf = io.StringIO()
    rt_yaml().dump(rt_yaml().load(text), buf)
    assert buf.getvalue() == text


def test_patch_set_keeps_comments_quotes_and_layout() -> None:
    out = patch_text(
        DOC,
        [
            PathOp("set", ["global", "default_preset"], "strict"),
            PathOp("set", ["items", {"id": "a"}, "value"], 5),
            PathOp("set", ["items", {"id": "b"}, "tags"], ["z"]),
        ],
    )
    expected = DOC.replace("default_preset: balanced", "default_preset: strict")
    expected = expected.replace("value: 1             # keep me", "value: 5             # keep me")
    assert out == expected.replace("tags: [x, y]", "tags: [z]")  # flow style of the replaced list is kept
    assert "# header comment" in out and "# about a" in out and '"two"' in out


def test_patch_delete_and_add() -> None:
    out = patch_text(
        DOC,
        [
            PathOp("delete", ["items", {"id": "b"}]),
            PathOp("set", ["global", "extra"], {"k": 1}),
            PathOp("set", ["items", 1], {"id": "c"}),
        ],
    )
    assert "id: b" not in out and "extra:" in out and "id: c" in out
    assert "# header comment" in out and "# trailing comment" in out and "# keep me" in out
    out = patch_text(DOC, [PathOp("delete", ["global", "mode"])])
    assert "mode:" not in out and "# header comment" in out


@pytest.mark.parametrize(
    "op",
    [
        PathOp("set", ["nope", "x"], 1),
        PathOp("delete", ["global", "missing"]),
        PathOp("delete", ["items", {"id": "zzz"}]),
        PathOp("set", ["global", "mode", "deep"], 1),
        PathOp("set", [], 1),
    ],
)
def test_patch_errors(op: PathOp) -> None:
    with pytest.raises(PatchError):
        patch_text(DOC, [op])
    with pytest.raises(PatchError):
        patch_text("a: [1\n", [PathOp("set", ["a"], 1)])


def test_locator_positions() -> None:
    loc = Locator(DOC)
    assert loc.locate(["global", "default_preset"]) == (4, 3)
    assert loc.locate(["items", 1, "value"]) == (10, 5)
    assert loc.locate(["items", {"id": "a"}, "value"]) == (8, 5)
    assert loc.locate(["items", "b", "value"]) == (10, 5)
    assert loc.locate(["global", "union_tag", "default_preset"]) == (4, 3)  # tags that are not in the YAML are skipped
    assert loc.locate(["missing"]) is None
    assert Locator("a: [1\n").locate(["a"]) is None


# ---------------------------------------------------------------- loader errors


def _errors(texts: dict[str, str]) -> list:
    with pytest.raises(PolicyLoadError) as exc:
        parse_documents(texts)
    return exc.value.errors


def test_loader_locates_schema_errors() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["routing.yaml"] = texts["routing.yaml"].replace("local_max: 0.0", "local_max: 9", 1)
    (route,) = _errors(texts)
    assert route.file == "routing.yaml" and route.path and "local_max" in route.path
    assert route.line == texts["routing.yaml"][: texts["routing.yaml"].index("local_max")].count("\n") + 1


def test_loader_locates_cross_reference_errors() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["groups.yaml"] = texts["groups.yaml"].replace(
        "models: [auto, local, bielik, smart, smart-pro]", "models: [auto, nope/model]", 1
    )
    (cross,) = _errors(texts)
    assert cross.file == "groups.yaml" and cross.path == "groups[admins].models" and "nope/model" in cross.message
    assert cross.line == texts["groups.yaml"][: texts["groups.yaml"].index("nope/model")].count("\n") + 1


def test_loader_splits_multiple_cross_reference_errors() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["groups.yaml"] = texts["groups.yaml"].replace("mcp_servers: [core-banking]", "mcp_servers: [ghost]", 1)
    texts["groups.yaml"] = texts["groups.yaml"].replace("bank.query: {}", "bank.ghost: {}", 1)
    errs = _errors(texts)
    assert len(errs) == 2 and {e.file for e in errs} == {"groups.yaml"} and all(e.line for e in errs)


def test_loader_reports_duplicate_section_with_line() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["extra.yaml"] = "# x\nbudgets:\n  org: {usd_month: 1}\n"
    (err,) = _errors(texts)
    assert err.file == "extra.yaml" and err.line == 2 and "already defined in budgets.yaml" in err.message


def test_loaded_policy_knows_which_file_defines_each_section() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    assert loaded.sections["controls"] == "controls.yaml" and loaded.sections["groups"] == "groups.yaml"


# ---------------------------------------------------------------- file source


def test_file_source_filters_names_normalises_and_writes_atomically(tmp_path: Path) -> None:
    src = FileSource(tmp_path)
    assert isinstance(src, PolicySource)
    (tmp_path / "a.yaml").write_bytes(b"\xef\xbb\xbfx: 1\r\ny: 2\r\n")
    for junk in (".a.yaml.swp", "a.yaml~", ".#a.yaml", "B.yaml", "c d.yaml", "notes.txt", ".acl-tmp-x.tmp"):
        (tmp_path / junk).write_text("junk: true\n", encoding="utf-8")
    files = src.read_files()
    assert list(files) == ["a.yaml"] and files["a.yaml"].content == "x: 1\ny: 2\n"
    src.write_file("a.yaml", "x: 2\ny: 3\n")
    assert (tmp_path / "a.yaml").read_bytes() == b"x: 2\ny: 3\n"
    src.write_file("new-file_1.yaml", "z: 1\n")
    assert sorted(p.name for p in tmp_path.glob(".acl-tmp-*")) == [".acl-tmp-x.tmp"]  # our temp files are cleaned up
    for bad in ("../a.yaml", "..\\a.yaml", "sub/a.yaml", "A.yaml", "a.yml"):
        assert not valid_file_name(bad)
        with pytest.raises(ValueError, match="invalid policy file name"):
            src.write_file(bad, "x: 1\n")
    src.delete_file("new-file_1.yaml")
    assert "new-file_1.yaml" not in src.read_files()


def test_file_source_reports_undecodable_file(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(PolicyLoadError) as exc:
        FileSource(tmp_path).read_files()
    assert exc.value.errors[0].file == "bad.yaml" and "UTF-8" in exc.value.errors[0].message


# ---------------------------------------------------------------- lock comparison


def test_locked_violations_unit() -> None:
    base = read_policy_dir(POLICY_DIR)
    base["controls.yaml"] = base["controls.yaml"].replace(
        "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: false",
        "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: true",
        1,
    )
    old = parse_documents(base).policy
    assert locked_violations(old, old) == []
    off = dict(base)
    off["controls.yaml"] = base["controls.yaml"].replace(
        "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: true",
        "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: false",
        1,
    )
    (v,) = locked_violations(old, parse_documents(off).policy)
    assert v.control_id == "SEC-SECRET-01" and v.changes == ("disabled",)
    # enabling a locked control that was disabled is fine
    assert locked_violations(parse_documents(off).policy, old) == []


def test_alembic_migration_creates_policy_versions(tmp_path: Path) -> None:
    import sqlite3

    from acl.migrate import upgrade_head

    db = tmp_path / "m.db"
    upgrade_head(f"sqlite+aiosqlite:///{db}")
    with sqlite3.connect(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(policy_versions)")}
    assert {"id", "version", "created_at", "author", "source", "message", "files_changed", "files", "diff"} <= cols
