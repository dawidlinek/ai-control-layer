"""Contracts are generated from code and must not drift; examples must validate against schemas."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from acl.contracts import export
from acl.contracts.canonical import audit_record_hash, bundle_digest

CONTRACTS = export.CONTRACTS


def test_contracts_are_up_to_date() -> None:
    assert export.main(["--check"]) == 0, "run `make contracts` and review the diff"


def _schema(name: str) -> dict:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def _validator(schema: dict, ref: str | None = None) -> jsonschema.Draft202012Validator:
    if ref:
        schema = {**schema, "$ref": f"#/$defs/{ref}"}
    return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize(
    ("example", "schema", "ref"),
    [
        ("inspection-context.ingress-pii.json", "decision.schema.json", "InspectionContext"),
        ("inspection-context.tool-call.json", "decision.schema.json", "InspectionContext"),
        ("verdict.pii.json", "decision.schema.json", "Verdict"),
        ("decision.route-local.json", "decision.schema.json", None),
        ("audit-event.decision.json", "event.schema.json", None),
        ("feed-bundle.example.json", "feed-bundle.schema.json", None),
    ],
)
def test_examples_validate(example: str, schema: str, ref: str | None) -> None:
    instance = json.loads((CONTRACTS / "examples" / example).read_text(encoding="utf-8"))
    _validator(_schema(schema), ref).validate(instance)


def test_audit_example_hash_chain_verifies() -> None:
    rec = json.loads((CONTRACTS / "examples" / "audit-event.decision.json").read_text(encoding="utf-8"))
    assert rec["hash"] == audit_record_hash(rec["prev_hash"], rec)
    tampered = {**rec, "decision": {**rec["decision"], "action": "allow"}}
    assert tampered["hash"] != audit_record_hash(rec["prev_hash"], tampered)


def test_feed_example_digest_verifies() -> None:
    b = json.loads((CONTRACTS / "examples" / "feed-bundle.example.json").read_text(encoding="utf-8"))
    assert b["signature"]["value"] == bundle_digest(b)


def test_policy_files_validate_against_published_schema() -> None:
    from ruamel.yaml import YAML

    validator = _validator(_schema("policy.schema.json"))
    root = Path(export.ROOT) / "policy"
    files = sorted(root.glob("*.yaml"))
    assert files
    for f in files:
        validator.validate(YAML(typ="safe", pure=True).load(f.read_text(encoding="utf-8")))


def test_audit_example_has_no_raw_identifiers() -> None:
    text = (CONTRACTS / "examples" / "audit-event.decision.json").read_text(encoding="utf-8")
    assert "44051401359" not in text
    assert "PL61109010140000071219812874" not in text
