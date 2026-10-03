from __future__ import annotations

from pathlib import Path

import pytest

from acl.contracts.common import Preset
from acl.policy.loader import PolicyLoadError, load_policy_dir, parse_documents, read_policy_dir

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"


def test_seed_policy_loads() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    p = loaded.policy
    assert set(p.presets) == set(Preset)
    assert "SEC-SECRET-01" in p.locked_control_ids()
    assert len(loaded.version) == 12


def test_every_control_declares_required_fields() -> None:
    for c in load_policy_dir(POLICY_DIR).policy.controls:
        assert c.id and c.stages and c.cost_tier and c.timeout_ms > 0


def test_version_changes_with_content() -> None:
    texts = read_policy_dir(POLICY_DIR)
    v1 = parse_documents(texts).version
    texts["routing.yaml"] += "\n# comment only\n"
    assert parse_documents(texts).version != v1


def test_duplicate_section_across_files_rejected() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["extra.yaml"] = "budgets:\n  org: {usd_month: 1}\n"
    with pytest.raises(PolicyLoadError) as exc:
        parse_documents(texts)
    assert any("already defined" in e.message for e in exc.value.errors)


def test_unknown_field_rejected_with_location() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["routing.yaml"] = texts["routing.yaml"].replace("routing:", "routing:\n  bogus_field: 1", 1)
    with pytest.raises(PolicyLoadError) as exc:
        parse_documents(texts)
    assert any(e.file == "routing.yaml" for e in exc.value.errors)


def test_dangling_model_reference_rejected() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["groups.yaml"] = texts["groups.yaml"].replace("models: [auto, local]", "models: [auto, nope/model]", 1)
    with pytest.raises(PolicyLoadError):
        parse_documents(texts)


def test_yaml_syntax_error_reports_line() -> None:
    texts = read_policy_dir(POLICY_DIR)
    texts["budgets.yaml"] = "budgets: [unclosed\n"
    with pytest.raises(PolicyLoadError) as exc:
        parse_documents(texts)
    assert exc.value.errors[0].line is not None
