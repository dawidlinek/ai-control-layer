"""System test harness: collects `tests/cases/*.yaml` as pytest items.

Case format (one YAML list per file; see tests/cases/README.md):

    - id: pii-pesel-valid-blocks          # unique, kebab-case
      control: SEC-PII-01                 # control under test (for mutation testing / attribution)
      kind: negative                      # positive (benign → allowed) | negative (attack/sensitive)
      pair: pii-pesel                     # links a negative case to its near-miss positive
      point: ingress                      # inspection point
      preset: balanced                    # optional (default: balanced)
      principal: {username: jan, groups: [credit-analysts]}
      input: "Mój PESEL to 44051401359"   # shorthand, or a payload dict (see acl.testing.make_payload)
      expect:
        action: pseudonymise              # expected primary decision action
        rule_id: SEC-PII-01               # must appear in decision.rule_ids (null = no rules fired)
        redaction: {contains: ["<PESEL_1>"], not_contains: ["44051401359"]}   # optional
      matrix: {monitor: monitor, balanced: pseudonymise, strict: route_local, paranoid: route_local}  # optional
      modes: [deterministic]              # deterministic | live

Deterministic mode (default) runs every case in-process against the policy in `policy/`, with
mock connectors. `ACL_TEST_MODE=live` runs `live` cases 3× with a 2-of-3 rule (Phase 3A).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = Path(__file__).parent / "cases"
MODE = os.environ.get("ACL_TEST_MODE", "deterministic")


def pytest_collect_file(parent: pytest.Collector, file_path: Path) -> pytest.Collector | None:
    if file_path.suffix in (".yaml", ".yml") and file_path.parent == CASES_DIR:
        return CaseFile.from_parent(parent, path=file_path)
    return None


class CaseFile(pytest.File):
    def collect(self):  # type: ignore[override]
        cases = YAML(typ="safe", pure=True).load(self.path.read_text(encoding="utf-8")) or []
        seen: set[str] = set()
        for case in cases:
            cid = case["id"]
            if cid in seen:
                raise ValueError(f"{self.path.name}: duplicate case id {cid}")
            seen.add(cid)
            presets = list(case.get("matrix", {})) or [case.get("preset", "balanced")]
            for preset in presets:
                name = cid if not case.get("matrix") else f"{cid}[{preset}]"
                item = CaseItem.from_parent(self, name=name, case=case, preset=preset)
                if MODE not in case.get("modes", ["deterministic"]):
                    item.add_marker(pytest.mark.skip(reason=f"case not enabled for mode {MODE}"))
                yield item


class CaseItem(pytest.Item):
    def __init__(self, *, case: dict[str, Any], preset: str, **kw: Any) -> None:
        super().__init__(**kw)
        self.case = case
        self.preset = preset

    def runtest(self) -> None:
        from harness.runner import run_case  # tests/harness

        run_case(self.case, self.preset)

    def reportinfo(self):  # type: ignore[override]
        return self.path, 0, f"case: {self.name}"

    def repr_failure(self, excinfo, style=None):  # type: ignore[override]
        if isinstance(excinfo.value, AssertionError):
            return f"{self.case['id']} [{self.preset}]: {excinfo.value}"
        return super().repr_failure(excinfo, style=style)


def pytest_configure(config: pytest.Config) -> None:
    import sys

    harness_root = str(Path(__file__).parent)
    if harness_root not in sys.path:
        sys.path.insert(0, harness_root)
    os.environ.setdefault("ACL_DETERMINISTIC", "1" if MODE == "deterministic" else "0")
