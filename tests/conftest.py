"""System test harness: collects `tests/cases/*.yaml` as pytest items.

Case format (one YAML list per file; see tests/cases/README.md):

    - id: pii-pesel-valid-blocks          # unique, kebab-case
      control: SEC-PII-01                 # control under test (mutation testing / attribution)
      kind: negative                      # positive (benign -> allowed) | negative (attack/sensitive)
      pair: pii-pesel                     # links a negative case to its near-miss positive
      point: ingress                      # inspection point
      preset: balanced                    # optional (default: balanced)
      principal: {username: jan, groups: [credit-analysts]}
      session: untrusted                  # optional: session preset name or SessionState fields
      input: "..."                        # shorthand, or a payload dict (see acl.testing.make_payload)
      expect:
        action: pseudonymise              # expected primary decision action
        rule_id: SEC-PII-01               # must appear in the decision's rules (null = no rule may fire)
        redaction: {contains: ["<PESEL_1>"], not_contains: ["..."]}   # checked after apply_replacements
      matrix: {monitor: monitor, balanced: pseudonymise, strict: route_local, paranoid: route_local}
      modes: [deterministic]              # deterministic | live

Deterministic mode (default) runs every case in-process through the real app wiring (`create_app`
lifespan, `harness.host`) with mock connectors. `ACL_TEST_MODE=live` runs `live` cases 3x with a 2-of-3 rule.
Reports: reports/junit.xml, reports/summary.json (GuardQualitySummary shape), reports/case_lint.json.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).parent
CASES_DIR = TESTS / "cases"
MODE = os.environ.get("ACL_TEST_MODE", "deterministic")

if str(TESTS) not in sys.path:  # `harness.*` and `oracle.*` live next to this file
    sys.path.insert(0, str(TESTS))


def pytest_collect_file(parent: pytest.Collector, file_path: Path) -> pytest.Collector | None:
    if file_path.suffix in (".yaml", ".yml") and file_path.parent == CASES_DIR:
        return CaseFile.from_parent(parent, path=file_path)
    return None


class CaseFile(pytest.File):
    def collect(self):  # type: ignore[override]
        from harness.cases import mode_markers

        cases = YAML(typ="safe", pure=True).load(self.path.read_text(encoding="utf-8")) or []
        seen: set[str] = set()
        for case in cases:
            case["_file"] = self.path.name
            cid = case["id"]
            if cid in seen:
                raise ValueError(f"{self.path.name}: duplicate case id {cid}")
            seen.add(cid)
            presets = list(case.get("matrix", {})) or [case.get("preset", "balanced")]
            for preset in presets:
                name = cid if not case.get("matrix") else f"{cid}[{preset}]"
                item = CaseItem.from_parent(self, name=name, case=case, preset=preset)
                for marker in mode_markers(case, MODE):
                    if marker == "skip":
                        item.add_marker(pytest.mark.skip(reason=f"case not enabled for mode {MODE}"))
                    else:
                        item.add_marker(getattr(pytest.mark, marker))
                yield item


class CaseItem(pytest.Item):
    def __init__(self, *, case: dict[str, Any], preset: str, **kw: Any) -> None:
        super().__init__(**kw)
        self.case = case
        self.preset = preset

    def runtest(self) -> None:
        from harness.runner import run_case

        run_case(self.case, self.preset)

    def reportinfo(self):  # type: ignore[override]
        return self.path, 0, f"case: {self.name}"

    def repr_failure(self, excinfo, style=None):  # type: ignore[override]
        if isinstance(excinfo.value, AssertionError):
            return f"{self.case['id']} [{self.preset}]: {excinfo.value}"
        return super().repr_failure(excinfo, style=style)


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    os.environ.setdefault("ACL_DETERMINISTIC", "1" if MODE == "deterministic" else "0")
    if not config.option.xmlpath and not os.environ.get("ACL_NO_JUNIT"):
        config.option.xmlpath = str(ROOT / "reports" / "junit.xml")
    from harness.plugin import MetricsPlugin

    config.pluginmanager.register(MetricsPlugin(MODE), "acl-metrics")


# ---------------------------------------------------------------- fixtures


@pytest.fixture(scope="session")
def host():
    """The session-wide `EngineHost`: the real app (lifespan run once) on a background loop."""
    from harness.host import get_host

    return get_host()


@pytest.fixture
def attacker_sink():
    """A fresh attacker sink (stdlib HTTP server) on a free port; `sink.url`, `sink.entries()`."""
    from oracle.sink import SinkServer

    with SinkServer() as sink:
        yield sink
