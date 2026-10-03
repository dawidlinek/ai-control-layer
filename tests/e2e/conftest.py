"""E2E fixtures. Every test here needs the docker-compose stack (`make up`); they skip cleanly without it."""

from __future__ import annotations

import pytest
from e2e.helpers import SseListener, Stack, StackConfig, stack_status


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/e2e" in item.nodeid.replace("\\", "/"):
            item.add_marker(pytest.mark.e2e)


@pytest.fixture(scope="session")
def stack():
    cfg = StackConfig()
    ok, reason = stack_status(cfg)
    if not ok:
        pytest.skip(f"e2e stack unavailable: {reason}")
    s = Stack(cfg)
    yield s
    s.close()


@pytest.fixture
def sse(stack):
    """SSE listener on the admin event stream (as user `adam`, member of `admins`), connected before the test body."""
    listener = SseListener(stack)
    try:
        listener.start()
    except RuntimeError as exc:
        pytest.fail(f"cannot open /admin/v1/events/stream: {exc}")
    yield listener
    listener.stop()
