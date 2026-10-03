"""Wilson 95% interval math."""

from __future__ import annotations

import math

import pytest
from harness.stats import Z95, rate_with_ci, wilson


def _reference(k: int, n: int) -> tuple[float, float]:
    """Independent formulation: solve the score-test equation (p - phat)^2 = z^2 p(1-p)/n for p."""
    phat, z2 = k / n, Z95**2
    a = 1 + z2 / n
    b = -(2 * phat + z2 / n)
    c = phat**2
    disc = math.sqrt(b * b - 4 * a * c)
    return (-b - disc) / (2 * a), (-b + disc) / (2 * a)


@pytest.mark.parametrize("k,n", [(1, 10), (5, 10), (9, 10), (40, 100), (3, 7), (120, 1000), (1, 2)])
def test_matches_reference_formulation(k: int, n: int) -> None:
    p, lo, hi = wilson(k, n)
    ref_lo, ref_hi = _reference(k, n)
    assert p == k / n
    assert lo == pytest.approx(ref_lo, abs=1e-9)
    assert hi == pytest.approx(ref_hi, abs=1e-9)


def test_known_values() -> None:
    # textbook: 0 of 10 -> upper bound z^2 / (n + z^2)
    _, lo, hi = wilson(0, 10)
    assert lo == 0.0
    assert hi == pytest.approx(Z95**2 / (10 + Z95**2))
    # 5 of 5 caught is NOT certainty: the lower bound is only ~0.566
    _, lo, hi = wilson(5, 5)
    assert hi == 1.0
    assert lo == pytest.approx(0.5655, abs=1e-3)
    # 50 of 100
    _, lo, hi = wilson(50, 100)
    assert (lo, hi) == (pytest.approx(0.4038, abs=1e-3), pytest.approx(0.5962, abs=1e-3))


def test_symmetry_and_narrowing() -> None:
    p1, lo1, hi1 = wilson(3, 20)
    p2, lo2, hi2 = wilson(17, 20)
    assert lo1 == pytest.approx(1 - hi2) and hi1 == pytest.approx(1 - lo2)
    width = [wilson(n // 2, n)[2] - wilson(n // 2, n)[1] for n in (10, 100, 1000)]
    assert width[0] > width[1] > width[2]
    assert p1 + p2 == pytest.approx(1)


def test_bounds_always_contain_estimate_and_stay_in_unit_interval() -> None:
    for n in range(1, 40):
        for k in range(n + 1):
            p, lo, hi = wilson(k, n)
            assert 0.0 <= lo <= p <= hi <= 1.0


def test_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        wilson(1, 0)
    with pytest.raises(ValueError):
        wilson(6, 5)
    assert rate_with_ci(0, 0) is None
    r = rate_with_ci(4, 5)
    assert r is not None and r["n"] == 5 and r["ci_low"] < r["value"] < r["ci_high"]
