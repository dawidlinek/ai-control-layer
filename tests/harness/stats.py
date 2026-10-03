"""Small statistics helpers (no dependencies)."""

from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float, float]:
    """Wilson score interval for a binomial proportion: returns (point estimate, low, high).

    Unlike the normal approximation it behaves at k=0, k=n and small n, which is where guard
    quality numbers live (e.g. 5 of 5 attacks caught is *not* a 100% detection rate with certainty).
    """
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= k <= n:
        raise ValueError("k must be within 0..n")
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    low = 0.0 if k == 0 else max(0.0, centre - half)
    high = 1.0 if k == n else min(1.0, centre + half)
    return p, low, high


def rate_with_ci(k: int, n: int) -> dict[str, float | int] | None:
    """Dict shaped like `acl.contracts.admin.RateWithCI` (None when there is no sample)."""
    if n <= 0:
        return None
    p, low, high = wilson(k, n)
    return {"value": round(p, 6), "ci_low": round(low, 6), "ci_high": round(high, 6), "n": n}
