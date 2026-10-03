"""Invoice helpers (demo workspace file)."""

from __future__ import annotations


def vat(net: float, rate: float = 0.23) -> float:
    return round(net * rate, 2)


def gross(net: float, rate: float = 0.23) -> float:
    return round(net + vat(net, rate), 2)
