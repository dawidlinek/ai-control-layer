"""Format a payment batch for the clearing house (demo code with a deliberate bug for the assistant to find)."""

from __future__ import annotations

import csv
import sys


def total_cents(rows: list[dict[str, str]]) -> int:
    # BUG: float arithmetic on money; should use Decimal or integer cents.
    return int(sum(float(r["amount"]) * 100 for r in rows))


def main(argv: list[str]) -> int:
    with open(argv[1], newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    print(f"{len(rows)} payments, total {total_cents(rows) / 100:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
