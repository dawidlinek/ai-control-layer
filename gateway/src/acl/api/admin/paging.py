"""`X-Total-Count`: total rows matching a list endpoint's filters, ignoring `limit` (body stays a plain array)."""

from __future__ import annotations

from fastapi import Response

TOTAL_COUNT_HEADER = "X-Total-Count"

# merged into a route's `responses=` so the generated OpenAPI documents the response header
TOTAL_COUNT_RESPONSES: dict[int | str, dict] = {
    200: {
        "description": "Successful Response",
        "headers": {
            TOTAL_COUNT_HEADER: {
                "description": "Number of rows matching the filters, ignoring `limit`.",
                "schema": {"type": "integer", "minimum": 0},
            }
        },
    }
}


def set_total(response: Response, total: int) -> None:
    response.headers[TOTAL_COUNT_HEADER] = str(total)
