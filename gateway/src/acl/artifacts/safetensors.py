"""Strict safetensors header validation.

Only the 8-byte length and the JSON header are read from disk. The layout rules mirror the reference parser:
tensors must tile the data section contiguously with no holes or overlaps, and each tensor's byte range must match
dtype * shape. Anything off is ART-ST-01 (a parser differential or memory-safety attempt, not a model).
"""

from __future__ import annotations

import json
import struct
from typing import Any, BinaryIO

from acl.artifacts.report import ScanFinding, make_finding, sanitize
from acl.contracts.common import Severity

MAX_HEADER_BYTES = 100 * 1024 * 1024
MAX_DIMS = 8
DTYPE_BYTES: dict[str, int] = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E5M2": 1,
    "F8_E4M3": 1,
    "F8_E8M0": 1,
    "E8M0": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "F64": 8,
    "I64": 8,
    "U64": 8,
}
SUB_BYTE_DTYPES = frozenset({"F4", "F6_E2M3", "F6_E3M2"})


class _Invalid(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Invalid("duplicate key in header JSON")
        out[key] = value
    return out


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate(f: BinaryIO, size: int) -> None:
    if size < 10:
        raise _Invalid("file shorter than the 8-byte length prefix and a header")
    f.seek(0)
    prefix = f.read(8)
    if len(prefix) != 8:
        raise _Invalid("short read of the length prefix")
    (n,) = struct.unpack("<Q", prefix)
    if n < 2:
        raise _Invalid(f"header length {n} is too small for a JSON object")
    if n > MAX_HEADER_BYTES:
        raise _Invalid(f"header length {n} exceeds the {MAX_HEADER_BYTES} byte limit")
    if 8 + n > size:
        raise _Invalid(f"header length {n} runs past the end of the {size} byte file")
    raw = f.read(n)
    if len(raw) != n:
        raise _Invalid("short read of the header")
    if raw[:1] != b"{":
        raise _Invalid("header does not start with an opening brace")
    try:
        text = raw.decode("utf-8")
        header = json.loads(text, object_pairs_hook=_no_duplicates)
    except _Invalid:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _Invalid(f"header is not valid UTF-8 JSON ({type(exc).__name__})") from exc
    if not isinstance(header, dict):
        raise _Invalid("header JSON is not an object")
    data_size = size - 8 - n
    if "__metadata__" in header:
        meta = header["__metadata__"]
        if not isinstance(meta, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in meta.items()):
            raise _Invalid("__metadata__ must be an object of string values")
    ranges: list[tuple[int, int]] = []
    for name, info in header.items():
        if name == "__metadata__":
            continue
        label = sanitize(name, 60)
        if not isinstance(info, dict):
            raise _Invalid(f"tensor {label}: entry is not an object")
        dtype = info.get("dtype")
        shape = info.get("shape")
        offsets = info.get("data_offsets")
        if not isinstance(dtype, str) or (dtype not in DTYPE_BYTES and dtype not in SUB_BYTE_DTYPES):
            raise _Invalid(f"tensor {label}: unknown dtype {sanitize(dtype, 20)}")
        if not isinstance(shape, list) or len(shape) > MAX_DIMS or not all(_is_int(d) and d >= 0 for d in shape):
            raise _Invalid(f"tensor {label}: invalid shape")
        if not isinstance(offsets, list) or len(offsets) != 2 or not all(_is_int(o) for o in offsets):
            raise _Invalid(f"tensor {label}: invalid data_offsets")
        begin, end = offsets
        if not 0 <= begin <= end <= data_size:
            raise _Invalid(f"tensor {label}: data_offsets [{begin}, {end}] outside the {data_size} byte data section")
        if dtype in DTYPE_BYTES:
            elements = 1
            for dim in shape:
                elements *= dim
            if end - begin != elements * DTYPE_BYTES[dtype]:
                raise _Invalid(f"tensor {label}: byte range does not match dtype and shape")
        ranges.append((begin, end))
    ranges.sort()
    cursor = 0
    for begin, end in ranges:
        if begin != cursor:
            raise _Invalid("tensor ranges overlap or leave a hole in the data section")
        cursor = end
    if cursor != data_size:
        raise _Invalid("tensor ranges do not cover the whole data section")


def scan_safetensors(f: BinaryIO, size: int) -> list[ScanFinding]:
    """[] when the header is valid, else one ART-ST-01 finding."""
    try:
        _validate(f, size)
    except _Invalid as exc:
        return [
            make_finding(
                "ART-ST-01",
                Severity.high,
                "Malformed safetensors header.",
                detail=f"{exc} (file size {size})",
                malicious=True,
            )
        ]
    except (OSError, MemoryError, OverflowError, struct.error) as exc:
        return [
            make_finding(
                "ART-ST-01",
                Severity.high,
                "Safetensors header could not be read.",
                detail=type(exc).__name__,
                malicious=True,
            )
        ]
    return []
