"""GGUF header and metadata validation (memory-safety bugs in parsers) plus chat-template injection check.

Only the header region is read from disk (bounded at 256 MiB; larger headers are malformed by definition). Every
count, length and offset is validated against the real file size *before* it is used to read or allocate. Tensor
data is never read.

Problems are reported as ART-GGUF-01 (malformed header/metadata) with the header facts in `detail`; a chat
template carrying template-injection markers is ART-GGUF-02 (CVE-2024-34359, llama-cpp-python rendering
templates with an unsandboxed Jinja environment).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from acl.artifacts.report import ScanFinding, make_finding
from acl.contracts.common import Severity

GGUF_MAGIC = b"GGUF"
SUPPORTED_VERSIONS = (1, 2, 3)
DEFAULT_ALIGNMENT = 32
MAX_ALIGNMENT = 1 << 16
MAX_KV = 65_536
MAX_TENSORS = 1_000_000
MAX_KEY_BYTES = 65_535
MAX_STRING_BYTES = 16 * 1024 * 1024
MAX_HEADER_BYTES = 256 * 1024 * 1024
MAX_LOOPED_ELEMENTS = 4_000_000
MAX_ARRAY_DEPTH = 2
MAX_DIMS = 4
MAX_GGML_TYPE = 39
_DIM_PRODUCT_LIMIT = 1 << 62
_CHUNK = 1 << 20

# value type id -> byte size for fixed-size scalars (uint8,int8,uint16,int16,uint32,int32,float32,bool,
# uint64,int64,float64); 8 = string, 9 = array.
_SCALAR_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_T_UINT32, _T_STRING, _T_ARRAY = 4, 8, 9
_VALID_VALUE_TYPES = frozenset(range(13))

# ggml type id -> (elements per block, bytes per block). Types not listed (removed or reserved ids) get the
# offset bound check only.
_GGML_BLOCKS: dict[int, tuple[int, int]] = {
    0: (1, 4),  # F32
    1: (1, 2),  # F16
    2: (32, 18),  # Q4_0
    3: (32, 20),  # Q4_1
    6: (32, 22),  # Q5_0
    7: (32, 24),  # Q5_1
    8: (32, 34),  # Q8_0
    9: (32, 36),  # Q8_1
    10: (256, 84),  # Q2_K
    11: (256, 110),  # Q3_K
    12: (256, 144),  # Q4_K
    13: (256, 176),  # Q5_K
    14: (256, 210),  # Q6_K
    15: (256, 292),  # Q8_K
    16: (256, 66),  # IQ2_XXS
    17: (256, 74),  # IQ2_XS
    18: (256, 98),  # IQ3_XXS
    19: (256, 50),  # IQ1_S
    20: (32, 18),  # IQ4_NL
    21: (256, 110),  # IQ3_S
    22: (256, 82),  # IQ2_S
    23: (256, 136),  # IQ4_XS
    24: (1, 1),  # I8
    25: (1, 2),  # I16
    26: (1, 4),  # I32
    27: (1, 8),  # I64
    28: (1, 8),  # F64
    29: (256, 56),  # IQ1_M
    30: (1, 2),  # BF16
    34: (256, 54),  # TQ1_0
    35: (256, 66),  # TQ2_0
    39: (32, 17),  # MXFP4
}

_TEMPLATE_LITERALS = (
    "__class__",
    "__globals__",
    "__subclasses__",
    "__builtins__",
    "__import__",
    "popen",
    "subprocess",
    "lipsum",
    "cycler",
    "joiner",
    "attr(",
)
_OS_RE = re.compile(r"(?<![A-Za-z0-9_])os\.")
_DUNDER_RE = re.compile(r"__[A-Za-z0-9_]+__")


class _Bad(Exception):
    pass


@dataclass(slots=True)
class _Facts:
    size: int
    version: int | None = None
    tensor_count: int | None = None
    kv_count: int | None = None
    alignment: int = DEFAULT_ALIGNMENT
    data_start: int | None = None
    templates: list[str] = field(default_factory=list)

    def describe(self) -> str:
        parts = [f"file_size={self.size}"]
        if self.version is not None:
            parts.append(f"version={self.version}")
        if self.tensor_count is not None:
            parts.append(f"tensors={self.tensor_count}")
        if self.kv_count is not None:
            parts.append(f"kv={self.kv_count}")
        parts.append(f"alignment={self.alignment}")
        if self.data_start is not None:
            parts.append(f"data_start={self.data_start}")
        return " ".join(parts)


class _Reader:
    """Bounded sequential reader: every request is checked against the file size and header limit first."""

    def __init__(self, f: BinaryIO, size: int) -> None:
        self.f = f
        self.size = size
        self.pos = 0
        self._buf = b""
        self._buf_start = 0

    def left(self) -> int:
        return self.size - self.pos

    def _check(self, n: int) -> None:
        if n < 0 or n > self.size - self.pos:
            raise _Bad("read past the end of the file")
        if self.pos + n > MAX_HEADER_BYTES:
            raise _Bad("header larger than the 256 MiB limit")

    def read(self, n: int) -> bytes:
        self._check(n)
        end = self.pos + n
        start = self._buf_start
        if start <= self.pos and end <= start + len(self._buf):
            out = self._buf[self.pos - start : end - start]
        else:
            self.f.seek(self.pos)
            if n > _CHUNK:
                out = self.f.read(n)
            else:
                self._buf = self.f.read(min(_CHUNK, self.size - self.pos, MAX_HEADER_BYTES - self.pos))
                self._buf_start = self.pos
                out = self._buf[:n]
            if len(out) != n:
                raise _Bad("short read")
        self.pos = end
        return out

    def skip(self, n: int) -> None:
        self._check(n)
        self.pos += n

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def length(self, version: int) -> int:
        return self.u32() if version == 1 else self.u64()


def template_markers(text: str) -> list[str]:
    """Names of template-injection markers present in a chat template (fixed vocabulary, never file text)."""
    low = text.lower()
    found = [marker for marker in _TEMPLATE_LITERALS if marker in low]
    if _OS_RE.search(text):
        found.append("os.")
    if _DUNDER_RE.search(text) and not any(m.startswith("__") for m in found):
        found.append("dunder attribute")
    return found


def _read_string(r: _Reader, version: int, keep: bool) -> bytes | None:
    n = r.length(version)
    if n > MAX_STRING_BYTES or n > r.left():
        raise _Bad("string length exceeds the 16 MiB limit or the remaining file")
    if keep:
        return r.read(n)
    r.skip(n)
    return None


@dataclass(slots=True)
class _State:
    looped: int = 0


def _skip_value(r: _Reader, vtype: int, version: int, depth: int, state: _State) -> None:
    if vtype in _SCALAR_SIZES:
        r.skip(_SCALAR_SIZES[vtype])
    elif vtype == _T_STRING:
        _read_string(r, version, keep=False)
    elif vtype == _T_ARRAY:
        _skip_array(r, version, depth + 1, state)
    else:
        raise _Bad(f"invalid value type {vtype}")


def _skip_array(r: _Reader, version: int, depth: int, state: _State) -> None:
    if depth > MAX_ARRAY_DEPTH:
        raise _Bad("array nesting deeper than 2")
    etype = r.u32()
    if etype not in _VALID_VALUE_TYPES:
        raise _Bad(f"invalid array element type {etype}")
    count = r.length(version)
    len_size = 4 if version == 1 else 8
    if etype in _SCALAR_SIZES:
        elem_min = _SCALAR_SIZES[etype]
    elif etype == _T_STRING:
        elem_min = len_size
    else:
        elem_min = 4 + len_size
    if count * elem_min > r.left():
        raise _Bad("array length exceeds the remaining file")
    if etype in _SCALAR_SIZES:
        r.skip(count * elem_min)
        return
    state.looped += count
    if state.looped > MAX_LOOPED_ELEMENTS:
        raise _Bad("too many array elements to walk")
    for _ in range(count):
        if etype == _T_STRING:
            _read_string(r, version, keep=False)
        else:
            _skip_array(r, version, depth + 1, state)


def _parse(f: BinaryIO, size: int, facts: _Facts) -> None:
    r = _Reader(f, size)
    if size < 16:
        raise _Bad("file shorter than the GGUF header")
    if r.read(4) != GGUF_MAGIC:
        raise _Bad("bad magic")
    version = r.u32()
    facts.version = version
    if version not in SUPPORTED_VERSIONS:
        raise _Bad(f"unsupported GGUF version {version} (big-endian files are not supported)")
    count_size = 4 if version == 1 else 8
    tensor_count = int.from_bytes(r.read(count_size), "little")
    kv_count = int.from_bytes(r.read(count_size), "little")
    facts.tensor_count, facts.kv_count = tensor_count, kv_count
    if kv_count > MAX_KV:
        raise _Bad("kv_count exceeds the 65536 limit")
    if tensor_count > MAX_TENSORS:
        raise _Bad("tensor_count exceeds the 1000000 limit")
    min_kv = 8 if version == 1 else 12
    min_tensor = 24 if version == 1 else 32
    if kv_count * min_kv + tensor_count * min_tensor > r.left():
        raise _Bad("kv/tensor counts cannot fit in the remaining file")

    state = _State()
    seen_keys: set[bytes] = set()
    for _ in range(kv_count):
        klen = r.length(version)
        if klen > MAX_KEY_BYTES or klen > r.left():
            raise _Bad("key length exceeds the limit or the remaining file")
        key = r.read(klen)
        if key in seen_keys:
            raise _Bad("duplicate metadata key")
        seen_keys.add(key)
        vtype = r.u32()
        if vtype not in _VALID_VALUE_TYPES:
            raise _Bad(f"invalid value type {vtype}")
        if key == b"general.alignment":
            if vtype != _T_UINT32:
                raise _Bad("general.alignment is not a uint32")
            alignment = r.u32()
            if alignment < 1 or alignment > MAX_ALIGNMENT or alignment & (alignment - 1):
                raise _Bad(f"general.alignment {alignment} is not a power of two in [1, 65536]")
            facts.alignment = alignment
        elif key.startswith(b"tokenizer.chat_template") and vtype == _T_STRING:
            raw = _read_string(r, version, keep=True)
            facts.templates.append((raw or b"").decode("utf-8", errors="replace"))
        else:
            _skip_value(r, vtype, version, 0, state)

    align = facts.alignment
    seen_names: set[bytes] = set()
    tensors: list[tuple[int, int | None]] = []
    for _ in range(tensor_count):
        nlen = r.length(version)
        if nlen > MAX_KEY_BYTES or nlen > r.left():
            raise _Bad("tensor name length exceeds the limit or the remaining file")
        name = r.read(nlen)
        if name in seen_names:
            raise _Bad("duplicate tensor name")
        seen_names.add(name)
        n_dims = r.u32()
        if not 1 <= n_dims <= MAX_DIMS:
            raise _Bad(f"tensor has {n_dims} dimensions (allowed 1..4)")
        dims: list[int] = []
        elements = 1
        for _d in range(n_dims):
            dim = r.u32() if version == 1 else r.u64()
            if dim < 1:
                raise _Bad("tensor dimension is zero")
            elements *= dim
            if elements >= _DIM_PRODUCT_LIMIT:
                raise _Bad("tensor element count overflows")
            dims.append(dim)
        gtype = r.u32()
        if gtype > MAX_GGML_TYPE:
            raise _Bad(f"unknown ggml tensor type {gtype}")
        offset = r.u64()
        if offset % align:
            raise _Bad("tensor offset is not a multiple of the alignment")
        nbytes: int | None = None
        block = _GGML_BLOCKS.get(gtype)
        if block is not None:
            per_block, bytes_per_block = block
            if dims[0] % per_block:
                raise _Bad("tensor row length is not a multiple of the block size")
            nbytes = (elements // per_block) * bytes_per_block
        tensors.append((offset, nbytes))

    data_start = (r.pos + align - 1) // align * align
    facts.data_start = data_start
    if tensors:
        avail = size - data_start
        if avail < 0:
            raise _Bad("header padding runs past the end of the file")
        for offset, nbytes in tensors:
            if offset > avail or (nbytes is not None and offset + nbytes > avail):
                raise _Bad("tensor data lies outside the file")


def scan_gguf(f: BinaryIO, size: int) -> list[ScanFinding]:
    """Validate a GGUF file. [] when sound; ART-GGUF-01 / ART-GGUF-02 findings otherwise."""
    facts = _Facts(size=size)
    findings: list[ScanFinding] = []
    try:
        _parse(f, size, facts)
    except _Bad as exc:
        findings.append(
            make_finding(
                "ART-GGUF-01",
                Severity.high,
                f"Malformed GGUF header or metadata: {exc}.",
                detail=facts.describe(),
                malicious=True,
            )
        )
    except (OSError, struct.error, OverflowError, MemoryError, ValueError) as exc:
        findings.append(
            make_finding(
                "ART-GGUF-01",
                Severity.high,
                f"GGUF header could not be parsed ({type(exc).__name__}).",
                detail=facts.describe(),
                malicious=True,
            )
        )
    for template in facts.templates:
        markers = template_markers(template)
        if markers:
            findings.append(
                make_finding(
                    "ART-GGUF-02",
                    Severity.critical,
                    "GGUF chat template contains template-injection markers.",
                    detail="markers: " + ", ".join(markers),
                    cve=("CVE-2024-34359",),
                    malicious=True,
                )
            )
            break
    return findings
