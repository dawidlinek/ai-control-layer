"""Format detection by magic bytes (never by extension) and extension families.

`detect_magic` looks only at the first bytes of a file. ZIP containers are refined by `classify_zip_names`
(torch / keras v3 / numpy npz / plain zip) once the central directory has been read.
"""

from __future__ import annotations

import ast
import re
import struct
from collections.abc import Iterable
from pathlib import PurePosixPath

MAGIC_GGUF = b"GGUF"
MAGIC_ZIP = (b"PK\x03\x04", b"PK\x05\x06")
MAGIC_7Z = b"7z\xbc\xaf\x27\x1c"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_XZ = b"\xfd7zXZ\x00"
MAGIC_RAR = b"Rar!\x1a\x07"
MAGIC_HDF5 = b"\x89HDF\r\n\x1a\n"
MAGIC_NUMPY = b"\x93NUMPY"

HDF5_OFFSETS = (0, 512, 1024, 2048)
HEAD_BYTES = 4096

ARCHIVE_FORMATS = frozenset({"7z", "gzip", "bzip2", "xz", "tar", "rar"})

# Extensions where a non-ZIP/non-pickle archive container is a format mismatch (nullifAI-style evasion).
PICKLE_FAMILY_EXTENSIONS = frozenset({".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib", ".keras"})
# Extensions that promise a pickle stream (or a torch zip around one).
PICKLE_EXTENSIONS = frozenset({".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib"})

# First bytes a protocol 0/1 pickle can plausibly start with.
PICKLE01_START = frozenset(b"(]})cNIFSVKMJBTXLGUC")

_BZIP2_RE = re.compile(rb"BZh[1-9]")
_BZIP2_STRICT_RE = re.compile(rb"BZh[1-9]\x31\x41\x59\x26\x53\x59")


def extension(filename: str) -> str:
    """Lower-cased final suffix, e.g. ".pt" (empty when there is none)."""
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    idx = name.rfind(".")
    return name[idx:].lower() if idx >= 0 else ""


def _is_hdf5(head: bytes) -> bool:
    return any(head.startswith(MAGIC_HDF5, off) for off in HDF5_OFFSETS)


def detect_magic(head: bytes, size: int) -> str:
    """Detect the container/format from the leading bytes; returns a `format_detected` token or "unknown"."""
    if head.startswith(MAGIC_GGUF):
        return "gguf"
    if head.startswith(MAGIC_ZIP):
        return "zip"
    if head.startswith(MAGIC_7Z):
        return "7z"
    if head.startswith(MAGIC_XZ):
        return "xz"
    if head.startswith(MAGIC_RAR):
        return "rar"
    if head.startswith(MAGIC_GZIP):
        return "gzip"
    if _BZIP2_RE.match(head):
        return "bzip2"
    if head[257:262] == b"ustar":
        return "tar"
    if _is_hdf5(head):
        return "hdf5"
    if head.startswith(MAGIC_NUMPY):
        return "numpy"
    # safetensors: u64 LE header length followed by a JSON object. Checked before pickle because the
    # little-endian length can legitimately start with 0x80 0x02..0x05.
    if size >= 10 and len(head) > 8 and head[8:9] == b"{":
        return "safetensors"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return "pickle"
    if head and head[0] in PICKLE01_START:
        return "pickle_maybe"
    return "unknown"


def nested_archive_kind(head: bytes) -> str | None:
    """Strict archive-magic test for members inside a model archive (3+ byte magics only, to avoid
    false positives on raw tensor bytes)."""
    if head.startswith(MAGIC_ZIP):
        return "zip"
    if head.startswith(MAGIC_7Z):
        return "7z"
    if head.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    if _BZIP2_STRICT_RE.match(head):
        return "bzip2"
    if head.startswith(MAGIC_XZ):
        return "xz"
    if head.startswith(MAGIC_RAR):
        return "rar"
    if head[257:262] == b"ustar":
        return "tar"
    return None


def _norm(name: str) -> str:
    return name.replace("\\", "/")


def is_raw_storage_member(name: str) -> bool:
    """`archive/data/<n>` (torch tensor storages) and `constants/<n>`: raw tensor bytes, never scanned as code."""
    parts = _norm(name).split("/")
    return len(parts) >= 2 and parts[-1].isdigit() and parts[-2] in {"data", "constants"}


def is_pickle_member(name: str) -> bool:
    low = _norm(name).lower()
    base = low.rsplit("/", 1)[-1]
    return low.endswith((".pkl", ".pickle")) or base == "data.pkl"


def classify_zip_names(names: Iterable[str]) -> str:
    """keras_v3 | torch_zip | numpy (npz) | zip."""
    normed = [_norm(n) for n in names]
    lowered = [n.lower() for n in normed]
    top = set(PurePosixPath(n).as_posix() for n in lowered)
    if "config.json" in top and ("model.weights.h5" in top or "metadata.json" in top):
        return "keras_v3"
    if any(n.endswith("data.pkl") for n in lowered):
        return "torch_zip"
    members = [n for n in lowered if not n.endswith("/")]
    if members and all(n.endswith(".npy") for n in members):
        return "numpy"
    return "zip"


def npy_info(head: bytes) -> tuple[int, bool] | None:
    """Parse a .npy header: (offset where array data starts, header mentions an object dtype), or None."""
    if not head.startswith(MAGIC_NUMPY) or len(head) < 10:
        return None
    major = head[6]
    if major == 1:
        hlen = struct.unpack_from("<H", head, 8)[0]
        start = 10
    elif major in (2, 3):
        if len(head) < 12:
            return None
        hlen = struct.unpack_from("<I", head, 8)[0]
        start = 12
    else:
        return None
    if hlen > 1 << 20:
        return None
    raw = head[start : start + hlen]
    text = raw.decode("latin-1")
    descr = ""
    try:
        parsed = ast.literal_eval(text.strip())
        if isinstance(parsed, dict):
            descr = repr(parsed.get("descr", ""))
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        descr = text
    return start + hlen, "O" in descr
