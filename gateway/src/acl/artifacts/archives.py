"""ZIP container checks for torch / keras v3 / numpy archives.

Nothing is extracted to disk and nothing is imported. Member data is read through `zipfile` with hard byte caps,
and declared sizes are checked before anything is read. Hostile structure (traversal names, duplicate members that
different parsers resolve differently, encrypted members, bombs, nested archives, corrupt directories) is
ART-ARCHIVE-03 / ART-ARCHIVE-02 and counts as malicious: an archive we cannot verify is not "unscannable", it is
evasion.

Pickles are walked in every member that is named like one (`*.pkl`, `data.pkl`) and also in any other member
outside the raw-storage pattern (`*/data/<digits>`) whose leading bytes look like a pickle, so a payload cannot
hide behind an innocent member name.
"""

from __future__ import annotations

import re
import struct
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import BinaryIO

from acl.artifacts.formats import (
    PICKLE01_START,
    classify_zip_names,
    is_pickle_member,
    is_raw_storage_member,
    nested_archive_kind,
    npy_info,
)
from acl.artifacts.keras import scan_keras_config
from acl.artifacts.pickle_walk import PickleScan, scan_pickle
from acl.artifacts.report import ScanFinding, ScanPolicy, make_finding, sanitize
from acl.contracts.common import Severity

MAX_RATIO = 200
RATIO_FLOOR_BYTES = 1024 * 1024
MEMBER_HEAD_BYTES = 512
MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_REPORTED_PER_RULE = 20
_EOCD_SIG = b"PK\x05\x06"
_EOCD_TAIL = 65_535 + 22
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ZIP_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    NotImplementedError,
    RuntimeError,
    ValueError,
    OSError,
    EOFError,
    OverflowError,
    struct.error,
    zlib.error,
)


@dataclass(slots=True)
class ZipScan:
    format: str = "zip"
    findings: list[ScanFinding] = field(default_factory=list)
    pickle_globals: list[str] = field(default_factory=list)


def eocd_entry_count(f: BinaryIO, size: int) -> tuple[int, int] | None:
    """(total entries, central directory size) from the last end-of-central-directory record, or None."""
    tail_len = min(size, _EOCD_TAIL)
    f.seek(size - tail_len)
    tail = f.read(tail_len)
    idx = tail.rfind(_EOCD_SIG)
    if idx < 0 or len(tail) - idx < 22:
        return None
    total_entries = struct.unpack_from("<H", tail, idx + 10)[0]
    cd_size = struct.unpack_from("<I", tail, idx + 12)[0]
    return total_entries, cd_size


def looks_like_zip(f: BinaryIO, size: int) -> bool:
    """True if the tail of the file is a structurally valid ZIP end record (used for polyglot detection)."""
    try:
        info = eocd_entry_count(f, size)
        if info is None:
            return False
        total, cd_size = info
        tail_len = min(size, _EOCD_TAIL)
        f.seek(size - tail_len)
        tail = f.read(tail_len)
        idx = tail.rfind(_EOCD_SIG)
        eocd_pos = size - tail_len + idx
        cd_start = eocd_pos - cd_size
        if total == 0 or cd_size == 0 or cd_start < 0:
            return False
        f.seek(cd_start)
        return f.read(4) == b"PK\x01\x02"
    except (OSError, struct.error, ValueError):
        return False


def _bad_name(name: str) -> bool:
    norm = name.replace("\\", "/")
    if norm.startswith("/") or _DRIVE_RE.match(norm):
        return True
    return any(part == ".." for part in norm.split("/"))


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> bytes:
    with zf.open(info) as member:
        return member.read(cap)


def _pickle_candidate(head: bytes) -> bool:
    """Leading bytes of a member that could start a pickle (protocol 2+ header or a protocol 0/1 opcode)."""
    if not head:
        return False
    if head[0] == 0x80:
        return len(head) > 1 and 2 <= head[1] <= 5
    return head[0] in PICKLE01_START


def scan_zip(f: BinaryIO, size: int, policy: ScanPolicy) -> ZipScan:
    """Scan a ZIP-container model file (torch zip, keras v3, npz, plain zip)."""
    result = ZipScan()
    counts: dict[str, int] = {}

    def add(finding: ScanFinding) -> None:
        n = counts.get(finding.rule_id, 0)
        if n >= MAX_REPORTED_PER_RULE:
            return
        counts[finding.rule_id] = n + 1
        result.findings.append(finding)

    def corrupt(reason: str) -> None:
        add(
            make_finding(
                "ART-ARCHIVE-03",
                Severity.high,
                f"Corrupt or unverifiable ZIP archive: {reason}.",
                malicious=True,
            )
        )

    try:
        eocd = eocd_entry_count(f, size)
    except (OSError, struct.error):
        eocd = None
    if eocd is not None:
        total_entries, cd_size = eocd
        if total_entries > policy.max_archive_members:
            add(
                make_finding(
                    "ART-ARCHIVE-03",
                    Severity.high,
                    "ZIP archive declares too many members.",
                    detail=f"declared entries {total_entries}, limit {policy.max_archive_members}",
                    malicious=True,
                )
            )
            return result
        if cd_size > 256 * 1024 * 1024:
            corrupt("central directory is implausibly large")
            return result

    try:
        f.seek(0)
        zf = zipfile.ZipFile(f)
    except _ZIP_ERRORS:
        corrupt("the central directory could not be parsed")
        return result

    with zf:
        infos = zf.infolist()
        if len(infos) > policy.max_archive_members:
            add(
                make_finding(
                    "ART-ARCHIVE-03",
                    Severity.high,
                    "ZIP archive has too many members.",
                    detail=f"{len(infos)} members, limit {policy.max_archive_members}",
                    malicious=True,
                )
            )
            return result
        names = [i.filename for i in infos]
        result.format = classify_zip_names(names)

        seen_names: set[str] = set()
        total_uncompressed = 0
        for info in infos:
            label = sanitize(info.filename, 100)
            norm = info.filename.replace("\\", "/")
            if norm in seen_names:
                add(
                    make_finding(
                        "ART-ARCHIVE-03",
                        Severity.high,
                        "ZIP archive has duplicate member names (parsers disagree about which one counts).",
                        detail=f"member {label}",
                        malicious=True,
                    )
                )
            seen_names.add(norm)
            if _bad_name(info.filename):
                add(
                    make_finding(
                        "ART-ARCHIVE-03",
                        Severity.high,
                        "ZIP member name escapes the archive root (path traversal / absolute path).",
                        detail=f"member {label}",
                        malicious=True,
                    )
                )
            if info.flag_bits & 0x1:
                add(
                    make_finding(
                        "ART-ARCHIVE-03",
                        Severity.high,
                        "ZIP member is encrypted and cannot be inspected.",
                        detail=f"member {label}",
                        malicious=True,
                    )
                )
            total_uncompressed += info.file_size
            if info.file_size >= RATIO_FLOOR_BYTES and info.file_size > MAX_RATIO * max(info.compress_size, 1):
                add(
                    make_finding(
                        "ART-ARCHIVE-03",
                        Severity.high,
                        f"ZIP member compression ratio exceeds {MAX_RATIO}:1 (zip bomb).",
                        detail=f"member {label}: {info.compress_size} -> {info.file_size} bytes",
                        malicious=True,
                    )
                )
        if total_uncompressed > policy.max_uncompressed_bytes:
            add(
                make_finding(
                    "ART-ARCHIVE-03",
                    Severity.high,
                    "ZIP archive expands beyond the uncompressed size limit.",
                    detail=f"declared total {total_uncompressed}, limit {policy.max_uncompressed_bytes}",
                    malicious=True,
                )
            )

        for info in infos:
            if info.is_dir() or info.flag_bits & 0x1:
                continue
            label = sanitize(info.filename, 100)
            name = info.filename
            storage = is_raw_storage_member(name)
            wants_pickle = is_pickle_member(name)
            is_npy = result.format == "numpy" and name.lower().endswith(".npy")
            is_keras_config = result.format == "keras_v3" and name == "config.json"
            if storage and not wants_pickle:
                continue
            if wants_pickle or is_npy:
                cap = policy.max_pickle_bytes + 1
            elif is_keras_config:
                cap = MAX_CONFIG_BYTES + 1
            elif info.file_size > 0:
                cap = MEMBER_HEAD_BYTES  # only the leading bytes: nested-archive / pickle-look check
            else:
                continue
            try:
                data = _read_member(zf, info, cap)
            except _ZIP_ERRORS:
                corrupt(f"member {label} cannot be read")
                continue
            kind = nested_archive_kind(data[:MEMBER_HEAD_BYTES])
            if kind is not None:
                add(
                    make_finding(
                        "ART-ARCHIVE-02",
                        Severity.critical,
                        f"Nested {kind} archive inside a model archive.",
                        detail=f"member {label}",
                        malicious=True,
                    )
                )
                continue
            if cap == MEMBER_HEAD_BYTES:
                if _pickle_candidate(data):
                    _walk_hidden_member(zf, info, policy, result, add, corrupt)
                continue
            if wants_pickle:
                partial = len(data) > policy.max_pickle_bytes
                walked = scan_pickle(
                    data[: policy.max_pickle_bytes] if partial else data,
                    label=name,
                    opcode_globs=policy.opcode_globs,
                    partial=partial,
                )
                _merge(result, walked)
                if partial:
                    add(
                        make_finding(
                            "ART-PICKLE-05",
                            Severity.high,
                            "Pickle member exceeds the size limit; only its first bytes were walked.",
                            detail=f"member {label}, limit {policy.max_pickle_bytes}",
                        )
                    )
            elif is_npy:
                parsed = npy_info(data[:4096])
                if parsed is not None and parsed[1]:
                    walked = scan_pickle(
                        data[parsed[0] : policy.max_pickle_bytes],
                        label=name,
                        opcode_globs=policy.opcode_globs,
                        probe=True,
                    )
                    if walked.pickle_like():
                        _merge(result, walked)
            elif is_keras_config:
                if len(data) > MAX_CONFIG_BYTES:
                    corrupt("Keras config.json exceeds the size limit")
                else:
                    for finding in scan_keras_config(data):
                        add(finding)
    return result


def _walk_hidden_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    policy: ScanPolicy,
    result: ZipScan,
    add: Callable[[ScanFinding], None],
    corrupt: Callable[[str], None],
) -> None:
    """Walk a member that is not named like a pickle but starts like one."""
    label = sanitize(info.filename, 100)
    try:
        data = _read_member(zf, info, policy.max_pickle_bytes + 1)
    except _ZIP_ERRORS:
        corrupt(f"member {label} cannot be read")
        return
    protocol2 = data[:1] == b"\x80"
    partial = len(data) > policy.max_pickle_bytes
    walked = scan_pickle(
        data[: policy.max_pickle_bytes] if partial else data,
        label=info.filename,
        opcode_globs=policy.opcode_globs,
        partial=partial,
        probe=not protocol2,
    )
    # Protocol 2+ header: certainly a pickle. Protocol 0/1: only if it parses as one (text such as source
    # code or notes that merely starts with a pickle opcode letter is ignored) or already carries a malicious hit.
    hostile = any(f.malicious and f.rule_id not in ("ART-PICKLE-03", "ART-PICKLE-04") for f in walked.findings)
    if protocol2 or (walked.pickle_like() and (not walked.broken or hostile)):
        _merge(result, walked)
        if partial:
            add(
                make_finding(
                    "ART-PICKLE-05",
                    Severity.high,
                    "Pickle-like member exceeds the size limit; only its first bytes were walked.",
                    detail=f"member {label}, limit {policy.max_pickle_bytes}",
                )
            )


def _merge(result: ZipScan, walked: PickleScan) -> None:
    result.findings.extend(walked.findings)
    for g in walked.globals:
        if g not in result.pickle_globals:
            result.pickle_globals.append(g)
