"""Keras model checks: Lambda layers (CVE-2024-3660) and arbitrary module/function references (CVE-2025-1550).

* `.keras` (v3) is a ZIP whose `config.json` is parsed (bounded) and walked iteratively; no code is ever deserialised.
* HDF5 (`.h5` / `.hdf5`, legacy Keras): no HDF5 library is available, so the `model_config` JSON attribute is
  located with a bounded *byte heuristic* (whitespace-tolerant regexes over the raw file, first 1 GiB). This is an
  honest limitation: a config stored in an unusual HDF5 layout, split across chunks beyond the scan window, or
  JSON-escaped in a way the regexes do not expect can be missed. Both formats are blocked by default anyway; the
  heuristic only decides between `blocked_format` and `malicious`.
"""

from __future__ import annotations

import json
import re
from typing import Any, BinaryIO

from acl.artifacts.report import ScanFinding, make_finding, sanitize
from acl.contracts.common import Severity

MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_NODES = 2_000_000
MAX_DEPTH = 200
MAX_REPORTED = 20
HDF5_SCAN_BYTES = 1024**3
HDF5_CHUNK = 8 * 1024 * 1024
HDF5_OVERLAP = 512

_LAMBDA_RE = re.compile(rb'"class_name"\s*:\s*"(?:Lambda|__lambda__)"')
_MODULE_RE = re.compile(rb'"module"\s*:\s*"([^"\\]{0,256})"')
_CVE_LAMBDA = ("CVE-2024-3660",)
_CVE_MODULE = ("CVE-2025-1550",)


def _is_keras_module(value: str) -> bool:
    return value == "keras" or value.startswith("keras.")


def _lambda_finding(where: str) -> ScanFinding:
    return make_finding(
        "ART-KERAS-01",
        Severity.critical,
        "Keras model contains a Lambda layer (arbitrary Python code executed on load).",
        detail=where,
        cve=_CVE_LAMBDA,
        malicious=True,
    )


def _module_finding(module: str, where: str) -> ScanFinding:
    return make_finding(
        "ART-KERAS-02",
        Severity.critical,
        f"Keras config references a module outside keras: {sanitize(module, 80)}.",
        detail=where,
        cve=_CVE_MODULE,
        malicious=True,
    )


def scan_keras_config(raw: bytes) -> list[ScanFinding]:
    """Walk a Keras v3 `config.json`. Unparsable or over-deep configs are malicious (fail closed)."""
    findings: list[ScanFinding] = []
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return [
            make_finding(
                "ART-KERAS-02",
                Severity.high,
                "Keras config.json is not valid UTF-8 JSON and cannot be verified.",
                cve=_CVE_MODULE,
                malicious=True,
            )
        ]
    seen: set[tuple[str, str]] = set()

    def report(finding: ScanFinding, key: tuple[str, str]) -> None:
        if key not in seen and len(findings) < MAX_REPORTED:
            seen.add(key)
            findings.append(finding)

    stack: list[tuple[Any, int, str]] = [(config, 0, "$")]
    nodes = 0
    while stack:
        node, depth, path = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            report(
                make_finding(
                    "ART-KERAS-02",
                    Severity.high,
                    "Keras config is too large or too deeply nested to verify.",
                    detail=f"nodes>{MAX_NODES} or depth>{MAX_DEPTH}",
                    cve=_CVE_MODULE,
                    malicious=True,
                ),
                ("limits", ""),
            )
            break
        if isinstance(node, list):
            stack.extend((item, depth + 1, f"{path}[{i}]") for i, item in enumerate(node))
            continue
        if not isinstance(node, dict):
            continue
        class_name = node.get("class_name")
        if class_name in ("Lambda", "__lambda__"):
            report(_lambda_finding(f"class_name {class_name} at {sanitize(path, 120)}"), ("lambda", path))
        module = node.get("module")
        if isinstance(module, str) and not _is_keras_module(module):
            report(_module_finding(module, f"module reference at {sanitize(path, 120)}"), ("module", module))
        registered = node.get("registered_name")
        if isinstance(registered, str) and ">" in registered:
            package = registered.split(">", 1)[0]
            if package != "keras":
                report(
                    make_finding(
                        "ART-KERAS-02",
                        Severity.critical,
                        f"Keras config uses a custom registered object: {sanitize(registered, 80)}.",
                        detail=f"registered_name at {sanitize(path, 120)}",
                        cve=_CVE_MODULE,
                        malicious=True,
                    ),
                    ("registered", registered),
                )
        function = node.get("function")
        if isinstance(function, dict):
            fmod = function.get("module")
            if "function_name" in function and not (isinstance(fmod, str) and _is_keras_module(fmod)):
                report(
                    _module_finding(str(fmod), f"function reference at {sanitize(path, 120)}"), ("module", str(fmod))
                )
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                stack.append((value, depth + 1, f"{path}.{sanitize(key, 40)}"))
    return findings


def scan_hdf5(f: BinaryIO, size: int) -> list[ScanFinding]:
    """Byte-heuristic scan of a legacy Keras HDF5 file for Lambda layers / non-keras module references."""
    findings: list[ScanFinding] = []
    seen_modules: set[bytes] = set()
    lambda_seen = False
    limit = min(size, HDF5_SCAN_BYTES)
    pos = 0
    carry = b""
    f.seek(0)
    while pos < limit:
        chunk = f.read(min(HDF5_CHUNK, limit - pos))
        if not chunk:
            break
        window = carry + chunk
        base = pos - len(carry)
        if not lambda_seen and (b"Lambda" in window or b"__lambda__" in window):
            match = _LAMBDA_RE.search(window)
            if match is not None:
                lambda_seen = True
                findings.append(_lambda_finding(f"Lambda class_name in model_config near byte {base + match.start()}"))
        if b'"module"' in window:
            for match in _MODULE_RE.finditer(window):
                value = match.group(1)
                if value in seen_modules or len(seen_modules) >= MAX_REPORTED:
                    continue
                text = value.decode("latin-1")
                if not _is_keras_module(text):
                    seen_modules.add(value)
                    findings.append(_module_finding(text, f"module reference near byte {base + match.start()}"))
        pos += len(chunk)
        carry = window[-HDF5_OVERLAP:]
    return findings
