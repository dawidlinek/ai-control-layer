"""Static pickle opcode walker. Never calls `pickle.loads`, never imports anything named by the file.

The walker runs `pickletools.genops` over the stream and simulates the pickle stack just enough to resolve
`GLOBAL` / `INST` / `STACK_GLOBAL` references (string constants, memo, DUP/POP) and to see which referenced
globals are actually called (`REDUCE`, `BUILD`, `OBJ`, `INST`, `NEWOBJ`, `NEWOBJ_EX`).

Every parse error becomes a finding: a broken or truncated stream is treated as malicious (nullifAI puts the
payload before the break so the real unpickler executes it before failing). Findings gathered before the break
are kept. Work is bounded by an opcode limit; the caller bounds the byte size.
"""

from __future__ import annotations

import fnmatch
import io
import pickletools
import re
import warnings
from dataclasses import dataclass, field

from acl.artifacts.report import ScanFinding, make_finding, sanitize
from acl.contracts.common import Severity

MAX_OPCODES = 5_000_000
MAX_PICKLES = 64
MAX_GLOBALS = 2_000
MAX_FINDINGS_PER_RULE = 25
PROBE_MIN_OPCODES = 8

DANGEROUS_MODULES = frozenset(
    {
        "os", "posix", "nt", "subprocess", "socket", "runpy", "importlib", "shutil", "webbrowser", "sys", "pty",
        "commands", "ctypes", "code", "codeop", "marshal", "pickle", "_pickle", "dill", "cloudpickle", "types",
        "multiprocessing", "signal", "asyncio", "requests", "urllib", "urllib2", "urllib3", "http", "httplib",
        "ftplib", "smtplib", "telnetlib", "paramiko", "platform", "pip", "setuptools", "pkg_resources",
        # beyond the required list: other ways to run code or reach the network from a global reference
        "_socket", "_ctypes", "_posixsubprocess", "_winapi", "_thread", "_signal", "_asyncio", "pydoc",
        "timeit", "trace", "cProfile", "profile", "pdb", "bdb", "imp", "zipimport", "ensurepip", "venv",
        "distutils", "numpy.testing", "numpy.f2py", "torch.hub", "torch.distributed.rpc", "torch.utils.bottleneck",
    }
)  # fmt: skip
DANGEROUS_BUILTIN_NAMES = frozenset(
    {
        "exec", "eval", "compile", "open", "__import__", "getattr", "setattr", "delattr", "globals", "locals",
        "vars", "input", "breakpoint", "help", "exit", "quit", "memoryview",
    }
)  # fmt: skip
BUILTIN_MODULES = frozenset({"builtins", "__builtin__"})
GADGETS = frozenset(
    {
        "operator.attrgetter", "operator.methodcaller", "functools.partial",
        "_operator.attrgetter", "_operator.methodcaller", "_functools.partial",
    }
)  # fmt: skip
SAFE_BUILTIN_NAMES = frozenset({"set", "frozenset", "slice", "complex", "bytearray"})
SAFE_GLOBALS = frozenset(
    {
        "collections.OrderedDict",
        "torch._utils._rebuild_tensor",
        "torch._utils._rebuild_tensor_v2",
        "torch._utils._rebuild_parameter",
        "torch._utils._rebuild_parameter_with_state",
        "torch.Size",
        "torch.device",
        "numpy.core.multiarray._reconstruct",
        "numpy._core.multiarray._reconstruct",
        "numpy.core.multiarray.scalar",
        "numpy._core.multiarray.scalar",
        "numpy.ndarray",
        "numpy.dtype",
        "_codecs.encode",
    }
)
TORCH_DTYPE_NAMES = frozenset(
    {
        "float16", "float32", "float64", "bfloat16", "half", "float", "double", "int8", "int16", "int32", "int64",
        "uint8", "bool", "short", "int", "long", "complex64", "complex128",
    }
)  # fmt: skip
CALL_OPCODES = frozenset({"REDUCE", "BUILD", "OBJ", "INST", "NEWOBJ", "NEWOBJ_EX"})
_STRING_OPCODES = frozenset(
    {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}
)
_PUT_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PADDING_RE = re.compile(rb"[\x00\s]*")
_LEGACY_NOTE = "legacy non-zip torch checkpoints hold several pickles by design and are still refused"


def classify_global(module: str, name: str) -> tuple[str, str]:
    """Return ("dangerous" | "safe" | "unknown", reason) for a resolved `module.name` global."""
    mod = module.strip().lower()
    parts = mod.split(".")
    for i in range(1, len(parts) + 1):
        prefix = ".".join(parts[:i])
        if prefix in DANGEROUS_MODULES:
            return "dangerous", f"module {prefix} is on the dangerous-module list"
    name_parts = name.split(".")
    first = name_parts[0]
    if mod in BUILTIN_MODULES and first.lower() in DANGEROUS_BUILTIN_NAMES:
        return "dangerous", f"builtin {first} executes or reflects on code"
    if f"{mod}.{name}".lower() in GADGETS:
        return "dangerous", "callable gadget (attribute/method/partial application)"
    if len(name_parts) > 1:
        # Protocol 4 qualified names walk attributes (`torch` + `os.system`): flag any component that reaches
        # a dangerous module or builtin.
        for part in name_parts:
            low = part.lower()
            if low in DANGEROUS_MODULES or low in DANGEROUS_BUILTIN_NAMES:
                return "dangerous", f"attribute path reaches {part}"
    if _is_safe(mod, module.strip(), name):
        return "safe", ""
    return "unknown", "global is not on the safe allowlist"


def _is_safe(mod: str, module: str, name: str) -> bool:
    if "." in name and mod not in BUILTIN_MODULES:
        return f"{module}.{name}" in SAFE_GLOBALS
    if mod in BUILTIN_MODULES:
        return name in SAFE_BUILTIN_NAMES
    if f"{module}.{name}" in SAFE_GLOBALS:
        return True
    if module in ("torch", "torch.storage") and name.endswith("Storage") and "." not in name:
        return True
    return module == "torch" and name in TORCH_DTYPE_NAMES


def torch_version_ok(version: str, minimum: str = "2.6.0") -> bool:
    """True if `version` >= `minimum` (numeric compare; tolerates `+cu121`, `rc1`, `.dev0` suffixes)."""

    def parse(text: str) -> tuple[int, ...] | None:
        match = re.match(r"\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
        if match is None:
            return None
        return tuple(int(g) if g is not None else 0 for g in match.groups())

    have, need = parse(version), parse(minimum)
    if have is None or need is None:
        return False
    return have >= need


def torch_note(minimum: str = "2.6.0") -> ScanFinding:
    return make_finding(
        "ART-TORCH-01",
        Severity.info,
        f"Pickle-based torch file: load only with torch>={minimum} and weights_only=True (CVE-2025-32434).",
        cve=("CVE-2025-32434",),
    )


class _Ref:
    """A resolved global reference sitting on the simulated stack."""

    __slots__ = ("module", "name")

    def __init__(self, module: str, name: str) -> None:
        self.module = module
        self.name = name

    @property
    def full(self) -> str:
        return f"{self.module}.{self.name}"


_MARK = object()


@dataclass(slots=True)
class _GlobalInfo:
    module: str
    name: str
    opcode: str
    offset: int
    called: set[str] = field(default_factory=set)


@dataclass(slots=True)
class PickleScan:
    globals: list[str] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)
    pickles: int = 0
    opcodes: int = 0
    underflows: int = 0
    broken: bool = False
    limit_hit: bool = False

    def pickle_like(self) -> bool:
        """Probe verdict: enough well-formed opcodes (or any global) to call this stream a pickle."""
        return self.opcodes >= PROBE_MIN_OPCODES or bool(self.globals)


class _Walker:
    def __init__(
        self,
        scan: PickleScan,
        opcode_globs: tuple[tuple[str, str], ...],
        max_opcodes: int,
        label: str,
    ) -> None:
        self.scan = scan
        self.opcode_globs = opcode_globs
        self.max_opcodes = max_opcodes
        self.label = f" in {sanitize(label, 120)}" if label else ""
        self.infos: dict[str, _GlobalInfo] = {}
        self.rule_counts: dict[str, int] = {}
        self.seen_findings: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ findings
    def add(self, key: str, finding: ScanFinding) -> None:
        marker = (finding.rule_id, key)
        if marker in self.seen_findings:
            return
        count = self.rule_counts.get(finding.rule_id, 0)
        if count >= MAX_FINDINGS_PER_RULE:
            return
        self.seen_findings.add(marker)
        self.rule_counts[finding.rule_id] = count + 1
        self.scan.findings.append(finding)

    def _record_global(self, module: str, name: str, opcode: str, offset: int) -> _Ref:
        ref = _Ref(module, name)
        full = ref.full
        if full not in self.infos:
            if len(self.infos) >= MAX_GLOBALS:
                self.scan.limit_hit = True
                return ref
            self.infos[full] = _GlobalInfo(module=module, name=name, opcode=opcode, offset=offset)
            if full not in self.scan.globals:
                self.scan.globals.append(full)
        return ref

    def _note_call(self, ref: _Ref, op: str) -> None:
        info = self.infos.get(ref.full)
        if info is not None:
            info.called.add(op)

    def finish(self) -> None:
        """Turn the collected globals into findings once every pickle of the stream has been walked."""
        for full, info in self.infos.items():
            if full == "?.?":
                self.add(
                    full,
                    make_finding(
                        "ART-PICKLE-02",
                        Severity.medium,
                        "Pickle uses a STACK_GLOBAL whose module/name could not be resolved statically.",
                        detail=f"{info.opcode} ?.? at offset {info.offset}{self.label}",
                    ),
                )
                continue
            kind, reason = classify_global(info.module, info.name)
            via = f" via {', '.join(sorted(info.called))}" if info.called else " (referenced, never called)"
            detail = f"{info.opcode} {full}{via} at offset {info.offset}{self.label}"
            if kind == "dangerous":
                self.add(
                    full,
                    make_finding(
                        "ART-PICKLE-01",
                        Severity.critical,
                        f"Pickle references dangerous global {full}: {reason}.",
                        detail=detail,
                        malicious=True,
                    ),
                )
            elif kind == "unknown":
                self.add(
                    full,
                    make_finding(
                        "ART-PICKLE-02",
                        Severity.medium,
                        f"Pickle references global {full} outside the safe allowlist.",
                        detail=detail,
                    ),
                )
            for sig_id, glob in self.opcode_globs:
                if fnmatch.fnmatchcase(full, glob):
                    self.add(
                        f"{sig_id}:{full}",
                        make_finding(
                            sig_id,
                            Severity.high,
                            f"Pickle global {full} matches signature feed entry {sig_id}.",
                            detail=detail,
                            malicious=True,
                        ),
                    )

    # ------------------------------------------------------------------ one pickle
    def run_one(self, data: bytes, start: int, *, quiet_if_empty: bool, partial: bool) -> tuple[int, str]:
        """Walk one pickle starting at `start`. Returns (end offset, status) with status in
        stop | error | limit. A parse error is recorded as ART-PICKLE-03 here."""
        stream = io.BytesIO(data)
        stream.seek(start)
        stack: list[object] = []
        memo: dict[int, object] = {}
        opcodes_here = 0
        status = "error"
        end = start
        err: Exception | None = None
        ops = pickletools.genops(stream)
        # pickletools decodes STRING arguments with codecs.escape_decode, which warns on odd escapes.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            while True:
                try:
                    info, arg, pos = next(ops)
                except StopIteration:
                    break
                except Exception as exc:  # genops raises ValueError & friends on any malformed stream
                    err = exc
                    end = stream.tell()
                    break
                self.scan.opcodes += 1
                opcodes_here += 1
                if self.scan.opcodes > self.max_opcodes:
                    status = "limit"
                    break
                self._step(info, arg, pos, stack, memo)
                if info.name == "STOP":
                    status = "stop"
                    end = stream.tell()
                    break
        if status == "limit":
            self.scan.limit_hit = True
        elif status == "error" and not partial and not (quiet_if_empty and opcodes_here == 0):
            self.scan.broken = True
            kind = type(err).__name__ if err is not None else "EOF"
            self.add(
                f"broken@{start}",
                make_finding(
                    "ART-PICKLE-03",
                    Severity.critical,
                    "Pickle stream is broken or truncated before STOP: an unpickler executes everything "
                    "before the break (nullifAI evasion), so the file is treated as malicious.",
                    detail=f"{kind} after {opcodes_here} opcodes at byte offset {end}{self.label}",
                    malicious=True,
                ),
            )
        return end, status

    def _pop(self, stack: list[object], n: int) -> list[object]:
        if n > len(stack):
            self.scan.underflows += 1
            n = len(stack)
        if n <= 0:
            return []
        out = stack[-n:]
        del stack[-n:]
        return out

    def _pop_to_mark(self, stack: list[object]) -> list[object]:
        for i in range(len(stack) - 1, -1, -1):
            if stack[i] is _MARK:
                out = stack[i + 1 :]
                del stack[i:]
                return out
        self.scan.underflows += 1
        out = list(stack)
        stack.clear()
        return out

    def _step(
        self, info: pickletools.OpcodeInfo, arg: object, pos: int, stack: list[object], memo: dict[int, object]
    ) -> None:
        name = info.name
        if name in _STRING_OPCODES:
            stack.append(arg if isinstance(arg, str) else None)
            return
        if name == "MARK":
            stack.append(_MARK)
            return
        if name in _PUT_OPCODES:
            if isinstance(arg, int):
                memo[arg] = stack[-1] if stack else None
            return
        if name == "MEMOIZE":
            memo[len(memo)] = stack[-1] if stack else None
            return
        if name in _GET_OPCODES:
            stack.append(memo.get(arg) if isinstance(arg, int) else None)
            return
        if name == "DUP":
            stack.append(stack[-1] if stack else None)
            return
        if name in ("GLOBAL", "INST"):
            text = arg if isinstance(arg, str) else ""
            module, _, attr = text.partition(" ")
            ref = self._record_global(module, attr, name, pos)
            if name == "INST":
                self._pop_to_mark(stack)
                self._note_call(ref, "INST")
                stack.append(None)
            else:
                stack.append(ref)
            return
        if name == "STACK_GLOBAL":
            items = self._pop(stack, 2)
            if len(items) == 2 and isinstance(items[0], str) and isinstance(items[1], str):
                stack.append(self._record_global(items[0], items[1], name, pos))
            else:
                stack.append(self._record_global("?", "?", name, pos))
            return
        if name == "REDUCE":
            items = self._pop(stack, 2)
            if len(items) == 2 and isinstance(items[0], _Ref):
                self._note_call(items[0], "REDUCE")
            stack.append(None)
            return
        if name in ("NEWOBJ", "NEWOBJ_EX"):
            items = self._pop(stack, 2 if name == "NEWOBJ" else 3)
            if items and isinstance(items[0], _Ref):
                self._note_call(items[0], name)
            stack.append(None)
            return
        if name == "OBJ":
            items = self._pop_to_mark(stack)
            if items and isinstance(items[0], _Ref):
                self._note_call(items[0], "OBJ")
            stack.append(None)
            return
        if name == "BUILD":
            items = self._pop(stack, 2)
            if items and isinstance(items[0], _Ref):
                self._note_call(items[0], "BUILD")
            stack.append(None)
            return
        if name in ("EXT1", "EXT2", "EXT4"):
            self.add(
                f"ext@{pos}",
                make_finding(
                    "ART-PICKLE-02",
                    Severity.medium,
                    "Pickle resolves a global through the copyreg extension registry (opaque reference).",
                    detail=f"{name} at offset {pos}{self.label}",
                ),
            )
            stack.append(None)
            return
        # Generic stack effect from the opcode table.
        before = [obj.name for obj in info.stack_before]
        if "mark" in before:
            self._pop_to_mark(stack)
            self._pop(stack, before.index("mark"))
        else:
            self._pop(stack, len(before))
        for _ in info.stack_after:
            stack.append(None)


def scan_pickle(
    data: bytes,
    *,
    label: str = "",
    opcode_globs: tuple[tuple[str, str], ...] = (),
    max_opcodes: int = MAX_OPCODES,
    partial: bool = False,
    probe: bool = False,
) -> PickleScan:
    """Walk every pickle in `data` (never executes anything).

    `partial` means `data` is a truncated prefix chosen by the caller (size cap), so a cut-off stream is not
    reported as broken. `probe` is for unknown content: a stream that fails immediately is silently "not a pickle".
    """
    scan = PickleScan()
    walker = _Walker(scan, opcode_globs, max_opcodes, label)
    total = len(data)
    pos = 0
    index = 0
    while True:
        if index >= MAX_PICKLES:
            scan.limit_hit = True
            break
        before = scan.opcodes
        end, status = walker.run_one(data, pos, quiet_if_empty=probe if index == 0 else True, partial=partial)
        parsed = scan.opcodes - before
        if index > 0:
            if parsed == 0:
                walker.add(
                    f"trailing@{pos}",
                    make_finding(
                        "ART-PICKLE-04",
                        Severity.critical,
                        f"Unparsable trailing data after STOP of the first pickle ({_LEGACY_NOTE}).",
                        detail=f"{total - pos} bytes after offset {pos}{walker.label}",
                        malicious=True,
                    ),
                )
                break
            walker.add(
                f"multi@{pos}",
                make_finding(
                    "ART-PICKLE-04",
                    Severity.critical,
                    f"Multiple pickles in one stream ({_LEGACY_NOTE}).",
                    detail=f"additional pickle at offset {pos}{walker.label}",
                    malicious=True,
                ),
            )
        if parsed:
            scan.pickles += 1
        index += 1
        if status != "stop":
            break
        nxt = _PADDING_RE.match(data, end).end()
        if nxt >= total:
            break
        pos = nxt
    if scan.limit_hit and not partial:
        walker.add(
            "limits",
            make_finding(
                "ART-PICKLE-05",
                Severity.high,
                "Pickle exceeds the scanner's opcode/stream limits and could not be fully walked.",
                detail=f"opcodes walked: {scan.opcodes}, pickles: {scan.pickles}{walker.label}",
            ),
        )
    walker.finish()
    return scan
