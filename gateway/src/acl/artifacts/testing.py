"""Deterministic fixture generators for the model-artifact scanner (unit tests and YAML system cases).

Everything is generated in code, is tiny and byte-for-byte reproducible. Malicious pickles are *assembled from
opcodes* (never produced by running `os.system`): the payload is only ever a string constant such as
`echo rogatka-test` and nothing here, or in the scanner, unpickles or executes any of it. Module names matter for
the signatures, so GLOBAL opcodes are written by hand instead of relying on the platform's `os`/`posix` alias.
"""

from __future__ import annotations

import atexit
import io
import json
import pickle
import shutil
import struct
import tempfile
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path

_ZIP_DATE = (2020, 1, 1, 0, 0, 0)
_PAYLOAD = "echo rogatka-test"


# ---------------------------------------------------------------- pickle opcode assembly
def _u32(n: int) -> bytes:
    return struct.pack("<I", n)


def _u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def _glob(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def _binunicode(text: str) -> bytes:
    raw = text.encode()
    return b"X" + _u32(len(raw)) + raw


def _short_binunicode(text: str) -> bytes:
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def _call_global(module: str, name: str, arg: str = _PAYLOAD) -> bytes:
    """Protocol 2 pickle: GLOBAL module.name; BINUNICODE arg; TUPLE1; REDUCE; STOP."""
    return b"\x80\x02" + _glob(module, name) + _binunicode(arg) + b"\x85R."


def _benign_pickle() -> bytes:
    return pickle.dumps({"layers": [[1, 2, 3], [4, 5, 6]], "names": ["a", "b"]}, protocol=4)


def _torch_pickle() -> bytes:
    """What torch.save writes into data.pkl for {'weight': tensor}, assembled by hand (no torch import)."""
    return b"".join(
        [
            b"\x80\x02",
            _glob("collections", "OrderedDict"),
            b")Rq\x00",
            b"(",
            _binunicode("weight"),
            b"q\x01",
            _glob("torch._utils", "_rebuild_tensor_v2"),
            b"q\x02",
            b"(",  # args of _rebuild_tensor_v2
            b"(",  # persistent id tuple
            _binunicode("storage"),
            _glob("torch", "FloatStorage"),
            _binunicode("0"),
            _binunicode("cpu"),
            b"K\x04t",
            b"Q",  # BINPERSID
            b"K\x00",
            b"K\x02K\x02\x86",
            b"K\x02K\x01\x86",
            b"\x89",
            _glob("collections", "OrderedDict"),
            b")R",
            b"t",
            b"R",
            b"u",
            b".",
        ]
    )


def _numpy_header(descr: str, shape: str) -> bytes:
    text = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': {shape}, }}"
    total = 10 + len(text) + 1
    pad = (-total) % 64
    header = (text + " " * pad + "\n").encode("latin-1")
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header


# ---------------------------------------------------------------- zip helpers
def _set_flag(blob: bytearray, name: str, flag: int) -> None:
    """Set a general-purpose flag bit in the local and central headers of `name` (the zipfile writer resets them)."""
    raw = name.encode()
    for sig, name_off, flag_off in ((b"PK", 30, 6), (b"PK", 46, 8)):
        start = blob.find(sig)
        while start >= 0:
            if bytes(blob[start + name_off : start + name_off + len(raw)]) == raw:
                blob[start + flag_off] |= flag
                break
            start = blob.find(sig, start + 4)


def _zip(members: dict[str, bytes], *, compress: bool = False, flag_bits: dict[str, int] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            zf.writestr(info, data)
    blob = bytearray(buf.getvalue())
    for name, flag in (flag_bits or {}).items():
        _set_flag(blob, name, flag)
    return bytes(blob)


def _torch_zip(pickle_bytes: bytes, extra: dict[str, bytes] | None = None, *, compress: bool = False) -> bytes:
    members = {"archive/data.pkl": pickle_bytes, "archive/version": b"3\n"}
    members.update(extra or {})
    return _zip(members, compress=compress)


# ---------------------------------------------------------------- keras
def _dtype_policy() -> dict[str, object]:
    return {"module": "keras", "class_name": "DTypePolicy", "config": {"name": "float32"}, "registered_name": None}


def _dense(name: str, units: int) -> dict[str, object]:
    return {
        "module": "keras.layers",
        "class_name": "Dense",
        "config": {
            "name": name,
            "trainable": True,
            "dtype": _dtype_policy(),
            "units": units,
            "activation": "relu",
            "use_bias": True,
            "kernel_initializer": {
                "module": "keras.initializers",
                "class_name": "GlorotUniform",
                "config": {"seed": None},
                "registered_name": "GlorotUniform",
            },
        },
        "registered_name": None,
        "build_config": {"input_shape": [None, 8]},
    }


def _keras_config(layers: list[dict[str, object]], loss: object = "mse") -> dict[str, object]:
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {"name": "sequential", "trainable": True, "dtype": _dtype_policy(), "layers": layers},
        "registered_name": "Sequential",
        "build_config": {"input_shape": [None, 8]},
        "compile_config": {
            "optimizer": {
                "module": "keras.optimizers",
                "class_name": "Adam",
                "config": {"learning_rate": 0.001},
                "registered_name": "Adam",
            },
            "loss": loss,
            "metrics": None,
        },
    }


def _keras_zip(config: dict[str, object]) -> bytes:
    return _zip(
        {
            "config.json": json.dumps(config).encode(),
            "metadata.json": json.dumps({"keras_version": "3.3.3", "date_saved": "2024-01-01"}).encode(),
            "model.weights.h5": b"\x89HDF\r\n\x1a\n" + b"\x00" * 64,
        },
        compress=True,
    )


def _lambda_layer() -> dict[str, object]:
    return {
        "module": "keras.layers",
        "class_name": "Lambda",
        "config": {
            "name": "lambda",
            "function": {"class_name": "__lambda__", "config": {"code": "4wEAAAAA", "defaults": None, "closure": None}},
        },
        "registered_name": "Lambda",
    }


# ---------------------------------------------------------------- safetensors
def _safetensors(
    header: dict[str, object] | None = None,
    data: bytes = b"",
    *,
    raw_header: bytes | None = None,
    declared_len: int | None = None,
) -> bytes:
    body = raw_header if raw_header is not None else json.dumps(header, separators=(",", ":")).encode()
    body += b" " * ((-len(body)) % 8)
    n = len(body) if declared_len is None else declared_len
    return _u64(n) + body + data


def _st_tensor(dtype: str, shape: list[int], begin: int, end: int) -> dict[str, object]:
    return {"dtype": dtype, "shape": shape, "data_offsets": [begin, end]}


_ST_DATA = struct.pack("<6f", 1.0, 2.0, 3.0, 4.0, 5.0, 6.0)  # 24 bytes
_ST_HEADER = {"weight": _st_tensor("F32", [2, 2], 0, 16), "bias": _st_tensor("F32", [2], 16, 24)}


# ---------------------------------------------------------------- gguf
def _gstr(text: str | bytes) -> bytes:
    raw = text.encode() if isinstance(text, str) else text
    return _u64(len(raw)) + raw


def _kv(key: str, vtype: int, payload: bytes) -> bytes:
    return _gstr(key) + _u32(vtype) + payload


def _kv_str(key: str, value: str) -> bytes:
    return _kv(key, 8, _gstr(value))


def _kv_u32(key: str, value: int) -> bytes:
    return _kv(key, 4, _u32(value))


def _kv_f32(key: str, value: float) -> bytes:
    return _kv(key, 6, struct.pack("<f", value))


def _kv_str_array(key: str, values: list[str]) -> bytes:
    return _kv(key, 9, _u32(8) + _u64(len(values)) + b"".join(_gstr(v) for v in values))


def _kv_f32_array(key: str, values: list[float]) -> bytes:
    return _kv(key, 9, _u32(6) + _u64(len(values)) + struct.pack(f"<{len(values)}f", *values))


def _tensor_info(name: str, dims: list[int], gtype: int, offset: int) -> bytes:
    return _gstr(name) + _u32(len(dims)) + b"".join(_u64(d) for d in dims) + _u32(gtype) + _u64(offset)


def _gguf(
    kvs: list[bytes],
    tensors: list[bytes],
    data: bytes = b"",
    *,
    alignment: int = 32,
    magic: bytes = b"GGUF",
    version: int = 3,
    kv_count: int | None = None,
    tensor_count: int | None = None,
) -> bytes:
    out = magic + _u32(version)
    out += _u64(len(tensors) if tensor_count is None else tensor_count)
    out += _u64(len(kvs) if kv_count is None else kv_count)
    out += b"".join(kvs) + b"".join(tensors)
    out += b"\x00" * ((-len(out)) % alignment)
    return out + data


def _base_kvs() -> list[bytes]:
    return [
        _kv_str("general.architecture", "llama"),
        _kv_str("general.name", "rogatka-test"),
        _kv_u32("general.alignment", 32),
        _kv_u32("llama.context_length", 2048),
        _kv_f32("llama.rope.freq_base", 10000.0),
        _kv_str_array("tokenizer.ggml.tokens", ["<s>", "</s>", "a"]),
        _kv_f32_array("tokenizer.ggml.scores", [0.0, 0.0, -1.0]),
    ]


_GGUF_TENSORS = [_tensor_info("token_embd.weight", [4, 2], 0, 0), _tensor_info("output.weight", [8], 1, 32)]
_GGUF_DATA = b"\x00" * 48  # 8 * f32 (32 bytes) + 8 * f16 (16 bytes)
_SAFE_TEMPLATE = "{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}\n{% endfor %}"
_EVIL_TEMPLATE = (
    "{{ ''.__class__.__mro__[1].__subclasses__() }}{{ cycler.__init__.__globals__.os.popen('echo rogatka-test') }}"
)


# ---------------------------------------------------------------- fixtures
def _benign_safetensors() -> bytes:
    return _safetensors(_ST_HEADER, _ST_DATA)


def _benign_safetensors_metadata() -> bytes:
    return _safetensors({"__metadata__": {"format": "pt"}, **_ST_HEADER}, _ST_DATA)


def _benign_gguf() -> bytes:
    return _gguf(_base_kvs(), _GGUF_TENSORS, _GGUF_DATA)


def _benign_gguf_template() -> bytes:
    return _gguf([*_base_kvs(), _kv_str("tokenizer.chat_template", _SAFE_TEMPLATE)], _GGUF_TENSORS, _GGUF_DATA)


def _pickle_stack_global_eval() -> bytes:
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode("builtins"),
            b"\x94",
            _short_binunicode("eval"),
            b"\x94",
            b"00",  # POP, POP: the strings now live only in the memo
            b"h\x00h\x01",  # BINGET 0, BINGET 1
            b"\x93",  # STACK_GLOBAL
            _short_binunicode("1+1"),
            b"\x85R.",
        ]
    )


def _pickle_dotted_global() -> bytes:
    """Protocol 4 qualified name: GLOBAL torch + 'os.system' resolves to os.system via getattr walking."""
    return b"".join(
        [
            b"\x80\x04",
            _short_binunicode("torch"),
            _short_binunicode("os.system"),
            b"\x93",
            _short_binunicode(_PAYLOAD),
            b"\x85R.",
        ]
    )


def _pickle_subprocess() -> bytes:
    return b"\x80\x02(" + _binunicode("echo") + b"i" + b"subprocess\nPopen\n" + b"."


def _pickle_7z_wrapped() -> bytes:
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 24 + _call_global("posix", "system")


def _pickle_broken_stream() -> bytes:
    return b"\x80\x02" + _glob("os", "system") + _binunicode(_PAYLOAD) + b"\x85R" + b"\xff\xfeNOT-A-STOP"


def _pickle_multiple() -> bytes:
    return pickle.dumps({"a": [1, 2]}, protocol=2) + _call_global("os", "system")


def _zip_nested_archive() -> bytes:
    nested = _zip({"inner.txt": b"hello"})
    return _torch_zip(_torch_pickle(), {"archive/extra.bin": nested})


def _torch_zip_hidden_member() -> bytes:
    """A pickle hiding in a member that is not named *.pkl (protocol 0 text pickle)."""
    return _torch_zip(_torch_pickle(), {"archive/extra": b"cos\nsystem\n(S'id'\ntR."})


def _zip_traversal() -> bytes:
    return _torch_zip(_torch_pickle(), {"../evil.pkl": _benign_pickle()})


def _zip_bomb() -> bytes:
    return _torch_zip(_torch_pickle(), {"archive/bomb.txt": b"\x00" * (4 * 1024 * 1024)}, compress=True)


def _zip_encrypted() -> bytes:
    return _zip(
        {"archive/data.pkl": _torch_pickle(), "archive/secret.bin": b"not really encrypted"},
        flag_bits={"archive/secret.bin": 0x1},
    )


def _keras_lambda() -> bytes:
    return _keras_zip(_keras_config([_dense("dense", 4), _lambda_layer()]))


def _keras_module_ref() -> bytes:
    loss = {"module": "os", "class_name": "function", "config": "system", "registered_name": "os.system"}
    return _keras_zip(_keras_config([_dense("dense", 4)], loss=loss))


def _keras_benign() -> bytes:
    return _keras_zip(_keras_config([_dense("dense", 4), _dense("dense_1", 2)]))


def _h5_lambda() -> bytes:
    config = {"class_name": "Sequential", "config": {"name": "sequential", "layers": [_lambda_layer()]}}
    text = json.dumps(config, indent=1).encode()
    return b"\x89HDF\r\n\x1a\n" + b"\x00" * 56 + b"model_config\x00" + text + b"\x00" * 64


def _gguf_template_injection() -> bytes:
    return _gguf([*_base_kvs(), _kv_str("tokenizer.chat_template", _EVIL_TEMPLATE)], _GGUF_TENSORS, _GGUF_DATA)


def _gguf_string_overflow() -> bytes:
    bad = _kv("general.description", 8, _u64(1 << 30) + b"abc")
    return _gguf([_kv_str("general.architecture", "llama"), bad], [], b"")


def _gguf_bad_alignment() -> bytes:
    return _gguf([_kv_str("general.architecture", "llama"), _kv_u32("general.alignment", 3)], [], b"", alignment=32)


def _gguf_tensor_out_of_bounds() -> bytes:
    return _gguf(_base_kvs(), [_tensor_info("token_embd.weight", [4, 2], 0, 1 << 20)], _GGUF_DATA)


def _safetensors_zip_polyglot() -> bytes:
    blob = _torch_zip(_call_global("posix", "system"))
    return _safetensors({"blob": _st_tensor("U8", [len(blob)], 0, len(blob))}, blob)


def _numpy_object_pickle() -> bytes:
    return _numpy_header("|O", "(1,)") + _call_global("posix", "system")


def _numpy_benign() -> bytes:
    return _numpy_header("<f8", "(1,)") + struct.pack("<d", 1.0)


FIXTURES: dict[str, Callable[[], bytes]] = {
    # benign
    "benign_safetensors": _benign_safetensors,
    "benign_safetensors_metadata": _benign_safetensors_metadata,
    "benign_gguf": _benign_gguf,
    "benign_gguf_template": _benign_gguf_template,
    "benign_torch_zip": lambda: _torch_zip(_torch_pickle()),
    "benign_pickle_plain": _benign_pickle,
    # malicious pickles
    "pickle_os_system": lambda: _call_global("os", "system"),
    "pickle_stack_global_eval": _pickle_stack_global_eval,
    "pickle_dotted_global": _pickle_dotted_global,
    "pickle_subprocess": _pickle_subprocess,
    "torch_zip_os_system": lambda: _torch_zip(_call_global("posix", "system")),
    "pickle_7z_wrapped": _pickle_7z_wrapped,
    "pickle_broken_stream": _pickle_broken_stream,
    "pickle_multiple": _pickle_multiple,
    "pickle_unknown_global": lambda: b"\x80\x02" + _glob("mymodel", "Net") + b")R.",
    "pickle_benign_blocked": lambda: pickle.dumps({"k": ["v", 1]}, protocol=4),
    # archives
    "zip_nested_archive": _zip_nested_archive,
    "zip_traversal": _zip_traversal,
    "torch_zip_hidden_member": _torch_zip_hidden_member,
    "zip_bomb": _zip_bomb,
    "zip_encrypted": _zip_encrypted,
    # keras / hdf5
    "keras_lambda": _keras_lambda,
    "keras_module_ref": _keras_module_ref,
    "keras_benign": _keras_benign,
    "h5_lambda": _h5_lambda,
    # gguf
    "gguf_bad_magic": lambda: _gguf(_base_kvs(), _GGUF_TENSORS, _GGUF_DATA, magic=b"GGUX"),
    "gguf_huge_kv_count": lambda: _gguf(_base_kvs(), _GGUF_TENSORS, _GGUF_DATA, kv_count=0xFFFFFFFFFFFF),
    "gguf_string_overflow": _gguf_string_overflow,
    "gguf_bad_alignment": _gguf_bad_alignment,
    "gguf_tensor_out_of_bounds": _gguf_tensor_out_of_bounds,
    "gguf_template_injection": _gguf_template_injection,
    # safetensors
    "safetensors_header_too_long": lambda: _safetensors(_ST_HEADER, _ST_DATA, declared_len=512 * 1024 * 1024),
    "safetensors_bad_json": lambda: _safetensors(raw_header=b'{"weight": not json}', data=_ST_DATA),
    "safetensors_offsets_overlap": lambda: _safetensors(
        {"weight": _st_tensor("F32", [2, 2], 0, 16), "bias": _st_tensor("F32", [4], 8, 24)}, _ST_DATA
    ),
    "safetensors_offsets_out_of_bounds": lambda: _safetensors(
        {"weight": _st_tensor("F32", [250], 0, 1000)}, _ST_DATA[:16]
    ),
    "safetensors_disguised_pickle": _benign_pickle,
    "safetensors_zip_polyglot": _safetensors_zip_polyglot,
    # numpy
    "numpy_object_pickle": _numpy_object_pickle,
    "numpy_benign": _numpy_benign,
}

FIXTURE_FILENAMES: dict[str, str] = {
    "benign_safetensors": "benign.safetensors",
    "benign_safetensors_metadata": "benign_meta.safetensors",
    "benign_gguf": "benign.gguf",
    "benign_gguf_template": "benign_template.gguf",
    "benign_torch_zip": "benign_torch.pt",
    "benign_pickle_plain": "benign_plain.pkl",
    "pickle_os_system": "os_system.pkl",
    "pickle_stack_global_eval": "stack_global_eval.pkl",
    "pickle_dotted_global": "dotted_global.pkl",
    "pickle_subprocess": "subprocess.pt",
    "torch_zip_os_system": "torch_os_system.pt",
    "pickle_7z_wrapped": "wrapped_7z.pt",
    "pickle_broken_stream": "broken_stream.bin",
    "pickle_multiple": "multiple.pkl",
    "pickle_unknown_global": "unknown_global.pkl",
    "pickle_benign_blocked": "benign_blocked.pkl",
    "zip_nested_archive": "nested.pt",
    "zip_traversal": "traversal.pt",
    "torch_zip_hidden_member": "hidden_member.pt",
    "zip_bomb": "bomb.pt",
    "zip_encrypted": "encrypted.pt",
    "keras_lambda": "lambda.keras",
    "keras_module_ref": "module_ref.keras",
    "keras_benign": "benign.keras",
    "h5_lambda": "lambda.h5",
    "gguf_bad_magic": "bad_magic.gguf",
    "gguf_huge_kv_count": "huge_kv.gguf",
    "gguf_string_overflow": "string_overflow.gguf",
    "gguf_bad_alignment": "bad_alignment.gguf",
    "gguf_tensor_out_of_bounds": "tensor_oob.gguf",
    "gguf_template_injection": "template_injection.gguf",
    "safetensors_header_too_long": "header_too_long.safetensors",
    "safetensors_bad_json": "bad_json.safetensors",
    "safetensors_offsets_overlap": "overlap.safetensors",
    "safetensors_offsets_out_of_bounds": "oob.safetensors",
    "safetensors_disguised_pickle": "disguised.safetensors",
    "safetensors_zip_polyglot": "polyglot.safetensors",
    "numpy_object_pickle": "object.npy",
    "numpy_benign": "benign.npy",
}

_lock = threading.Lock()
_tmpdir: Path | None = None
_paths: dict[str, Path] = {}


def fixture_bytes(name: str) -> bytes:
    return FIXTURES[name]()


def fixture_filename(name: str) -> str:
    return FIXTURE_FILENAMES[name]


def fixture_path(name: str) -> Path:
    """Materialise the fixture once per process into a private temp directory and return its path
    (`<tmp>/<name>/<filename>`, so same-named files of different fixtures never collide)."""
    global _tmpdir
    with _lock:
        cached = _paths.get(name)
        if cached is not None and cached.exists():
            return cached
        if _tmpdir is None:
            _tmpdir = Path(tempfile.mkdtemp(prefix="acl-artifacts-"))
            atexit.register(shutil.rmtree, _tmpdir, ignore_errors=True)
        folder = _tmpdir / name
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / fixture_filename(name)
        path.write_bytes(fixture_bytes(name))
        _paths[name] = path
        return path
