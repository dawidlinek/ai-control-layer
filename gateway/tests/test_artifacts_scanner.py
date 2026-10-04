"""S1: model-artifact scanner core (pure library). Fixtures are generated in code by acl.artifacts.testing."""

from __future__ import annotations

import io
import json
import pickle
import random
import struct
import subprocess
import tracemalloc
import warnings
import zipfile
from datetime import date, timedelta
from pathlib import Path

import pytest

from acl.artifacts import keras as keras_mod
from acl.artifacts.formats import detect_magic, extension, npy_info
from acl.artifacts.gguf import scan_gguf, template_markers
from acl.artifacts.huggingface import parse_hf_source, validate_hf_source
from acl.artifacts.pickle_walk import classify_global, scan_pickle, torch_version_ok
from acl.artifacts.report import FormatException, ScanPolicy
from acl.artifacts.safetensors import scan_safetensors
from acl.artifacts.scanner import scan_bytes, scan_file
from acl.artifacts.testing import FIXTURES, fixture_bytes, fixture_filename, fixture_path

SHA = "a" * 40

# name -> (verdict under the default policy, rule ids that must be present)
EXPECTED: dict[str, tuple[str, set[str]]] = {
    "benign_safetensors": ("safe", set()),
    "benign_safetensors_metadata": ("safe", set()),
    "benign_gguf": ("safe", set()),
    "benign_gguf_template": ("safe", set()),
    "benign_torch_zip": ("blocked_format", {"ART-FORMAT-01", "ART-TORCH-01"}),
    "benign_pickle_plain": ("blocked_format", {"ART-FORMAT-01"}),
    "pickle_os_system": ("malicious", {"ART-PICKLE-01"}),
    "pickle_stack_global_eval": ("malicious", {"ART-PICKLE-01"}),
    "pickle_dotted_global": ("malicious", {"ART-PICKLE-01"}),
    "pickle_subprocess": ("malicious", {"ART-PICKLE-01"}),
    "torch_zip_os_system": ("malicious", {"ART-PICKLE-01"}),
    "pickle_7z_wrapped": ("malicious", {"ART-ARCHIVE-01"}),
    "pickle_broken_stream": ("malicious", {"ART-PICKLE-03", "ART-PICKLE-01"}),
    "pickle_multiple": ("malicious", {"ART-PICKLE-04", "ART-PICKLE-01"}),
    "pickle_unknown_global": ("blocked_format", {"ART-PICKLE-02", "ART-FORMAT-01"}),
    "pickle_benign_blocked": ("blocked_format", {"ART-FORMAT-01"}),
    "zip_nested_archive": ("malicious", {"ART-ARCHIVE-02"}),
    "zip_traversal": ("malicious", {"ART-ARCHIVE-03"}),
    "torch_zip_hidden_member": ("malicious", {"ART-PICKLE-01"}),
    "zip_bomb": ("malicious", {"ART-ARCHIVE-03"}),
    "zip_encrypted": ("malicious", {"ART-ARCHIVE-03"}),
    "keras_lambda": ("malicious", {"ART-KERAS-01"}),
    "keras_module_ref": ("malicious", {"ART-KERAS-02"}),
    "keras_benign": ("blocked_format", {"ART-FORMAT-01"}),
    "h5_lambda": ("malicious", {"ART-KERAS-01"}),
    "gguf_bad_magic": ("malicious", {"ART-FORMAT-02"}),
    "gguf_huge_kv_count": ("malicious", {"ART-GGUF-01"}),
    "gguf_string_overflow": ("malicious", {"ART-GGUF-01"}),
    "gguf_bad_alignment": ("malicious", {"ART-GGUF-01"}),
    "gguf_tensor_out_of_bounds": ("malicious", {"ART-GGUF-01"}),
    "gguf_template_injection": ("malicious", {"ART-GGUF-02"}),
    "safetensors_header_too_long": ("malicious", {"ART-ST-01"}),
    "safetensors_bad_json": ("malicious", {"ART-ST-01"}),
    "safetensors_offsets_overlap": ("malicious", {"ART-ST-01"}),
    "safetensors_offsets_out_of_bounds": ("malicious", {"ART-ST-01"}),
    "safetensors_disguised_pickle": ("malicious", {"ART-FORMAT-02"}),
    "safetensors_zip_polyglot": ("malicious", {"ART-FORMAT-02"}),
    "numpy_object_pickle": ("malicious", {"ART-PICKLE-01"}),
    "numpy_benign": ("blocked_format", {"ART-FORMAT-01"}),
}


def scan(name: str, **kw: object):
    return scan_bytes(fixture_bytes(name), filename=fixture_filename(name), **kw)  # type: ignore[arg-type]


def rules(report) -> set[str]:
    return {f.rule_id for f in report.findings}


# ------------------------------------------------------------------ fixtures x expected verdicts
def test_every_fixture_has_an_expectation() -> None:
    assert set(EXPECTED) == set(FIXTURES)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_verdicts(name: str) -> None:
    verdict, required = EXPECTED[name]
    report = scan(name)
    assert report.verdict == verdict, (name, report.verdict, [f.rule_id for f in report.findings])
    assert required <= rules(report), (name, rules(report))
    if verdict == "safe":
        assert report.findings == []
    if verdict != "malicious":
        assert not any(f.malicious for f in report.findings)


@pytest.mark.parametrize("name", ["benign_safetensors", "benign_gguf", "torch_zip_os_system", "keras_lambda"])
def test_scan_file_matches_scan_bytes(name: str) -> None:
    path = fixture_path(name)
    assert path.name == fixture_filename(name)
    from_file = scan_file(path)
    from_bytes = scan(name)
    assert from_file.to_dict() == from_bytes.to_dict()
    assert from_file.size == path.stat().st_size


def test_fixtures_are_deterministic() -> None:
    for name in FIXTURES:
        assert fixture_bytes(name) == fixture_bytes(name)


def test_expected_rule_details_and_cves() -> None:
    lam = {f.rule_id: f for f in scan("keras_lambda").findings}
    assert lam["ART-KERAS-01"].cve == ("CVE-2024-3660",)
    assert lam["ART-KERAS-01"].severity.value == "critical"
    assert scan("keras_module_ref").findings[0].cve == ("CVE-2025-1550",)
    tpl = next(f for f in scan("gguf_template_injection").findings if f.rule_id == "ART-GGUF-02")
    assert tpl.cve == ("CVE-2024-34359",)
    note = next(f for f in scan("benign_torch_zip").findings if f.rule_id == "ART-TORCH-01")
    assert note.severity.value == "info" and "CVE-2025-32434" in note.message and "2.6.0" in note.message


def test_pickle_globals_and_detail() -> None:
    assert scan("torch_zip_os_system").pickle_globals == ["posix.system"]
    assert scan("pickle_os_system").pickle_globals == ["os.system"]
    assert scan("pickle_stack_global_eval").pickle_globals == ["builtins.eval"]
    assert scan("pickle_subprocess").pickle_globals == ["subprocess.Popen"]
    assert scan("benign_torch_zip").pickle_globals == [
        "collections.OrderedDict",
        "torch._utils._rebuild_tensor_v2",
        "torch.FloatStorage",
    ]
    finding = next(f for f in scan("pickle_os_system").findings if f.rule_id == "ART-PICKLE-01")
    assert finding.detail is not None and "GLOBAL os.system via REDUCE" in finding.detail
    finding = next(f for f in scan("pickle_subprocess").findings if f.rule_id == "ART-PICKLE-01")
    assert finding.detail is not None and "INST" in finding.detail
    assert next(f for f in scan("pickle_stack_global_eval").findings if f.rule_id == "ART-PICKLE-01").detail.startswith(
        "STACK_GLOBAL builtins.eval via REDUCE"
    )


def test_walkers_run_even_for_blocked_formats() -> None:
    report = scan("pickle_os_system")
    assert report.verdict == "malicious"  # not just blocked_format
    assert "ART-FORMAT-01" in rules(report)


# ------------------------------------------------------------------ exceptions
def _exc(sha: str, **kw: object) -> FormatException:
    return FormatException(sha256=sha, reason="approved by security review", **kw)  # type: ignore[arg-type]


def test_exception_admits_benign_pickle_and_torch_zip() -> None:
    for name in ("benign_pickle_plain", "benign_torch_zip", "pickle_benign_blocked", "keras_benign"):
        sha = scan(name).sha256
        report = scan(name, policy=ScanPolicy(exceptions=(_exc(sha),)))
        assert report.verdict == "safe", (name, report.verdict)
        assert report.exception == "approved by security review"
        assert "ART-FORMAT-01" in rules(report)  # recorded, but only as info
        assert not any(f.severity.value in ("medium", "high", "critical") for f in report.findings)


def test_exception_with_unknown_global_is_suspicious() -> None:
    sha = scan("pickle_unknown_global").sha256
    report = scan("pickle_unknown_global", policy=ScanPolicy(exceptions=(_exc(sha),)))
    assert report.verdict == "suspicious"
    assert report.exception is not None


@pytest.mark.parametrize(
    "name",
    ["pickle_os_system", "torch_zip_os_system", "pickle_broken_stream", "pickle_multiple", "zip_nested_archive"],
)
def test_exception_never_admits_a_malicious_file(name: str) -> None:
    sha = scan(name).sha256
    report = scan(name, policy=ScanPolicy(exceptions=(_exc(sha),)))
    assert report.verdict == "malicious"
    assert report.exception is None


def test_exception_expiry_sha_and_format_scope() -> None:
    sha = scan("benign_pickle_plain").sha256
    today = date(2030, 6, 1)
    kw = {"today": today}
    expired = ScanPolicy(exceptions=(_exc(sha, expires=today - timedelta(days=1)),))
    assert scan("benign_pickle_plain", policy=expired, **kw).verdict == "blocked_format"
    last_day = ScanPolicy(exceptions=(_exc(sha, expires=today),))
    assert scan("benign_pickle_plain", policy=last_day, **kw).verdict == "safe"
    other_sha = ScanPolicy(exceptions=(_exc("0" * 64),))
    assert scan("benign_pickle_plain", policy=other_sha).verdict == "blocked_format"
    wrong_format = ScanPolicy(exceptions=(_exc(sha, formats=("torch_zip",)),))
    assert scan("benign_pickle_plain", policy=wrong_format).verdict == "blocked_format"
    right_format = ScanPolicy(exceptions=(_exc(sha, formats=("pickle", "torch_zip")),))
    assert scan("benign_pickle_plain", policy=right_format).verdict == "safe"
    upper = ScanPolicy(exceptions=(_exc(sha.upper()),))
    assert scan("benign_pickle_plain", policy=upper).verdict == "safe"


def test_allowed_formats_can_be_widened() -> None:
    policy = ScanPolicy(allowed_formats=("safetensors", "gguf", "keras_v3"))
    assert scan("keras_benign", policy=policy).verdict == "safe"
    assert scan("keras_lambda", policy=policy).verdict == "malicious"
    assert scan("benign_safetensors", policy=ScanPolicy(allowed_formats=())).verdict == "blocked_format"


# ------------------------------------------------------------------ signature feed globs
def test_feed_opcode_glob_flags_allowlisted_global() -> None:
    policy = ScanPolicy(opcode_globs=(("ART-SIG-0042", "torch._utils.*"),))
    report = scan("benign_torch_zip", policy=policy)
    assert report.verdict == "malicious"
    hit = [f for f in report.findings if f.rule_id == "ART-SIG-0042"]
    assert len(hit) == 1 and hit[0].malicious and hit[0].severity.value == "high"
    assert "torch._utils._rebuild_tensor_v2" in hit[0].message
    # no match -> unchanged
    clean = scan("benign_torch_zip", policy=ScanPolicy(opcode_globs=(("ART-SIG-0043", "nothing.*"),)))
    assert clean.verdict == "blocked_format"


# ------------------------------------------------------------------ hash and source
def test_declared_hash_mismatch_is_malicious() -> None:
    sha = scan("benign_safetensors").sha256
    ok = scan("benign_safetensors", expected_sha256=sha.upper())
    assert ok.verdict == "safe"
    bad = scan("benign_safetensors", expected_sha256="0" * 64)
    assert bad.verdict == "malicious" and "ART-HASH-01" in rules(bad)


def test_hf_source_checks_on_scan() -> None:
    policy = ScanPolicy(hf_repo_allowlist=("acme/*", "other/exact"))
    pinned = f"hf:acme/model@{SHA}"
    assert scan("benign_safetensors", policy=policy, source=pinned).verdict == "safe"
    assert scan("benign_safetensors", policy=policy, source="upload").verdict == "safe"
    assert scan("benign_safetensors", policy=policy, source=None).verdict == "safe"
    branch = scan("benign_safetensors", policy=policy, source="hf:acme/model@main")
    assert branch.verdict == "suspicious" and rules(branch) == {"ART-HF-01"}
    unlisted = scan("benign_safetensors", policy=policy, source=f"hf:evil/model@{SHA}")
    assert unlisted.verdict == "suspicious" and rules(unlisted) == {"ART-HF-02"}
    both = scan("benign_safetensors", policy=policy, source="hf:evil/model@main")
    assert rules(both) == {"ART-HF-01", "ART-HF-02"}
    assert all(f.severity.value == "high" for f in both.findings)
    # no allowlist configured -> no HF source allowed
    assert rules(scan("benign_safetensors", source=pinned)) == {"ART-HF-02"}


def test_hf_parse_and_validate() -> None:
    ref = parse_hf_source(f"hf:acme/model-7b@{SHA}")
    assert ref is not None and ref.repo_id == "acme/model-7b" and ref.pinned
    assert parse_hf_source("hf:acme/model@main") is not None
    assert not parse_hf_source("hf:acme/model@main").pinned  # type: ignore[union-attr]
    for bad in ("hf:model@main", "hf:acme/model", "hf:acme/model@", "hf:../x/y@abc", "upload", None, "hf:a/b@c d"):
        assert parse_hf_source(bad) is None
    assert [f.rule_id for f in validate_hf_source("hf:model@main", ("*",))] == ["ART-HF-01"]
    assert [f.rule_id for f in validate_hf_source(f"hf:acme/model@{'A' * 40}", ("acme/*",))] == ["ART-HF-01"]
    assert [f.rule_id for f in validate_hf_source(f"hf:acme/model@{SHA[:39]}", ("acme/*",))] == ["ART-HF-01"]
    assert validate_hf_source(f"hf:acme/model@{SHA}", ("acme/model",)) == []
    assert validate_hf_source("https://example.com/model", ()) == []


def test_torch_version_gate() -> None:
    assert torch_version_ok("2.6.0") and torch_version_ok("2.7.1+cu121") and torch_version_ok("3.0")
    assert torch_version_ok("2.6.0rc1") and torch_version_ok("2.6.0.dev20250101")
    assert not torch_version_ok("2.5.1") and not torch_version_ok("1.13.1+cpu") and not torch_version_ok("2.5.99")
    assert not torch_version_ok("garbage") and not torch_version_ok("")
    assert torch_version_ok("2.4.0", minimum="2.4") and not torch_version_ok("2.3.9", minimum="2.4")


# ------------------------------------------------------------------ format detection
def test_extension_and_magic_detection() -> None:
    assert extension("a/b/Model.PT") == ".pt" and extension("noext") == "" and extension("x.tar.gz") == ".gz"
    assert detect_magic(b"GGUF\x03\x00\x00\x00", 100) == "gguf"
    assert detect_magic(b"PK\x03\x04" + b"\x00" * 30, 100) == "zip"
    assert detect_magic(b"PK\x05\x06" + b"\x00" * 30, 100) == "zip"
    assert detect_magic(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 30, 100) == "7z"
    assert detect_magic(b"\x1f\x8b\x08" + b"\x00" * 30, 100) == "gzip"
    assert detect_magic(b"BZh9" + b"\x00" * 30, 100) == "bzip2"
    assert detect_magic(b"\xfd7zXZ\x00" + b"\x00" * 30, 100) == "xz"
    assert detect_magic(b"Rar!\x1a\x07\x00" + b"\x00" * 30, 100) == "rar"
    assert detect_magic(b"\x00" * 257 + b"ustar\x00" + b"\x00" * 30, 400) == "tar"
    assert detect_magic(b"\x89HDF\r\n\x1a\n" + b"\x00" * 30, 100) == "hdf5"
    assert detect_magic(b"\x00" * 512 + b"\x89HDF\r\n\x1a\n" + b"\x00" * 30, 1000) == "hdf5"
    assert detect_magic(b"\x93NUMPY\x01\x00" + b"\x00" * 30, 100) == "numpy"
    assert detect_magic(b"\x80\x04\x95" + b"\x00" * 30, 100) == "pickle"
    assert detect_magic(b"\x80\x06" + b"\x00" * 30, 100) == "unknown"
    assert detect_magic(b"hello world, plain text", 23) == "unknown"
    assert detect_magic(b"", 0) == "unknown"


def test_safetensors_with_length_prefix_that_looks_like_a_pickle_header() -> None:
    # header length 0x0580 = 1408 bytes: the little-endian prefix starts 0x80 0x05, a valid pickle PROTO.
    header = {"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}
    body = json.dumps(header, separators=(",", ":")).encode()
    body += b" " * (0x0580 - len(body))
    blob = struct.pack("<Q", len(body)) + body + b"abcd"
    assert blob[:2] == b"\x80\x05"
    report = scan_bytes(blob, filename="m.safetensors")
    assert report.format_detected == "safetensors" and report.verdict == "safe"


def test_extension_mismatch_and_archive_mismatch() -> None:
    st = fixture_bytes("benign_safetensors")
    assert rules(scan_bytes(st, filename="model.gguf")) == {"ART-FORMAT-02"}
    assert scan_bytes(st, filename="model.gguf").verdict == "malicious"
    assert scan_bytes(st, filename="model.bin").verdict == "safe"  # safetensors under another name is not a lie
    gz = b"\x1f\x8b\x08\x00" + b"\x00" * 60
    for name in ("m.pt", "m.pth", "m.bin", "m.ckpt", "m.pkl", "m.pickle", "m.joblib", "m.keras"):
        report = scan_bytes(gz, filename=name)
        assert report.verdict == "malicious" and "ART-ARCHIVE-01" in rules(report), name
    for magic in (b"BZh9", b"\xfd7zXZ\x00", b"Rar!\x1a\x07\x00", b"7z\xbc\xaf\x27\x1c"):
        assert "ART-ARCHIVE-01" in rules(scan_bytes(magic + b"\x00" * 60, filename="m.pt"))
    tar = b"\x00" * 257 + b"ustar\x00" + b"\x00" * 100
    assert "ART-ARCHIVE-01" in rules(scan_bytes(tar, filename="m.bin"))
    # the same archive under an archive extension is just a blocked format
    assert scan_bytes(gz, filename="m.tar.gz").verdict == "blocked_format"
    assert scan_bytes(gz, filename="m.dat").verdict == "blocked_format"


def test_unknown_content_under_model_extensions() -> None:
    junk = bytes(range(1, 200))
    for name in ("m.pt", "m.bin", "m.pkl", "m.keras", "m.h5", "m.safetensors", "m.gguf"):
        report = scan_bytes(junk, filename=name)
        assert report.verdict == "malicious" and "ART-FORMAT-02" in rules(report), name
    assert scan_bytes(junk, filename="m.dat").verdict == "blocked_format"
    assert scan_bytes(b"", filename="m.dat").verdict == "blocked_format"
    assert scan_bytes(b"", filename="m.safetensors").verdict == "malicious"


def test_protocol0_pickle_without_magic_is_found_by_probing() -> None:
    payload = b"cos\nsystem\n(S'echo rogatka-test'\ntR."
    report = scan_bytes(payload, filename="model.dat")
    assert report.format_detected == "pickle" and report.verdict == "malicious"
    assert report.pickle_globals == ["os.system"]
    benign = pickle.dumps({"a": [1, 2, 3], "b": "text", "c": (1.5, None)}, protocol=0)
    assert scan_bytes(benign, filename="m.pkl").verdict == "blocked_format"
    assert scan_bytes(benign, filename="m.pkl").format_detected == "pickle"


def test_numpy_object_arrays_are_walked() -> None:
    report = scan("numpy_object_pickle")
    assert report.format_detected == "numpy" and report.pickle_globals == ["posix.system"]
    info = npy_info(fixture_bytes("numpy_object_pickle")[:4096])
    assert info is not None and info[1] is True
    benign = npy_info(fixture_bytes("numpy_benign")[:4096])
    assert benign is not None and benign[1] is False
    assert npy_info(b"not numpy") is None


def test_npz_with_object_member_is_walked() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("arr_0.npy", fixture_bytes("numpy_object_pickle"))
        zf.writestr("arr_1.npy", fixture_bytes("numpy_benign"))
    report = scan_bytes(buf.getvalue(), filename="data.npz")
    assert report.format_detected == "numpy" and report.verdict == "malicious"
    assert "ART-PICKLE-01" in rules(report)


# ------------------------------------------------------------------ pickle walker
def test_walker_has_no_false_positives_on_stdlib_pickles() -> None:
    import collections

    objs = [
        {"a": [1, 2, 3], "b": ("x", None, 1.5), "c": {1, 2}},
        collections.OrderedDict(a=1, b=[2, 3]),
        frozenset({"a", "b"}),
        b"bytes" * 40,
        complex(1, 2),
        bytearray(b"ab"),
        [[i, str(i)] for i in range(50)],
    ]
    for proto in range(0, 6):
        for obj in objs:
            walked = scan_pickle(pickle.dumps(obj, protocol=proto))
            assert walked.underflows == 0, (proto, obj)
            assert not walked.broken
            assert not [f for f in walked.findings if f.malicious], (proto, obj, walked.globals)


def test_classify_global_table() -> None:
    dangerous = [
        ("os", "system"),
        ("posix", "system"),
        ("nt", "system"),
        ("subprocess", "Popen"),
        ("os.path", "join"),
        ("builtins", "eval"),
        ("__builtin__", "exec"),
        ("builtins", "__import__"),
        ("builtins", "getattr"),
        ("operator", "attrgetter"),
        ("operator", "methodcaller"),
        ("functools", "partial"),
        ("importlib", "import_module"),
        ("socket", "socket"),
        ("urllib.request", "urlopen"),
        ("shutil", "rmtree"),
        ("pickle", "loads"),
        ("torch", "os.system"),
        ("collections", "sys.modules"),
        ("builtins", "eval.__call__"),
        ("numpy.testing._private.utils", "runstring"),
        ("OS", "system"),
    ]
    for module, name in dangerous:
        assert classify_global(module, name)[0] == "dangerous", (module, name)
    safe = [
        ("collections", "OrderedDict"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_parameter_with_state"),
        ("torch", "FloatStorage"),
        ("torch", "LongStorage"),
        ("torch", "BFloat16Storage"),
        ("torch", "Size"),
        ("torch", "device"),
        ("torch", "float32"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy", "ndarray"),
        ("numpy", "dtype"),
        ("_codecs", "encode"),
        ("builtins", "set"),
        ("builtins", "frozenset"),
        ("builtins", "slice"),
        ("builtins", "complex"),
        ("builtins", "bytearray"),
    ]
    for module, name in safe:
        assert classify_global(module, name)[0] == "safe", (module, name)
    for module, name in [("mypkg", "Model"), ("torch", "load"), ("builtins", "print"), ("torch.nn", "Linear")]:
        assert classify_global(module, name)[0] == "unknown", (module, name)


def test_stack_global_is_resolved_through_memo_and_dup() -> None:
    # SHORT_BINUNICODE 'os' ; MEMOIZE ; SHORT_BINUNICODE 'system' ; MEMOIZE ; POP POP ; BINGET 0 ; BINGET 1 ;
    # STACK_GLOBAL ; ...
    data = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94" + b"00h\x00h\x01\x93" + b"\x8c\x04echo\x85R."
    walked = scan_pickle(data)
    assert walked.globals == ["os.system"]
    assert [f.rule_id for f in walked.findings] == ["ART-PICKLE-01"]
    # DUP of a string used for both module and name: 'x' 'x' -> x.x
    dup = b"\x80\x04\x8c\x01x2\x93)R."
    assert scan_pickle(dup).globals == ["x.x"]


def test_unresolved_stack_global() -> None:
    # STACK_GLOBAL fed by integers, not strings
    data = b"\x80\x04K\x01K\x02\x93)R."
    walked = scan_pickle(data)
    assert walked.globals == ["?.?"]
    assert [f.rule_id for f in walked.findings] == ["ART-PICKLE-02"]
    assert not walked.findings[0].malicious
    # empty stack: underflow is tolerated and also unresolved
    assert scan_pickle(b"\x80\x04\x93.").globals == ["?.?"]


def test_protocol4_dotted_name_attribute_walk_is_dangerous() -> None:
    assert scan("pickle_dotted_global").verdict == "malicious"


def test_obj_and_newobj_and_build_record_how_a_global_is_used() -> None:
    obj = b"\x80\x02(csubprocess\nPopen\nX\x04\x00\x00\x00echoo."
    walked = scan_pickle(obj)
    assert walked.globals == ["subprocess.Popen"]
    assert "OBJ" in (walked.findings[0].detail or "")
    newobj = b"\x80\x02cos\nsystem\n)\x81."
    assert "NEWOBJ" in (scan_pickle(newobj).findings[0].detail or "")
    referenced = b"\x80\x02cos\nsystem\n0."
    assert "never called" in (scan_pickle(referenced).findings[0].detail or "")


def test_broken_and_truncated_streams() -> None:
    good = fixture_bytes("pickle_os_system")
    for cut in (len(good) - 1, len(good) - 5, 10, 3):
        walked = scan_pickle(good[:cut])
        assert walked.broken and "ART-PICKLE-03" in {f.rule_id for f in walked.findings}
    # findings collected before the break are kept
    assert "ART-PICKLE-01" in {f.rule_id for f in scan_pickle(good[:-1]).findings}
    assert scan_pickle(b"").broken
    assert scan_pickle(b"\x80\x02\xff\xff").broken
    # a truncated prefix chosen by the caller is not "broken"
    partial = scan_pickle(good[:-1], partial=True)
    assert not partial.broken and "ART-PICKLE-03" not in {f.rule_id for f in partial.findings}


def test_trailing_data_and_padding_after_stop() -> None:
    benign = pickle.dumps({"a": 1}, protocol=2)
    assert not scan_pickle(benign + b"\x00" * 100).findings
    assert not scan_pickle(benign + b"\n  \x00\x00").findings
    junk = scan_pickle(benign + b"\xde\xad\xbe\xef trailing")
    assert [f.rule_id for f in junk.findings] == ["ART-PICKLE-04"] and junk.findings[0].malicious
    multi = scan_pickle(benign + benign)
    assert [f.rule_id for f in multi.findings] == ["ART-PICKLE-04"]
    assert "legacy" in multi.findings[0].message
    both = scan_pickle(benign + fixture_bytes("pickle_os_system"))
    assert {f.rule_id for f in both.findings} == {"ART-PICKLE-04", "ART-PICKLE-01"}


def test_opcode_limit_is_suspicious_not_malicious() -> None:
    data = b"\x80\x02" + b"K\x01" * 1000 + b"."
    walked = scan_pickle(data, max_opcodes=100)
    assert walked.limit_hit
    limit = [f for f in walked.findings if f.rule_id == "ART-PICKLE-05"]
    assert len(limit) == 1 and limit[0].severity.value == "high" and not limit[0].malicious
    assert scan_pickle(data).findings == []


def test_pickle_size_limit_via_policy() -> None:
    blob = fixture_bytes("pickle_benign_blocked") + b"\x00" * 500
    big = scan_bytes(blob, filename="m.pkl", policy=ScanPolicy(max_pickle_bytes=40))
    assert "ART-PICKLE-05" in rules(big)
    assert "ART-PICKLE-03" not in rules(big)
    assert big.verdict == "blocked_format"


def test_many_pickles_are_bounded() -> None:
    one = pickle.dumps(1, protocol=2)
    walked = scan_pickle(one * 500)
    assert walked.limit_hit and walked.pickles <= 65


# ------------------------------------------------------------------ archives
def _zip_with(members: list[tuple[str, bytes]], **kw: object) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w", **kw) as zf:  # type: ignore[arg-type]
            for name, data in members:
                zf.writestr(zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0)), data)
    return buf.getvalue()


def test_zip_path_traversal_variants() -> None:
    benign = pickle.dumps({"a": 1}, protocol=2)
    for evil in ("../x.pkl", "a/../../x.pkl", "/abs/data.pkl", "\\win\\data.pkl", "C:/data.pkl", "..\\x.pkl"):
        blob = _zip_with([("archive/data.pkl", benign), (evil, benign)])
        report = scan_bytes(blob, filename="m.pt")
        assert report.verdict == "malicious" and "ART-ARCHIVE-03" in rules(report), evil
    assert scan_bytes(_zip_with([("archive/data.pkl", benign), ("archive/a..b/c", b"x")]), filename="m.pt").verdict == (
        "blocked_format"
    )


def test_zip_duplicate_members_and_corruption() -> None:
    benign = pickle.dumps({"a": 1}, protocol=2)
    dup = _zip_with([("archive/data.pkl", benign), ("archive/data.pkl", fixture_bytes("pickle_os_system"))])
    report = scan_bytes(dup, filename="m.pt")
    assert report.verdict == "malicious" and "ART-ARCHIVE-03" in rules(report)
    good = fixture_bytes("benign_torch_zip")
    for cut in (len(good) - 10, len(good) // 2, 30):
        broken = scan_bytes(good[:cut], filename="m.pt")
        assert broken.verdict == "malicious" and "ART-ARCHIVE-03" in rules(broken), cut
    flipped = bytearray(good)
    start = flipped.index(b"collections")  # inside the stored data.pkl: CRC mismatch on read
    flipped[start] ^= 0x01
    assert scan_bytes(bytes(flipped), filename="m.pt").verdict == "malicious"


def test_zip_member_and_size_limits() -> None:
    blob = fixture_bytes("benign_torch_zip")
    many = scan_bytes(blob, filename="m.pt", policy=ScanPolicy(max_archive_members=1))
    assert many.verdict == "malicious" and "ART-ARCHIVE-03" in rules(many)
    small = scan_bytes(blob, filename="m.pt", policy=ScanPolicy(max_uncompressed_bytes=10))
    assert small.verdict == "malicious" and "ART-ARCHIVE-03" in rules(small)
    assert scan_bytes(blob, filename="m.pt").verdict == "blocked_format"


def test_nested_archive_kinds_inside_model_zip() -> None:
    benign = fixture_bytes("benign_pickle_plain")
    kinds = {
        "zip": b"PK\x03\x04" + b"\x00" * 40,
        "7z": b"7z\xbc\xaf\x27\x1c" + b"\x00" * 40,
        "gzip": b"\x1f\x8b\x08\x00" + b"\x00" * 40,
        "xz": b"\xfd7zXZ\x00" + b"\x00" * 40,
        "rar": b"Rar!\x1a\x07\x00" + b"\x00" * 40,
        "tar": b"\x00" * 257 + b"ustar\x00" + b"\x00" * 40,
        "bzip2": b"BZh91AY&SY" + b"\x00" * 40,
    }
    for kind, payload in kinds.items():
        report = scan_bytes(
            _zip_with([("archive/data.pkl", benign), ("archive/payload.dat", payload)]), filename="m.pt"
        )
        assert "ART-ARCHIVE-02" in rules(report), kind
    # raw tensor storages are never mistaken for archives, whatever their first bytes are
    storage = _zip_with([("archive/data.pkl", benign), ("archive/data/0", b"PK\x03\x04\x1f\x8b\x08BZh9")])
    assert "ART-ARCHIVE-02" not in rules(scan_bytes(storage, filename="m.pt"))


def test_torch_zip_with_hostile_pickle_in_nonstandard_member() -> None:
    evil = fixture_bytes("pickle_os_system")
    blob = _zip_with([("archive/data.pkl", pickle.dumps({}, protocol=2)), ("archive/more.pkl", evil)])
    report = scan_bytes(blob, filename="m.pt")
    assert report.verdict == "malicious" and "os.system" in report.pickle_globals


def test_pickle_content_in_non_pkl_members_is_walked() -> None:
    report = scan("torch_zip_hidden_member")
    assert report.verdict == "malicious" and "os.system" in report.pickle_globals
    finding = next(f for f in report.findings if f.rule_id == "ART-PICKLE-01")
    assert finding.detail is not None and "archive/extra" in finding.detail
    benign = pickle.dumps({"a": 1}, protocol=2)
    evil = fixture_bytes("pickle_os_system")  # protocol 2 header
    for member in ("archive/extra", "archive/blob.bin", "weights/side"):
        blob = _zip_with([("archive/data.pkl", benign), (member, evil)])
        found = scan_bytes(blob, filename="m.pt")
        assert found.verdict == "malicious" and "ART-PICKLE-01" in rules(found), member
    # a broken protocol-2 stream in a hidden member is the nullifAI shape
    broken = _zip_with([("archive/data.pkl", benign), ("archive/x", fixture_bytes("pickle_broken_stream"))])
    assert {"ART-PICKLE-03", "ART-PICKLE-01"} <= rules(scan_bytes(broken, filename="m.pt"))
    # storages and ordinary members are not mistaken for pickles
    texts = [
        ("archive/code/model.py", b"class Foo:\n    def forward(self, x):\n        return x\n"),
        ("archive/version", b"3\n"),
        ("archive/byteorder", b"little"),
        ("archive/data/0", b"cos\nsystem\n(S'id'\ntR."),
        ("archive/notes.txt", b"(just some text in parentheses)\n"),
    ]
    clean = scan_bytes(_zip_with([("archive/data.pkl", benign), *texts]), filename="m.pt")
    assert clean.verdict == "blocked_format"
    assert not rules(clean) & {"ART-PICKLE-01", "ART-PICKLE-02", "ART-PICKLE-03"}


def test_zip_polyglot_safetensors_and_gguf() -> None:
    report = scan("safetensors_zip_polyglot")
    assert report.verdict == "malicious" and rules(report) == {"ART-FORMAT-02"}
    zip_tail = fixture_bytes("torch_zip_os_system")
    gguf = fixture_bytes("benign_gguf")
    # a GGUF whose last bytes are a real zip: tensor data region hides a second format
    gguf_poly = gguf[: -len(zip_tail)] + zip_tail if len(gguf) > len(zip_tail) else gguf + zip_tail
    assert "ART-FORMAT-02" in rules(scan_bytes(gguf_poly, filename="m.gguf"))
    assert scan("benign_gguf").verdict == "safe"


# ------------------------------------------------------------------ keras
def test_keras_config_rules() -> None:
    def cfg(**node: object) -> bytes:
        return json.dumps({"config": {"layers": [node]}}).encode()

    assert keras_mod.scan_keras_config(cfg(module="keras.layers", class_name="Dense")) == []
    assert keras_mod.scan_keras_config(cfg(module="keras", class_name="Sequential")) == []
    assert keras_mod.scan_keras_config(cfg(module="keras.src.layers.core.dense", class_name="Dense")) == []
    lam = keras_mod.scan_keras_config(cfg(class_name="Lambda"))
    assert [f.rule_id for f in lam] == ["ART-KERAS-01"] and lam[0].cve == ("CVE-2024-3660",)
    for module in ("os", "subprocess", "builtins", "kerasx", "my.pkg", ""):
        found = keras_mod.scan_keras_config(cfg(module=module, class_name="X"))
        assert [f.rule_id for f in found] == ["ART-KERAS-02"], module
    reg = keras_mod.scan_keras_config(cfg(module="keras.layers", class_name="X", registered_name="mypkg>Layer"))
    assert [f.rule_id for f in reg] == ["ART-KERAS-02"]
    assert keras_mod.scan_keras_config(cfg(module="keras.layers", class_name="X", registered_name="keras>Dense")) == []
    assert keras_mod.scan_keras_config(cfg(module="keras.layers", class_name="X", registered_name="Dense")) == []
    func = keras_mod.scan_keras_config(cfg(function={"module": "mylib", "function_name": "f"}))
    assert [f.rule_id for f in func] == ["ART-KERAS-02"]
    assert keras_mod.scan_keras_config(cfg(function={"module": "keras.activations", "function_name": "relu"})) == []
    assert all(f.cve == ("CVE-2025-1550",) for f in func + reg)


def test_keras_config_garbage_and_depth_fail_closed() -> None:
    for raw in (b"not json", b"\xff\xfe\x00", b"{", b""):
        found = keras_mod.scan_keras_config(raw)
        assert found and found[0].malicious
    deep = ("[" * 300 + "]" * 300).encode()
    found = keras_mod.scan_keras_config(deep)
    assert found and found[0].malicious
    absurd = ("[" * 100_000).encode()
    assert keras_mod.scan_keras_config(absurd)[0].malicious  # RecursionError inside json -> fail closed


def test_keras_zip_with_only_weights_is_classified_correctly() -> None:
    blob = fixture_bytes("keras_benign")
    assert scan_bytes(blob, filename="m.keras").format_detected == "keras_v3"
    no_meta = _zip_with([("config.json", b"{}")])
    assert scan_bytes(no_meta, filename="m.keras").format_detected == "zip"


def test_hdf5_heuristic_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    magic = b"\x89HDF\r\n\x1a\n"
    spaced = magic + b'xx {"class_name" :\n "Lambda" , "config": {}}'
    assert "ART-KERAS-01" in rules(scan_bytes(spaced, filename="m.h5"))
    module = magic + b'.. {"module"  :  "os", "class_name": "x"}'
    assert "ART-KERAS-02" in rules(scan_bytes(module, filename="m.h5"))
    clean = magic + b'.. {"module": "keras.layers", "class_name": "Dense"}'
    report = scan_bytes(clean, filename="m.h5")
    assert report.verdict == "blocked_format" and rules(report) == {"ART-FORMAT-01"}
    # user block: HDF5 signature at offset 512
    shifted = b"\x00" * 512 + spaced
    assert "ART-KERAS-01" in rules(scan_bytes(shifted, filename="m.h5"))
    # matches straddling chunk boundaries are still found
    monkeypatch.setattr(keras_mod, "HDF5_CHUNK", 64)
    for pad in range(0, 40):
        padded = magic + b"\x00" * pad + b'{"class_name": "Lambda"}'
        assert "ART-KERAS-01" in rules(scan_bytes(padded, filename="m.h5")), pad


# ------------------------------------------------------------------ gguf
def test_gguf_versions_and_limits() -> None:
    from acl.artifacts import testing as t

    def parse(blob: bytes) -> set[str]:
        return {f.rule_id for f in scan_gguf(io.BytesIO(blob), len(blob))}

    base = fixture_bytes("benign_gguf")
    assert parse(base) == set()
    v2 = base[:4] + struct.pack("<I", 2) + base[8:]
    assert parse(v2) == set()
    assert parse(base[:4] + struct.pack("<I", 4) + base[8:]) == {"ART-GGUF-01"}
    assert parse(base[:4] + struct.pack("<I", 0) + base[8:]) == {"ART-GGUF-01"}
    assert parse(base[:4] + struct.pack(">I", 3) + base[8:]) == {"ART-GGUF-01"}  # big-endian marker
    # v1: u32 counts and lengths
    kv = struct.pack("<I", 4) + b"name" + struct.pack("<I", 8) + struct.pack("<I", 3) + b"abc"
    v1 = b"GGUF" + struct.pack("<III", 1, 0, 1)[:4] + struct.pack("<II", 0, 1) + kv
    assert parse(v1) == set()
    assert parse(v1[:-1]) == {"ART-GGUF-01"}
    # truncation anywhere in the header or data is malformed (never an exception)
    for cut in range(0, len(base), 7):
        assert parse(base[:cut]) <= {"ART-GGUF-01"}
    # structural violations
    gg = t._gguf
    kvs = [t._kv_str("general.architecture", "llama")]
    ok_tensor = t._tensor_info("a", [4], 0, 0)
    data = b"\x00" * 16
    assert parse(gg(kvs, [ok_tensor], data)) == set()
    assert parse(gg(kvs, [ok_tensor, ok_tensor], data)) == {"ART-GGUF-01"}  # duplicate tensor name
    assert parse(gg([kvs[0], kvs[0]], [], b"")) == {"ART-GGUF-01"}  # duplicate key
    assert parse(gg(kvs, [t._tensor_info("a", [1, 2, 3, 4, 5], 0, 0)], data)) == {"ART-GGUF-01"}  # 5 dims
    assert parse(gg(kvs, [t._tensor_info("a", [0], 0, 0)], data)) == {"ART-GGUF-01"}  # zero dim
    assert parse(gg(kvs, [t._tensor_info("a", [4], 99, 0)], data)) == {"ART-GGUF-01"}  # unknown ggml type
    assert parse(gg(kvs, [t._tensor_info("a", [4], 0, 4)], data)) == {"ART-GGUF-01"}  # unaligned offset
    assert parse(gg(kvs, [t._tensor_info("a", [4], 0, 32)], data)) == {"ART-GGUF-01"}  # beyond data
    assert parse(gg(kvs, [t._tensor_info("a", [1 << 40, 1 << 40], 0, 0)], data)) == {"ART-GGUF-01"}  # overflow
    assert parse(gg(kvs, [t._tensor_info("a", [30], 2, 0)], data)) == {"ART-GGUF-01"}  # Q4_0 row not x32
    assert parse(gg(kvs, [t._tensor_info("a", [4], 24, 0)], data)) == set()  # I8
    assert parse(gg(kvs, [], b"", tensor_count=5)) == {"ART-GGUF-01"}  # count > bytes
    assert parse(gg(kvs, [], b"", tensor_count=2_000_000)) == {"ART-GGUF-01"}
    big_align = [t._kv_u32("general.alignment", 1 << 17)]
    assert parse(gg(big_align, [], b"")) == {"ART-GGUF-01"}
    wrong_type = [t._kv_str("general.alignment", "32")]
    assert parse(gg(wrong_type, [], b"")) == {"ART-GGUF-01"}
    bad_vtype = [t._kv("x", 13, b"\x00" * 8)]
    assert parse(gg(bad_vtype, [], b"")) == {"ART-GGUF-01"}
    # arrays: bad element type, oversized length, nesting depth
    assert parse(gg([t._kv("x", 9, struct.pack("<IQ", 99, 0))], [], b"")) == {"ART-GGUF-01"}
    assert parse(gg([t._kv("x", 9, struct.pack("<IQ", 6, 1 << 40))], [], b"")) == {"ART-GGUF-01"}
    inner = struct.pack("<IQ", 4, 1) + struct.pack("<I", 1)  # array of u32
    mid = struct.pack("<IQ", 9, 1) + inner  # array of arrays
    top = struct.pack("<IQ", 9, 1) + mid  # array of arrays of arrays: too deep
    assert parse(gg([t._kv("x", 9, mid)], [], b"")) == set()
    assert parse(gg([t._kv("x", 9, top)], [], b"")) == {"ART-GGUF-01"}
    # oversized key length
    huge_key = struct.pack("<Q", 70_000) + b"k" * 70_000 + struct.pack("<I", 4) + struct.pack("<I", 1)
    assert parse(gg([huge_key], [], b"")) == {"ART-GGUF-01"}


def test_gguf_malformed_detail_has_header_facts_but_no_content() -> None:
    finding = next(f for f in scan("gguf_bad_alignment").findings if f.rule_id == "ART-GGUF-01")
    assert finding.detail is not None and "version=3" in finding.detail and "kv=2" in finding.detail
    assert finding.malicious and finding.severity.value == "high"


def test_gguf_template_markers() -> None:
    assert template_markers("{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}{% endfor %}") == []
    assert template_markers("{{ bos_token }}{% if pos.x %}{{ cos.y }}{% endif %}") == []
    for text in (
        "{{ x.__class__ }}",
        "{{ x.__globals__ }}",
        "{{ x.__subclasses__() }}",
        "{{ x.__builtins__ }}",
        "{{ __import__('os') }}",
        "{{ os.system('id') }}",
        "{{ x.popen('id') }}",
        "{{ subprocess.run('id') }}",
        "{{ lipsum.foo }}",
        "{{ x|attr('y') }}",
        "{{ y.__weird__ }}",
    ):
        assert template_markers(text), text
    # case-insensitive for the word markers
    assert template_markers("{{ x.POPEN() }}")


def test_gguf_template_in_named_template_key_is_checked() -> None:
    from acl.artifacts import testing as t

    blob = t._gguf(
        [t._kv_str("tokenizer.chat_template.rag", "{{ x.__class__ }}")],
        [],
        b"",
    )
    report = scan_bytes(blob, filename="m.gguf")
    assert report.verdict == "malicious" and rules(report) == {"ART-GGUF-02"}


# ------------------------------------------------------------------ safetensors
def _st(header: object, data: bytes = b"", *, raw: bytes | None = None) -> bytes:
    body = raw if raw is not None else json.dumps(header).encode()
    body += b" " * ((-len(body)) % 8)
    return struct.pack("<Q", len(body)) + body + data


def _st_ok(blob: bytes) -> bool:
    return scan_safetensors(io.BytesIO(blob), len(blob)) == []


def test_safetensors_header_rules() -> None:
    t = {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}
    assert _st_ok(_st({"a": t}, b"\x00" * 8))
    assert _st_ok(_st({"__metadata__": {"k": "v"}, "a": t}, b"\x00" * 8))
    assert _st_ok(_st({}, b""))  # no tensors, no data
    assert _st_ok(_st({"e": {"dtype": "F32", "shape": [0], "data_offsets": [0, 0]}}, b""))  # zero-size tensor
    assert _st_ok(_st({"s": {"dtype": "F32", "shape": [], "data_offsets": [0, 4]}}, b"\x00" * 4))  # scalar
    assert _st_ok(_st({"q": {"dtype": "F4", "shape": [4], "data_offsets": [0, 2]}}, b"\x00" * 2))  # sub-byte
    bad = [
        _st({"a": t}, b"\x00" * 7),  # data shorter than offsets
        _st({"a": t}, b"\x00" * 9),  # trailing bytes not covered
        _st({"a": {**t, "data_offsets": [0, 4]}}, b"\x00" * 4),  # size != prod(shape)*itemsize
        _st({"a": {**t, "dtype": "F33"}}, b"\x00" * 8),  # unknown dtype
        _st({"a": {**t, "dtype": 5}}, b"\x00" * 8),
        _st({"a": {**t, "shape": [-2]}}, b"\x00" * 8),
        _st({"a": {**t, "shape": [True, 2]}}, b"\x00" * 8),
        _st({"a": {**t, "shape": [1] * 9}}, b"\x00" * 8),
        _st({"a": {**t, "shape": "2"}}, b"\x00" * 8),
        _st({"a": {**t, "data_offsets": [0]}}, b"\x00" * 8),
        _st({"a": {**t, "data_offsets": [8, 0]}}, b"\x00" * 8),
        _st({"a": {**t, "data_offsets": [0.0, 8]}}, b"\x00" * 8),
        _st({"a": {**t, "data_offsets": [-8, 0]}}, b"\x00" * 8),
        _st({"a": t, "b": {**t, "data_offsets": [0, 8]}}, b"\x00" * 8),  # overlap
        _st({"a": t, "b": {**t, "data_offsets": [16, 24]}}, b"\x00" * 24),  # hole
        _st({"__metadata__": {"k": 1}, "a": t}, b"\x00" * 8),
        _st({"__metadata__": [], "a": t}, b"\x00" * 8),
        _st({"a": "nope"}, b""),
        _st([1, 2, 3], b""),
        _st(None, raw=b'{"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}, "a": 1}', data=b"\x00" * 8),
        _st(None, raw=b"{\xff}", data=b""),
        _st(None, raw=b' {"a": 1}', data=b""),  # does not start with an opening brace
        _st(None, raw=b"{" * 5000 + b"}" * 5000),
        b"",
        b"\x00" * 9,
        struct.pack("<Q", 1) + b"{" + b"\x00" * 4,  # header length 1 too small
        struct.pack("<Q", 2**63) + b"{}" + b"\x00" * 8,
    ]
    for i, blob in enumerate(bad):
        assert not _st_ok(blob), i
    for blob in bad:
        report = scan_bytes(blob, filename="m.safetensors")
        assert report.verdict == "malicious"


# ------------------------------------------------------------------ robustness: nothing is executed, nothing raises
def test_fuzz_never_raises_and_always_returns_a_valid_verdict() -> None:
    verdicts = {"safe", "malicious", "blocked_format", "suspicious"}
    permissive = ScanPolicy(allowed_formats=("safetensors", "gguf", "pickle", "torch_zip", "keras_v3", "zip", "hdf5"))
    scans = 0
    for name in sorted(FIXTURES):
        base = fixture_bytes(name)
        rng = random.Random(f"acl-fuzz-{name}")
        fname = fixture_filename(name)
        for i in range(200):
            blob = bytearray(base)
            op = i % 5
            if op == 0:
                blob = blob[: rng.randrange(0, len(blob) + 1)]
            elif op == 1:
                for _ in range(rng.randint(1, 8)):
                    if blob:
                        blob[rng.randrange(len(blob))] = rng.randrange(256)
            elif op == 2 and blob:
                start = rng.randrange(len(blob))
                del blob[start : start + rng.randint(1, 32)]
            elif op == 3:
                at = rng.randrange(len(blob) + 1)
                blob[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
            elif blob:
                start = rng.randrange(len(blob))
                blob[start : start + rng.randint(1, 16)] = b"\x00" * rng.randint(1, 16)
            data = bytes(blob)
            # alternate between the default policy and a permissive one so the walkers' output is exercised
            for policy in (ScanPolicy(), permissive):
                report = scan_bytes(data, filename=fname, policy=policy)
                scans += 1
                assert report.verdict in verdicts, (name, i)
                assert report.format_detected, (name, i)
                assert len(report.sha256) == 64
                assert not any(f.rule_id == "ART-INTERNAL-01" for f in report.findings), (name, i, report.findings)
                if report.verdict == "safe":
                    assert not any(f.malicious for f in report.findings)
                json.dumps(report.to_dict())
    assert scans == len(FIXTURES) * 400


def test_all_findings_are_bounded_and_clean_text() -> None:
    for name in FIXTURES:
        for finding in scan(name).findings:
            assert len(finding.message) <= 500
            assert finding.detail is None or len(finding.detail) <= 2000
            for text in (finding.message, finding.detail or ""):
                assert all(" " <= ch <= "~" for ch in text), (name, finding.rule_id)
            assert finding.rule_id.startswith("ART-")


def test_hostile_names_are_sanitised_in_messages() -> None:
    nasty = "evil\x00\x1b[31m\u202e/../data.pkl\n" + "A" * 5000
    blob = _zip_with([("archive/data.pkl", pickle.dumps({}, protocol=2)), (nasty, b"x")])
    report = scan_bytes(blob, filename="m.pt")
    for finding in report.findings:
        for text in (finding.message, finding.detail or ""):
            assert "\x1b" not in text and "\x00" not in text and "\n" not in text and len(text) <= 2000


def test_to_dict_is_json_safe_and_free_of_raw_content() -> None:
    for name in ("pickle_os_system", "torch_zip_os_system", "keras_lambda", "pickle_broken_stream", "h5_lambda"):
        report = scan(name)
        text = json.dumps(report.to_dict())
        assert "rogatka-test" not in text  # the payload string constant never leaks
        assert report.to_dict()["verdict"] == "malicious"
    data = scan("benign_safetensors").to_dict()
    assert set(data) == {
        "filename",
        "sha256",
        "size",
        "format_detected",
        "verdict",
        "findings",
        "pickle_globals",
        "exception",
    }
    assert json.loads(json.dumps(scan("pickle_os_system").to_dict()))["findings"][0]["severity"] in {
        "critical",
        "info",
        "high",
    }


def test_nothing_is_ever_unpickled_or_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("scanner tried to execute or unpickle file content")

    monkeypatch.setattr(pickle, "loads", boom)
    monkeypatch.setattr(pickle, "load", boom)
    monkeypatch.setattr(pickle, "Unpickler", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    import marshal

    monkeypatch.setattr(marshal, "loads", boom)
    for name in FIXTURES:
        report = scan(name)
        assert report.verdict in {"safe", "malicious", "blocked_format", "suspicious"}
        report = scan_file(fixture_path(name))
        assert report.verdict in {"safe", "malicious", "blocked_format", "suspicious"}


def test_large_file_is_streamed_not_loaded(tmp_path: Path) -> None:
    n = 48 * 1024 * 1024
    header = json.dumps({"big": {"dtype": "U8", "shape": [n], "data_offsets": [0, n]}}).encode()
    header += b" " * ((-len(header)) % 8)
    path = tmp_path / "big.safetensors"
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", len(header)) + header)
        chunk = b"\x01" * (1 << 20)
        for _ in range(n >> 20):
            handle.write(chunk)
    tracemalloc.start()
    try:
        report = scan_file(path)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert report.verdict == "safe" and report.size == path.stat().st_size
    assert peak < 8 * 1024 * 1024, peak  # hashing in 1 MiB chunks; header only


def test_oversized_file_is_flagged_but_still_scanned() -> None:
    report = scan("benign_safetensors", policy=ScanPolicy(max_file_bytes=10))
    assert rules(report) == {"ART-SIZE-01"} and report.verdict == "suspicious"


def test_scan_file_default_filename_and_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "weights.safetensors"
    path.write_bytes(fixture_bytes("benign_safetensors"))
    assert scan_file(path).filename == "weights.safetensors"
    assert scan_file(path, filename="other.gguf").verdict == "malicious"  # name is what the caller says it is
    with pytest.raises(FileNotFoundError):
        scan_file(tmp_path / "missing.pt")


def test_internal_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from acl.artifacts import scanner

    def explode(*_a: object, **_k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner, "scan_safetensors", explode)
    report = scan("benign_safetensors")
    assert report.verdict == "malicious" and rules(report) == {"ART-INTERNAL-01"}
    assert report.findings[0].detail == "RuntimeError"
