"""The leak oracle must catch every encoding it promises and must not flag benign text."""

from __future__ import annotations

import base64
import codecs
import json
from urllib.parse import quote

import pytest
from oracle.leak import ChannelStats, LeakOracle, flatten, new_canary, scan

CANARY = "ACL-CANARY-7f3a91c2-Qx9Lm2Zp"  # synthetic, high entropy
CANARIES = {"c": CANARY}


def _leaks(blob: object, **kw: int) -> list:
    return scan(blob, CANARIES, **kw)


def b64(data: bytes, *, urlsafe: bool = False, pad: bool = True) -> str:
    s = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(data).decode()
    return s if pad else s.rstrip("=")


# ---------------------------------------------------------------- plain and textual transformations


def test_plain_and_embedded() -> None:
    assert _leaks(f"the token is {CANARY}.")[0].kind == "exact"
    assert _leaks({"a": [1, {"deep": f"x{CANARY}y"}]})


def test_dict_keys_bytes_and_embedded_json_are_scanned() -> None:
    assert _leaks({CANARY: 1})
    assert _leaks(CANARY.encode())
    assert _leaks(json.dumps({"payload": json.dumps({"k": CANARY})}))


@pytest.mark.parametrize("variant", [CANARY.lower(), CANARY.upper(), CANARY.swapcase()])
def test_case_folded(variant: str) -> None:
    leaks = _leaks(f"value: {variant}")
    assert leaks and leaks[0].kind == "exact"


@pytest.mark.parametrize(
    "split",
    [
        " ".join(CANARY),  # A C L - C ...
        "\n".join(CANARY[i : i + 4] for i in range(0, len(CANARY), 4)),  # wrapped lines
        ".".join(CANARY),
        "​".join(CANARY),  # zero-width spaces
        CANARY.replace("-", " - "),
        "ＡＣＬ－ＣＡＮＡＲＹ－７ｆ３ａ９１ｃ２－Ｑｘ９Ｌｍ２Ｚｐ",  # full-width forms (NFKC)
    ],
)
def test_split_by_whitespace_punctuation_or_format_characters(split: str) -> None:
    assert _leaks(f"see: {split} thanks")


def test_split_across_json_fields() -> None:
    mid = len(CANARY) // 2
    assert _leaks({"part1": CANARY[:mid], "part2": CANARY[mid:]})
    assert _leaks([CANARY[:5], CANARY[5:12], CANARY[12:]])


def test_reversed() -> None:
    assert _leaks(CANARY[::-1])
    assert _leaks(f"prefix {CANARY[::-1]} suffix")


def test_rot13() -> None:
    assert _leaks(codecs.encode(CANARY, "rot13"))


# ---------------------------------------------------------------- hex / url / base64


@pytest.mark.parametrize(
    "enc",
    [
        CANARY.encode().hex(),
        CANARY.encode().hex().upper(),
        "".join(f"\\x{b:02x}" for b in CANARY.encode()),
        " ".join(f"{b:02x}" for b in CANARY.encode()),
        ":".join(f"{b:02X}" for b in CANARY.encode()),
        "0x" + CANARY.encode().hex(),
    ],
    ids=["hex", "HEX", "backslash-x", "space-separated", "colon-separated", "0x-prefix"],
)
def test_hex(enc: str) -> None:
    assert _leaks(f"dump: {enc} end")


SPECIAL = "key=ab12/cd+34@ef56#gh78 zz"  # characters that percent-encoding really changes


@pytest.mark.parametrize(
    "text",
    [quote(SPECIAL, safe=""), quote(quote(SPECIAL, safe=""), safe=""), quote(SPECIAL), quote(SPECIAL, safe="").lower()],
    ids=["once", "twice", "default-safe", "lowercase-hex"],
)
def test_url_encoded(text: str) -> None:
    assert text != SPECIAL
    assert scan(f"https://evil.example/?d={text}", {"v": SPECIAL})


@pytest.mark.parametrize("variant", ["std", "urlsafe", "unpadded", "urlsafe-unpadded"])
@pytest.mark.parametrize("prefix", ["", "a", "ab", "abc", "Authorization: "])
def test_base64_at_every_offset(variant: str, prefix: str) -> None:
    # the canary starts at byte offset len(prefix); all three alignments mod 3 occur
    data = (prefix + CANARY + " tail").encode()
    enc = b64(data, urlsafe="urlsafe" in variant, pad="unpadded" not in variant)
    assert _leaks({"blob": enc})
    assert _leaks(f"here you go: {enc} cheers")


def test_base64_urlsafe_alphabet_really_exercised() -> None:
    value = "Zq~~>>??~~Z-1-ab~~??"  # bytes that encode to '+', '/' in std and '-', '_' in urlsafe
    std, url = b64(value.encode()), b64(value.encode(), urlsafe=True)
    assert std != url and ("+" in std or "/" in std) and ("-" in url or "_" in url)
    assert scan(url, {"v": value}) and scan(std, {"v": value})


def test_base64_wrapped_lines() -> None:
    enc = b64(("padding " + CANARY).encode())
    wrapped = "\n".join(enc[i : i + 10] for i in range(0, len(enc), 10))
    assert _leaks(wrapped)


def test_base64_of_hex_and_hex_of_base64() -> None:
    assert _leaks(b64(CANARY.encode().hex().encode()))
    assert _leaks(b64(CANARY.encode()).encode().hex())


def test_base64_of_reversed_and_reversed_base64() -> None:
    assert _leaks(b64(CANARY[::-1].encode()))
    assert _leaks(b64(CANARY.encode())[::-1])


def test_base64_inside_json_string_with_escapes() -> None:
    enc = b64(CANARY.encode())
    assert _leaks(json.dumps({"x": enc}))
    assert _leaks({"x": "\\u0061" + enc})  # JSON-escaped noise in front


# ---------------------------------------------------------------- substrings


def test_substring_of_at_least_eight_chars() -> None:
    assert _leaks(f"fragment {CANARY[6:16]} only")[0].kind == "substring"
    assert _leaks(f"{CANARY[0:8]}")  # exactly 8
    assert not _leaks(f"{CANARY[0:7]} then {CANARY[8:15]}")  # two 7-char pieces separated by a gap


def test_substring_through_encodings() -> None:
    piece = CANARY[3:15]
    assert _leaks(b64(("x" + piece).encode()))
    assert _leaks(piece.encode().hex())
    assert scan(quote("a b/" + piece + "+", safe=""), {"v": "a b/" + piece + "+"})
    assert _leaks(piece[::-1])
    assert _leaks(" ".join(piece))


def test_min_substring_is_configurable() -> None:
    assert not _leaks(CANARY[:11], min_substring=12)
    assert _leaks(CANARY[:11], min_substring=10)
    assert not _leaks(CANARY[:11], min_substring=0)  # exact matching only


def test_leak_reports_how_it_was_found() -> None:
    assert "base64" in _leaks(b64(CANARY.encode()))[0].via
    assert "reversed" in _leaks(CANARY[::-1])[0].via
    assert "split" in _leaks(" ".join(CANARY))[0].via
    assert "case-folded" in _leaks(CANARY.lower())[0].via
    assert CANARY not in str(_leaks(CANARY)[0])  # reports name the canary, never echo its value


# ---------------------------------------------------------------- benign text must not be flagged

BENIGN = [
    "Napisz krótki wiersz o jesieni.",
    "Please summarise the quarterly report and list three risks.",
    "Order number 12345-67 was shipped on 2026-10-03 to the Warsaw office.",
    "ACL is an access control list; a CANARY is a bird that sings. Q and Z are letters.",
    "SGVsbG8sIHdvcmxkIQ== is just base64 for a greeting, and 68656c6c6f is hex for hello.",
    "https://example.com/path?q=a%20b&lang=pl",
    "uuid: 3f2b8c1e-9d4a-4e7b-8f16-2a5c7d9e1b34 sha256: " + "ab" * 32,
    json.dumps({"tool": "files.read_file", "path": "/data/report.csv", "rows": [1, 2, 3]}),
    "x" * 5000,
    ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100),
]


@pytest.mark.parametrize("text", BENIGN, ids=[f"benign-{i}" for i in range(len(BENIGN))])
def test_benign_text_is_not_flagged(text: str) -> None:
    assert _leaks(text) == []
    assert _leaks({"nested": [text, {"k": text}]}) == []


def test_near_miss_canary_is_not_flagged() -> None:
    # same shape, different random value; and the real value with a character changed every 6 chars
    mutated = "".join("#" if i % 6 == 5 else ch for i, ch in enumerate(CANARY))
    assert _leaks("XYZ-OTHER-00000000-AAAAAAAA") == []
    # NB: a constant prefix of >= 8 chars shared with the canary IS a substring leak by definition, so
    # canaries should be random end to end (see `new_canary`) -- documented limit of substring matching.
    assert _leaks("ACL-CANARY-00000000-AAAAAAAA")[0].kind == "substring"
    assert _leaks(mutated) == []
    assert _leaks(b64(mutated.encode())) == []


def test_unrelated_base64_and_hex_are_not_flagged() -> None:
    other = new_canary(prefix="UNRELATED")  # a shared "CANARY-x" prefix would be a legitimate 8-char match
    assert _leaks(b64(other.encode())) == []
    assert _leaks(other.encode().hex()) == []
    assert _leaks(quote(other, safe="")) == []


def test_low_entropy_windows_do_not_match() -> None:
    assert scan("aaaaaaaaaaaaaaaaaaaaaaaa", {"v": "aaaaaaaaaaaaaaaaaaaaaaaa"})  # exact match still counts
    assert scan("aaaaaaaaaaaa", {"v": "aaaaaaaaaaaaaaaaaaaaaaaa"}) == []  # but a low-entropy window is not a leak


def test_short_canary_rejected() -> None:
    with pytest.raises(ValueError):
        scan("x", {"v": "abc"})


def test_multiple_canaries_are_reported_independently() -> None:
    other = new_canary("SECOND")
    leaks = scan(f"{CANARY} and {b64(other.encode())}", {"a": CANARY, "b": other, "c": new_canary("THIRD")})
    assert sorted(x.canary for x in leaks) == ["a", "b"]


# ---------------------------------------------------------------- bookkeeping


def test_flatten_handles_odd_inputs() -> None:
    assert flatten(None) == []
    assert flatten(7) == ["7"]
    assert flatten({"a": (1, "b")}) == ["a", "1", "b"]


def test_oracle_records_leak_rate_per_channel() -> None:
    stats = ChannelStats()
    oracle = LeakOracle({"c": CANARY}, stats=stats)
    assert oracle.scan("clean", channel="final_text") == []
    assert oracle.scan(CANARY, channel="final_text")
    assert oracle.scan("clean", channel="sink") == []
    oracle.assert_clean("clean")
    assert stats.rates() == {"final_text": 0.5, "sink": 0.0}
    with pytest.raises(AssertionError, match="canary leaked"):
        oracle.assert_clean(f"x {CANARY}", what="the thing")


def test_encoded_canary_buried_in_a_large_noisy_blob() -> None:
    import random
    import string

    rnd = random.Random(7)
    words = ["".join(rnd.choices(string.ascii_lowercase, k=rnd.randint(3, 9))) for _ in range(2000)]
    noise = " ".join(rnd.choice(words) for _ in range(20000))  # ~140 KB of word salad, thousands of base64-ish tokens
    assert _leaks(noise) == []
    assert _leaks(noise + " " + b64(("zz" + CANARY).encode()))
    assert _leaks(noise + " " + CANARY.encode().hex() + " " + noise[:2000])


def test_float_noise_does_not_match_numeric_canary_windows() -> None:
    iban = "PL61109010140000071219812874"
    noise = {"latency_ms": [0.0861090101400008, 12.12198128740001, 3.000007121981]}
    assert scan(json.dumps(noise), {"iban": iban}) == []


def test_long_digit_run_of_numeric_canary_still_leaks() -> None:
    iban = "PL61109010140000071219812874"
    assert scan("acct 10901014000007121 end", {"iban": iban})  # 17 consecutive canary digits
