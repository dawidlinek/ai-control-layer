"""Checksum validators for identifiers (pure functions, digits-only inputs unless stated)."""

from __future__ import annotations

import datetime as dt
import re

# ----------------------------------------------------------------------------- PESEL


def valid_pesel(s: str) -> bool:
    """11 digits, weighted checksum, and a calendar-valid birth date (month encodes the century)."""
    if len(s) != 11 or not s.isdigit() or not s.isascii():
        return False
    d = [int(c) for c in s]
    if (10 - sum(w * x for w, x in zip((1, 3, 7, 9, 1, 3, 7, 9, 1, 3), d[:10], strict=True)) % 10) % 10 != d[10]:
        return False
    yy, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
    century = {0: 1900, 1: 2000, 2: 2100, 3: 2200, 4: 1800}.get(mm // 20)
    if century is None:
        return False
    try:
        dt.date(century + yy, mm % 20, dd)
    except ValueError:
        return False
    return True


# ----------------------------------------------------------------------------- NIP / REGON


def valid_nip(s: str) -> bool:
    if len(s) != 10 or not s.isdigit() or not s.isascii():
        return False
    d = [int(c) for c in s]
    total = sum(w * x for w, x in zip((6, 5, 7, 2, 3, 4, 5, 6, 7), d[:9], strict=True)) % 11
    return total != 10 and total == d[9]


def valid_regon(s: str) -> bool:
    if not s.isdigit() or not s.isascii() or len(s) not in (9, 14):
        return False
    d = [int(c) for c in s]
    w9 = (8, 9, 2, 3, 4, 5, 6, 7)
    c9 = sum(w * x for w, x in zip(w9, d[:8], strict=True)) % 11 % 10
    if c9 != d[8]:
        return False
    if len(s) == 9:
        return True
    w14 = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)
    return sum(w * x for w, x in zip(w14, d[:13], strict=True)) % 11 % 10 == d[13]


# ----------------------------------------------------------------------------- Polish ID card


def valid_pl_id_card(s: str) -> bool:
    """`ABC123456`: three capital letters + six digits; the 4th character is the check digit."""
    if len(s) != 9 or not re.fullmatch(r"[A-Z]{3}\d{6}", s):
        return False
    vals = [ord(c) - 55 for c in s[:3]] + [int(c) for c in s[3:]]
    weights = (7, 3, 1, 0, 7, 3, 1, 7, 3)
    return sum(w * v for w, v in zip(weights, vals, strict=True)) % 10 == vals[3]


# ----------------------------------------------------------------------------- IBAN

_IBAN_SPEC = (
    "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BR29 BY28 CH21 CR22 CY28 CZ24 DE22 DK18 DO28 EE20 EG29 ES24 FI18 "
    "FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 "
    "LU20 LV21 MC27 MD24 ME22 MK19 MR27 MT31 MU30 NL18 NO15 PK24 PL28 PS29 PT25 QA29 RO24 RS22 SA24 SC31 SE24 SI19 "
    "SK24 SM27 ST25 SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20"
)
IBAN_LENGTHS: dict[str, int] = {pair[:2]: int(pair[2:]) for pair in _IBAN_SPEC.split()}


def valid_iban(s: str) -> bool:
    """IBAN without spaces: country length + ISO 7064 mod-97-10."""
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    if IBAN_LENGTHS.get(s[:2]) != len(s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


# ----------------------------------------------------------------------------- payment cards


def luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or not digits.isascii():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_SCHEMES: tuple[tuple[str, re.Pattern[str], tuple[int, ...]], ...] = (
    ("visa", re.compile(r"4"), (13, 16, 19)),
    ("mastercard", re.compile(r"5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)"), (16,)),
    ("amex", re.compile(r"3[47]"), (15,)),
    ("discover", re.compile(r"6011|65|64[4-9]"), (16, 17, 18, 19)),
    ("diners", re.compile(r"3(?:0[0-5]|[689])"), (14, 15, 16, 17, 18, 19)),
    ("jcb", re.compile(r"35(?:2[89]|[3-8]\d)"), (16, 17, 18, 19)),
    ("unionpay", re.compile(r"62"), (16, 17, 18, 19)),
    ("maestro", re.compile(r"5018|5020|5038|5893|6304|6759|676[1-3]"), tuple(range(12, 20))),
)


def card_scheme(digits: str) -> str | None:
    for name, prefix, lengths in _SCHEMES:
        if len(digits) in lengths and prefix.match(digits):
            return name
    return None


def valid_card(digits: str) -> bool:
    """Luhn + a known issuer prefix with a matching length."""
    return card_scheme(digits) is not None and luhn_ok(digits)
