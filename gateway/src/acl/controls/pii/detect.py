"""PII tier T0: regex candidates + checksum validators → `Hit`s (concept §6.2 stage 1).

Entities: PESEL, NIP, REGON, PL_ID_CARD, IBAN, CREDIT_CARD, EMAIL, PHONE. Values never leave this
module except inside `Hit.value` (in-memory); callers hash or placeholder them.

Context rules keep false positives down for identifiers that are "just digits": a bare 10-digit NIP,
a 9/14-digit REGON and a bare 9-digit phone number are only reported when a keyword (NIP, REGON, tel, ...)
precedes them. Formatted NIPs (`123-456-32-18`), `+48` phones and grouped phones need no context.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from acl.controls.normalise.scan import Hit
from acl.controls.pii.validators import (
    IBAN_LENGTHS,
    valid_card,
    valid_iban,
    valid_nip,
    valid_pesel,
    valid_pl_id_card,
    valid_regon,
)

ALL_ENTITIES: tuple[str, ...] = ("IBAN", "CREDIT_CARD", "PESEL", "NIP", "REGON", "PL_ID_CARD", "EMAIL", "PHONE")
# entities that may be recovered from text whose line breaks were removed (long, checksummed)
JOINABLE: frozenset[str] = frozenset({"IBAN", "CREDIT_CARD", "PESEL"})

_DIGIT_RUN = re.compile(r"\d+")
_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)(?![A-Za-z0-9])")
_IBAN_PL_BARE = re.compile(r"(?<![\d])(\d{2}(?: ?\d{4}){6})(?![\d])")
_CARD = re.compile(r"(?<![\d])((?:\d[ -]?){12,18}\d)(?![\d])")
_PESEL = re.compile(r"(?<![\d])(\d{11})(?![\d])")
_NIP_FMT = re.compile(
    r"(?<![\d-])((?:PL ?)?(?:\d{3}[- ]\d{3}[- ]\d{2}[- ]\d{2}|\d{3}[- ]\d{2}[- ]\d{2}[- ]\d{3}))(?![\d-])"
)
_NIP_BARE = re.compile(r"(?<![\d-])((?:PL ?)?\d{10})(?![\d-])")
_REGON = re.compile(r"(?<![\d-])(\d{14}|\d{9})(?![\d-])")
_ID_CARD = re.compile(r"(?<![A-Za-z0-9])([A-Z]{3} ?\d{6})(?![A-Za-z0-9])")
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}(?![A-Za-z0-9@])"
)
_PHONE_INTL = re.compile(
    r"(?<![\w+])((?:\+|00)48[ -]?(?:\(?\d{2}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|\d{3}[ -]?\d{3}[ -]?\d{3}))(?![\d])"
)
_PHONE_GROUPED = re.compile(r"(?<![\d+-])([4-8]\d{2}[ -]\d{3}[ -]\d{3})(?![\d-])")
_PHONE_LANDLINE = re.compile(
    r"(?<![\d+-])(\(\d{2}\) ?\d{3}[ -]?\d{2}[ -]?\d{2}|\d{2}[ -]\d{3}[ -]\d{2}[ -]\d{2})(?![\d-])"
)
_PHONE_BARE = re.compile(r"(?<![\d-])([4-8]\d{8})(?![\d-])")

_NIP_CTX = ("nip", "vat", "tax id", "taxid", "tax number", "identyfikacji podatkowej")
_REGON_CTX = ("regon",)
_PHONE_CTX = (
    "tel",
    "phone",
    "mobile",
    "kom",
    "gsm",
    "numer",
    "kontakt",
    "contact",
    "call",
    "sms",
    "whatsapp",
    "zadzwo",
)

_SCORE = {
    "IBAN": 0.99,
    "CREDIT_CARD": 0.98,
    "PESEL": 0.99,
    "NIP": 0.97,
    "REGON": 0.95,
    "PL_ID_CARD": 0.9,
    "EMAIL": 0.95,
    "PHONE": 0.85,
}


def _ctx(text: str, start: int, words: tuple[str, ...], window: int = 32) -> bool:
    before = text[max(0, start - window) : start].lower()
    return any(w in before for w in words)


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def canonical(entity: str, value: str) -> str:
    """Identity of a value for pseudonymisation (same person/account → same placeholder)."""
    if entity == "IBAN":
        v = value.replace(" ", "").upper()
        return v if v[:2].isalpha() else "PL" + v
    if entity in ("PESEL", "REGON", "CREDIT_CARD"):
        return _digits(value)
    if entity == "NIP":
        return _digits(value)
    if entity == "PL_ID_CARD":
        return value.replace(" ", "").upper()
    if entity == "EMAIL":
        return value.lower()
    if entity == "PHONE":
        d = _digits(value)
        return d[-9:] if len(d) > 9 else d
    return value


def _iban_hits(text: str) -> Iterable[Hit]:
    for m in _IBAN.finditer(text):
        raw = m.group(1)
        compact = raw.replace(" ", "")
        want = IBAN_LENGTHS.get(compact[:2])
        if want is None or len(compact) < want:
            continue
        # consume exactly `want` alphanumerics (drops over-captured trailing words)
        count = 0
        end = 0
        for i, ch in enumerate(raw):
            if ch != " ":
                count += 1
                if count == want:
                    end = i + 1
                    break
        cand = raw[:end]
        if valid_iban(cand.replace(" ", "")):
            yield Hit("IBAN", m.start(1), m.start(1) + end, cand, _SCORE["IBAN"])
    for m in _IBAN_PL_BARE.finditer(text):
        compact = m.group(1).replace(" ", "")
        if valid_iban("PL" + compact):
            yield Hit("IBAN", m.start(1), m.end(1), m.group(1), _SCORE["IBAN"])


def _card_hits(text: str) -> Iterable[Hit]:
    for m in _CARD.finditer(text):
        digits = _digits(m.group(1))
        if 13 <= len(digits) <= 19 and valid_card(digits):
            yield Hit("CREDIT_CARD", m.start(1), m.end(1), m.group(1), _SCORE["CREDIT_CARD"])


def _simple(text: str, rx: re.Pattern[str], entity: str, ok, ctx_words: tuple[str, ...] | None = None) -> Iterable[Hit]:
    for m in rx.finditer(text):
        raw = m.group(1)
        if not ok(raw):
            continue
        if ctx_words is not None and not _ctx(text, m.start(1), ctx_words):
            continue
        yield Hit(entity, m.start(1), m.end(1), raw, _SCORE[entity])


def detect(text: str, entities: Iterable[str] = ALL_ENTITIES) -> list[Hit]:
    """Non-overlapping hits (priority: IBAN, card, PESEL, NIP, REGON, ID card, email, phone)."""
    want = set(entities)
    if not text or len(text) < 5:
        return []
    # lengths of the maximal digit runs: cheap pre-filter for the identifiers that are plain digit strings
    runs = {len(r) for r in _DIGIT_RUN.findall(text)}
    has_digit = bool(runs)
    cand: list[tuple[int, Hit]] = []

    def add(prio: int, hits: Iterable[Hit]) -> None:
        cand.extend((prio, h) for h in hits)

    if has_digit:
        if "IBAN" in want:
            add(0, _iban_hits(text))
        if "CREDIT_CARD" in want:
            add(1, _card_hits(text))
        if "PESEL" in want and 11 in runs:
            add(2, _simple(text, _PESEL, "PESEL", valid_pesel))
        if "NIP" in want:
            add(3, _simple(text, _NIP_FMT, "NIP", lambda r: valid_nip(_digits(r))))
            if 10 in runs:
                add(3, _simple(text, _NIP_BARE, "NIP", lambda r: valid_nip(_digits(r)), _NIP_CTX))
        if "REGON" in want and (9 in runs or 14 in runs):
            add(4, _simple(text, _REGON, "REGON", valid_regon, _REGON_CTX))
        if "PL_ID_CARD" in want and 6 in runs:
            add(5, _simple(text, _ID_CARD, "PL_ID_CARD", lambda r: valid_pl_id_card(r.replace(" ", ""))))
    if "EMAIL" in want and "@" in text:
        for m in _EMAIL.finditer(text):
            nxt = text[m.end() : m.end() + 2]
            if nxt[:1] == ":" and nxt[1:2].isalpha():  # git@host:org/repo (ssh remote), not a mailbox
                continue
            cand.append((6, Hit("EMAIL", m.start(), m.end(), m.group(0), _SCORE["EMAIL"])))
    if "PHONE" in want and has_digit:
        add(7, _simple(text, _PHONE_INTL, "PHONE", lambda _r: True))
        add(7, _simple(text, _PHONE_GROUPED, "PHONE", lambda _r: True))
        add(7, _simple(text, _PHONE_LANDLINE, "PHONE", lambda _r: True))
        if 9 in runs:
            add(7, _simple(text, _PHONE_BARE, "PHONE", lambda _r: True, _PHONE_CTX))

    cand.sort(key=lambda t: (t[0], t[1].start))
    chosen: list[Hit] = []
    for _prio, h in cand:
        if all(h.end <= c.start or h.start >= c.end for c in chosen):
            chosen.append(h)
    chosen.sort(key=lambda h: h.start)
    return chosen
