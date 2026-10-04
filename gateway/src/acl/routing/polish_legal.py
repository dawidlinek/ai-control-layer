"""Deterministic Polish-legal-text detector (task `polish_legal` of `acl.routing.specialist`).

The kNN over a specialist's `examples` is a lexical overlap: a perfectly good Polish legal question that shares few
words with any example scores below the threshold and falls through to the cloud model. This detector closes that gap
without a model call, a network call or a dependency (about 0.2 ms for 2 KB):

    confidence = language score x legal-domain score            (both in [0, 1])

* language score: Polish function words ("czy", "jest", "według", "oraz" ...), Polish diacritics and Polish
  inflection endings, combined noisy-or. English text scores 0, so an English legal question never matches.
* legal-domain score: a weighted lexicon (contracts, civil / labour / criminal codes, procedure, courts, data
  protection, inheritance ...) matched on diacritic-folded tokens by exact inflection or by stem, plus regexes for
  article citations ("art. 415 k.c."), code abbreviations ("k.p.c."), "Dz.U." and "§ 3". Each distinct term counts
  once (noisy-or), repeated up to three times it counts more, so a pasted contract that keeps saying "umowa" wins
  while one incidental "umowa" in a Polish sentence about coffee does not (a single term never reaches 0.5).

The result carries only a short reason made of scores, counts and coarse domain categories: no prompt text.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

__all__ = ["Detection", "detect"]

_HEAD = 8000
_TAIL = 2000
_TOKEN = re.compile(r"[^\W\d_]+")
_PL_CHARS = frozenset("ąćęłńśźż")
_FN_FULL = 0.15  # share of Polish function words that already means "clearly Polish"
_DIA_FULL = 0.10  # share of words with a Polish diacritic that already means "clearly Polish"
_MORPH_FULL = 0.25
_MAX_REPEAT = 3

# Function words that are not English words (diacritics folded). Ambiguous ones (to, do, ten, pod, ale, a, i ...)
# are left out.
_FUNCTION_WORDS = frozenset(
    """
    czy jest sa nie sie ze na od po za przez przy dla bez nad oraz lub albo jak jaki jaka jakie jakich jakiej
    jakim ktory ktora ktore ktorego ktorej ktorych ktorym tego tej tym tych jego jej ich byc byl byla bylo beda
    bedzie moze mozna musi musze mam mamy chce prosze wedlug zgodnie czyli wiec takze rowniez jednak bardzo tylko
    juz jeszcze wszystkie wszystkich wszystko kazdy kazda gdy gdzie kiedy dlaczego czego czym kto ponadto mi mnie
    ma maja wlasnie takie taki taka tez tak ani lecz pomoc napisz podaj wyjasnij sporzadz przygotuj zinterpretuj
    co mowi mowia wynika dotyczy oznacza zawiera wolno powinien powinna powinno czym
    """.split()  # noqa: SIM905
)
# Inflection endings (folded) that are common in Polish and rare in English; matched on words of 6+ letters.
_ENDINGS = ("ego", "emu", "ymi", "ych", "osci", "ania", "enia", "nego", "owac", "ujac", "skiej", "cznej", "wych")


_FOLD = str.maketrans("ąćęłńóśźż", "acelnoszz")


def _fold(text: str) -> str:
    """Text without Polish diacritics (a translate table: fast; the lexicon is written in folded form)."""
    return text.translate(_FOLD)


def _forms(stem: str, endings: str) -> list[str]:
    return [stem + e for e in endings.split("|")]


@dataclass(frozen=True)
class _Term:
    category: str
    weight: float
    exact: frozenset[str] = frozenset()
    stems: tuple[str, ...] = ()


def _t(category: str, weight: float, exact: list[str] | None = None, stems: tuple[str, ...] = ()) -> _Term:
    return _Term(category, weight, frozenset(exact or ()), stems)


_N = "a|y|ie|e|ach|ami|om|"  # umowa-type feminine noun endings (+ bare genitive plural)
_TERMS: tuple[_Term, ...] = (
    # contracts (exact forms where the stem is also an everyday word: umowic sie, ustawienia, przepis ...)
    _t("contract", 0.40, [*_forms("umow", _N), "umowna", "umowne", "umownej", "umowny", "umownego"]),
    # "najm..." alone is also najmniej / najmlodszy: only the inflected forms of najem
    _t("contract", 0.40, ["najem", "najmu", "najmie", "najmem", "najmy", "najmow"], stems=("najemc", "najemn")),
    _t("contract", 0.40, stems=("wynajm", "wynajem", "dzierzaw")),
    _t("contract", 0.40, stems=("aneks", "niedozwolon", "pelnomocnict", "pelnomocni")),
    _t("contract", 0.35, stems=("klauzul",)),
    _t("contract", 0.30, stems=("regulamin",)),
    _t("contract", 0.45, stems=("wypowiedzen", "rekojmi", "poreczen", "cesj")),
    _t("contract", 0.25, [*_forms("odstapien", "ie|ia|iu|iem"), *_forms("zlecen", "ie|ia|iu|iem")]),
    _t("contract", 0.30, stems=("zobowiazan", "kontraktow", "kaucj", "czynsz", "lokator")),
    # civil / general law
    _t("civil", 0.50, stems=("kodeks",)),
    _t("civil", 0.45, ["kc", "kpc", "kpk", "kpa", "kro", "ksh"]),
    _t("civil", 0.35, stems=("cywiln", "cywilnoprawn")),
    _t("civil", 0.50, stems=("przedawnien", "zadoscuczynien", "deliktow", "intercyz", "eksmisj", "wieczyst")),
    _t("civil", 0.45, stems=("odszkodowan", "roszczen", "wierzyciel", "dziedziczen", "orzecznict")),
    _t("civil", 0.40, stems=("dluznik", "hipotek", "wykladni", "kazus")),
    _t("civil", 0.50, stems=("spadkobierc", "spadkodaw", "zachowek")),
    _t("civil", 0.30, stems=("spadkow", "testamen", "notari", "notarial")),
    _t("civil", 0.25, [*_forms("spadek", "|u|iem|ach"), *_forms("spadk", "u|iem|ach")]),
    _t("civil", 0.35, stems=("prawnik", "prawn", "kancelari")),
    _t("civil", 0.15, ["prawo", "prawa", "prawem"]),
    # procedure and courts
    _t("procedure", 0.50, ["pozew", "pozwu", "pozwie", "pozwem", "pozwy", "pozwow", "pozwany", "pozwana", "pozwanego"]),
    _t("procedure", 0.50, stems=("apelacj", "kasacj", "powodztw")),
    _t("procedure", 0.40, stems=("wyrok", "zazalen", "orzeczen", "prokurat", "adwokat", "oskarz")),
    _t("procedure", 0.30, stems=("sedzi", "sedzio", "radc")),
    _t(
        "procedure",
        0.25,
        ["sad", "sadu", "sadzie", "sadem", "sady", "sadow", "sadowi", "sadowy", "sadowa", "sadowe", "sadowego"],
    ),
    _t("procedure", 0.20, stems=("postepowan",)),
    # criminal
    _t("criminal", 0.45, stems=("przestepst", "wykroczen", "karnoprawn")),
    # family
    _t("family", 0.45, stems=("rozwod", "alimen")),
    _t("family", 0.30, stems=("separacj",)),
    # statutes and data protection
    _t("statute", 0.35, _forms("ustaw", "a|y|ie|e|ach|ami|om")),
    _t("statute", 0.40, stems=("rozporzadzen", "konstytuc")),
    _t("statute", 0.30, stems=("trybunal", "dyrektyw")),
    _t("data protection", 0.45, ["rodo", "uodo"]),
    _t("labour", 0.30, stems=("mobbing", "pracodawc")),
)
_EXACT: dict[str, list[tuple[int, _Term]]] = {}  # form -> terms
_BY_PREFIX: dict[str, list[tuple[int, _Term, str]]] = {}
for _i, _term in enumerate(_TERMS):
    for _form in _term.exact:
        _EXACT.setdefault(_form, []).append((_i, _term))
    for _stem in _term.stems:
        _BY_PREFIX.setdefault(_stem[:4], []).append((_i, _term, _stem))


@dataclass(frozen=True)
class _Pattern:
    name: str
    category: str
    weight: float
    regex: re.Pattern[str]
    needles: tuple[str, ...]  # cheap substring pre-check: the regex only runs when one of them occurs


_CODE = r"(?:k\.\s?[a-z]\.?(?:\s?[a-z]\.)*|kodeksu|ustawy|konstytucji|rozporzadzenia|kc|kpc|kpk|kpa|kro|ksh|kp|kk|kw)"
# phrase / citation patterns on lower-cased, diacritic-folded text; of the patterns sharing a name only one counts
_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        "article citation",
        "citation",
        0.85,
        re.compile(r"\bart\.?\s*\d{1,4}\s?[a-z]?(?:\s*(?:§|par\.?|ust\.?|pkt|lit\.?)\s*\d+[a-z]?)*\s*" + _CODE + r"\b"),
        ("art",),
    ),
    _Pattern("article citation", "citation", 0.45, re.compile(r"\bart\.\s*\d{1,4}\s?[a-z]?\b"), ("art.",)),
    _Pattern(
        "code abbreviation",
        "citation",
        0.60,
        re.compile(r"\bk\.\s?(?:[cpkrsw]|r\.\s?o|s\.\s?h|p\.\s?[cka])\."),
        ("k.",),
    ),
    _Pattern("journal of laws", "citation", 0.60, re.compile(r"\bdz\.\s?u\."), ("dz.",)),
    _Pattern("case reference", "procedure", 0.50, re.compile(r"\bsygn\."), ("sygn",)),
    _Pattern("paragraph sign", "citation", 0.20, re.compile(r"§\s*\d"), ("§",)),
    _Pattern(
        "labour code",
        "labour",
        0.45,
        re.compile(r"\b(?:kodeks\w*|prawo|prawa|stosunek|stosunku|umow\w*) (?:pracy|o prace|o dzielo|zlecenia)\b"),
        ("pracy", "prace", "dzielo", "zlecenia"),
    ),
    _Pattern("labour law", "labour", 0.40, re.compile(r"\bokres\w* wypowiedzenia\b"), ("wypowiedzenia",)),
    _Pattern(
        "data protection law",
        "data protection",
        0.55,
        re.compile(r"\bochron\w+ danych osobowych\b"),
        ("osobowych",),
    ),
    _Pattern(
        "data controller", "data protection", 0.40, re.compile(r"\badministrator\w* danych\b"), ("administrator",)
    ),
    _Pattern("contractual penalty", "contract", 0.45, re.compile(r"\bkar\w+ umown\w+"), ("umown",)),
)


@dataclass(frozen=True)
class Detection:
    """`confidence = lang * legal`; `reason` holds scores, counts and categories only (never prompt text)."""

    confidence: float
    lang: float
    legal: float
    terms: int = 0
    categories: tuple[str, ...] = ()
    citation: bool = False

    @property
    def reason(self) -> str:
        parts = [f"lang=pl {self.lang:.2f}", f"legal={self.legal:.2f}"]
        extra: list[str] = []
        if self.terms:
            extra.append(f"legal terms={self.terms}")
        if self.citation:
            extra.append("legal citation")
        if self.categories:
            extra.append("domain: " + ", ".join(self.categories))
        return ", ".join(parts) + (f" ({'; '.join(extra)})" if extra else "")


_NONE = Detection(0.0, 0.0, 0.0)


def _window(text: str) -> str:
    return text if len(text) <= _HEAD + _TAIL else text[:_HEAD] + "\n" + text[-_TAIL:]


def _language(raw: Counter[str], folded: Counter[str]) -> float:
    total = folded.total()
    if not total:
        return 0.0
    fn = sum(n for t, n in folded.items() if t in _FUNCTION_WORDS)
    dia = sum(n for t, n in raw.items() if not _PL_CHARS.isdisjoint(t))
    morph = sum(n for t, n in folded.items() if len(t) >= 6 and t.endswith(_ENDINGS))
    lang_fn = min(1.0, fn / total / _FN_FULL)
    lang_dia = min(1.0, dia / total / _DIA_FULL)
    lang_morph = min(1.0, morph / total / _MORPH_FULL)
    return 1.0 - (1.0 - lang_fn) * (1.0 - 0.9 * lang_dia) * (1.0 - 0.5 * lang_morph)


def _noisy_or(weights: list[float]) -> float:
    miss = 1.0
    for w in weights:
        miss *= 1.0 - w
    return 1.0 - miss


def detect(text: str) -> Detection:
    """Score `text` as Polish legal text. Deterministic, dependency-free, no I/O."""
    if not text or not text.strip():
        return _NONE
    text = _window(text)
    lowered = text.lower()
    folded_text = _fold(lowered)
    # token counts only: folding is 1:1 on letters, so the raw and the folded text tokenise identically
    raw = Counter(_TOKEN.findall(lowered))
    folded = Counter(_TOKEN.findall(folded_text))
    lang = _language(raw, folded)
    if lang <= 0.0:
        return _NONE  # nothing Polish about it: skip the lexicon

    hits: Counter[int] = Counter()
    for tok, count in folded.items():
        matched: set[int] = set()
        for i, _ in _EXACT.get(tok, ()):
            matched.add(i)
        if len(tok) >= 4:
            for i, _, stem in _BY_PREFIX.get(tok[:4], ()):
                if tok.startswith(stem):
                    matched.add(i)
        for i in matched:
            hits[i] += count

    terms = len(hits)
    score_parts = [1.0 - (1.0 - _TERMS[i].weight) ** min(n, _MAX_REPEAT) for i, n in hits.items()]
    cats = {_TERMS[i].category for i in hits}
    citation = False
    seen_patterns: set[str] = set()
    for pat in _PATTERNS:
        if pat.name in seen_patterns or not any(x in folded_text for x in pat.needles):
            continue  # the weaker twin of an already matched pattern / cheap pre-check
        n = len(pat.regex.findall(folded_text))
        if n:
            seen_patterns.add(pat.name)
            terms += 1
            score_parts.append(1.0 - (1.0 - pat.weight) ** min(n, _MAX_REPEAT))
            cats.add(pat.category)
            citation = citation or pat.category == "citation"
    legal = _noisy_or(score_parts)
    if legal <= 0.0:
        return Detection(0.0, round(lang, 3), 0.0)
    cats.discard("citation")
    return Detection(
        round(lang * legal, 3),
        round(lang, 3),
        round(legal, 3),
        terms=terms,
        categories=tuple(sorted(cats)),
        citation=citation,
    )
