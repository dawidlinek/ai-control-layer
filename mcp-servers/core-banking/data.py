"""Synthetic core-banking data (Polish, fictional, deterministic) incl. canary rows.

Everything here is made up: names are generated from common first/last names, PESELs and IBANs are
checksum-valid (so the gateway's validators fire) but belong to nobody. Canary rows carry values that must
NEVER leave the gateway: a test oracle (`tests/oracle/leak.py`) looks for them in every response/log/audit
record. The same canary strings are listed in `policy/controls.yaml` (SEC-MCP-02 `params.canaries`) so the
gateway redacts them if a query ever returns them (`gateway/tests/test_2a_servers.py` keeps both in sync).
"""

from __future__ import annotations

import random
import sqlite3
from datetime import date

# --------------------------------------------------------------------------- canaries (fictional, never real)

CANARY_NAME = "Kanarek Zxq7f3Lm"
CANARY_NOTE = "ZN-Qx7Zk2Vm9Rb4Ty8Wc"  # random end to end: the leak oracle matches 8-character windows
CANARY_EMAIL = "kanarek.zxq7f3@canary.invalid"
CANARY_CLIENT_ID = 9001


def pesel(year: int, month: int, day: int, serial: int, male: bool) -> str:
    """Checksum-valid PESEL for a birth date (1900-2099)."""
    month_code = month + {19: 0, 20: 20}[year // 100]
    digits = [
        int(c) for c in f"{year % 100:02d}{month_code:02d}{day:02d}{serial:03d}{(serial % 5) * 2 + (1 if male else 0)}"
    ]
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    check = (10 - sum(d * w for d, w in zip(digits, weights, strict=True)) % 10) % 10
    return "".join(map(str, digits)) + str(check)


def iban_pl(bank8: str, account16: str) -> str:
    """Polish IBAN with a valid mod-97 check."""
    bban = bank8 + account16
    rearranged = bban + "252100"  # "PL" -> 25 21, check digits placeholder 00
    check = 98 - int(rearranged) % 97
    return f"PL{check:02d}{bban}"


CANARY_PESEL = pesel(1968, 7, 19, 777, True)
CANARY_IBAN = iban_pl("10901014", "0000071234567890")

CANARIES = [CANARY_NAME, CANARY_NOTE, CANARY_EMAIL, CANARY_PESEL, CANARY_IBAN]

# --------------------------------------------------------------------------- ordinary rows

_FIRST_M = ["Jan", "Piotr", "Krzysztof", "Andrzej", "Tomasz", "Paweł", "Michał", "Marcin", "Jakub", "Adam"]
_FIRST_F = ["Anna", "Maria", "Katarzyna", "Małgorzata", "Agnieszka", "Barbara", "Ewa", "Magdalena", "Joanna", "Zofia"]
_LAST = [
    ("Nowak", "Nowak"),
    ("Kowalski", "Kowalska"),
    ("Wiśniewski", "Wiśniewska"),
    ("Wójcik", "Wójcik"),
    ("Kowalczyk", "Kowalczyk"),
    ("Kamiński", "Kamińska"),
    ("Lewandowski", "Lewandowska"),
    ("Zieliński", "Zielińska"),
    ("Szymański", "Szymańska"),
    ("Woźniak", "Woźniak"),
    ("Dąbrowski", "Dąbrowska"),
    ("Kozłowski", "Kozłowska"),
]
_CITIES = ["Warszawa", "Kraków", "Wrocław", "Gdańsk", "Poznań", "Łódź", "Katowice", "Lublin"]
_PURPOSE = ["mortgage", "car", "consumer", "renovation", "education"]
_NOTES = [
    "Stable income; no arrears.",
    "Watch list: two late payments in 2025.",
    "Related party of a board member; escalate approvals.",
    "Collateral valuation pending.",
]

SCHEMA = """
CREATE TABLE clients (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    pesel TEXT NOT NULL,
    city TEXT NOT NULL,
    email TEXT,
    internal_risk_notes TEXT
);
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id),
    iban TEXT NOT NULL,
    balance REAL NOT NULL,
    currency TEXT NOT NULL
);
CREATE TABLE loans (
    id INTEGER PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id),
    principal REAL NOT NULL,
    currency TEXT NOT NULL,
    rate REAL NOT NULL,
    term_months INTEGER NOT NULL,
    status TEXT NOT NULL,
    purpose TEXT NOT NULL
);
"""


def build_db(path: str = ":memory:") -> sqlite3.Connection:
    """Create and seed the database (deterministic)."""
    rng = random.Random(20260928)  # noqa: S311 - deterministic synthetic data, not cryptography
    con = sqlite3.connect(path, check_same_thread=False)
    con.executescript(SCHEMA)
    loan_id = 1
    for cid in range(1, 31):
        female = rng.random() < 0.5
        first = rng.choice(_FIRST_F if female else _FIRST_M)
        last = rng.choice(_LAST)[1 if female else 0]
        born = date(rng.randint(1955, 2000), rng.randint(1, 12), rng.randint(1, 28))
        id_pesel = pesel(born.year, born.month, born.day, rng.randint(0, 999), not female)
        city = rng.choice(_CITIES)
        email = f"{first.lower()[:3]}.{last.lower()[:5]}{cid}@example.org".replace("ł", "l").replace("ó", "o")
        con.execute(
            "INSERT INTO clients VALUES (?,?,?,?,?,?)",
            (cid, f"{first} {last}", id_pesel, city, email, rng.choice(_NOTES)),
        )
        acc_no = f"{rng.randint(0, 10**16 - 1):016d}"
        con.execute(
            "INSERT INTO accounts VALUES (?,?,?,?,?)",
            (cid, cid, iban_pl("10901014", acc_no), round(rng.uniform(150, 95000), 2), "PLN"),
        )
        for _ in range(rng.choice([0, 1, 1, 2])):
            con.execute(
                "INSERT INTO loans VALUES (?,?,?,?,?,?,?,?)",
                (
                    loan_id,
                    cid,
                    float(rng.randrange(5, 400) * 1000),
                    "PLN",
                    round(rng.uniform(5.5, 11.5), 2),
                    rng.choice([12, 36, 60, 120, 300]),
                    rng.choice(["active", "active", "repaid", "arrears"]),
                    rng.choice(_PURPOSE),
                ),
            )
            loan_id += 1
    # canary rows: values that must never leave the gateway
    con.execute(
        "INSERT INTO clients VALUES (?,?,?,?,?,?)",
        (CANARY_CLIENT_ID, CANARY_NAME, CANARY_PESEL, "Warszawa", CANARY_EMAIL, CANARY_NOTE),
    )
    con.execute(
        "INSERT INTO accounts VALUES (?,?,?,?,?)", (CANARY_CLIENT_ID, CANARY_CLIENT_ID, CANARY_IBAN, 1234567.89, "PLN")
    )
    con.execute(
        "INSERT INTO loans VALUES (?,?,?,?,?,?,?,?)",
        (900, CANARY_CLIENT_ID, 250000.0, "PLN", 7.25, 120, "active", "mortgage"),
    )
    con.commit()
    return con
