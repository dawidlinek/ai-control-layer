"""Generate the Automation Insights demo history (`history.jsonl`). Deterministic: `python generate.py`.

Synthetic, already-redacted prompts as the gateway would store them (`redacted_payload`): personal data appears
only as pseudonyms (`<PERSON_1>`, `<PESEL_1>`, `<IBAN_1>`). Dates are relative (`workdays_ago` / `days_ago`) and
models are roles (`@local`, `@cloud`) so the history stays recent and fits whatever model line-up the policy has.

Stories (scenario 14):
- credit-analysts (6 people) summarise a loan application for the credit committee on every workday, ~5 times a
  day with regenerations, ~40 min/day in total; confidential → served by the local model.
- developers (6 people) write release notes from commit lists twice a week (Mon, Thu) on the cloud model.
- developers (3 people only) generate SQL migrations: a real cluster, hidden from management because k = 5.
- ad-hoc questions in both groups (noise) and an operations group that has not opted in.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

OUT = Path(__file__).with_name("history.jsonl")
WORKDAYS = 22
rng = random.Random(1404)  # noqa: S311 - reproducible synthetic data, not security

ANALYSTS = ["anna.nowak", "marta.lis", "tomasz.wisniewski", "ola.kaczmarek", "michal.wrobel", "julia.zajac"]
DEVELOPERS = ["jan.kowalski", "piotr.zielinski", "adam.nowicki", "ola.mazur", "bartek.lis", "kuba.wojcik"]
OPERATIONS = ["ewa.grabowska", "lena.krol", "igor.sowa"]

LOAN_INSTRUCTIONS = [
    ("Summarise this loan application for the credit committee", 7),
    ("Summarise this loan application into a credit memo for the committee", 2),
    ("Please summarise this loan application for the credit committee", 1),
]
PRODUCTS = [
    ("mortgage", "purchase of a flat in {city}", (240_000, 780_000), (20, 30)),
    ("cash loan", "home renovation", (20_000, 90_000), (3, 8)),
    ("car loan", "purchase of a used car", (35_000, 140_000), (4, 7)),
    ("refinancing", "consolidation of two consumer loans", (40_000, 160_000), (5, 10)),
]
CITIES = ["Wrocław", "Kraków", "Poznań", "Gdańsk", "Łódź", "Warszawa", "Opole"]
EMPLOYMENT = [
    "permanent contract since {y}",
    "self-employed (sole trader) since {y}",
    "civil-law contract since {y}",
    "permanent contract in the public sector since {y}",
]
OBLIGATIONS = [
    "none",
    "car loan {n} PLN/month",
    "credit card limit {n} PLN",
    "cash loan {n} PLN/month",
    "mortgage {n} PLN/month (co-borrower)",
]
COLLATERAL = [
    "mortgage on the property",
    "none",
    "car registration certificate",
    "guarantor <PERSON_2>",
    "blocked deposit",
]

RELEASE_INSTRUCTIONS = [
    ("Write release notes for these commits", 7),
    ("Write short release notes for these commits", 2),
    ("Please write release notes for these commits", 1),
]
COMMIT_TYPES = ["feat", "fix", "chore", "refactor", "perf", "docs"]
AREAS = ["api", "auth", "billing", "ui", "export", "search", "notifications", "reports", "cli", "db"]
CHANGES = [
    "add pagination to {a} endpoints",
    "handle empty {a} payloads",
    "retry failed {a} jobs with backoff",
    "remove deprecated {a} flags",
    "cache {a} lookups for 5 minutes",
    "validate {a} input against the schema",
    "speed up {a} queries with an index",
    "log {a} errors with trace ids",
    "upgrade the {a} client library",
    "fix timezone handling in {a}",
]

SQL_PROMPTS = [
    "Generate a SQL migration that adds a nullable column {c} to table {t} and backfills it",
    "Generate a SQL migration to add an index on {t}.{c}",
    "Generate a SQL migration that renames column {c} in table {t}",
]

ADHOC_ANALYSTS = [
    "What is the difference between DTI and DSTI?",
    "Explain the WIBOR to WIRON transition in two sentences.",
    "How do I calculate the LTV for a flat bought with a 20% down payment?",
    "Translate 'zdolność kredytowa' into English for a report.",
    "Write a polite email asking <PERSON_1> for a missing payslip.",
    "Which documents does a sole trader need for a cash loan?",
    "Summarise the main points of Recommendation S in five bullets.",
    "Draft an agenda for tomorrow's credit committee meeting.",
    "What does a BIK score of 520 mean?",
    "Rewrite this paragraph in plain English: the applicant's creditworthiness is assessed as adequate.",
    "Give me an Excel formula for the monthly instalment of an annuity loan.",
    "Is a civil-law contract treated as stable income?",
]
ADHOC_DEVELOPERS = [
    "Explain this regex: ^(?=.*\\d)(?=.*[a-z]).{8,}$",
    "How do I mock an async context manager in pytest?",
    "What is the difference between a list and a tuple in Python?",
    "Write a bash one-liner that counts lines in all .py files.",
    "Why does my Docker build cache miss on COPY?",
    "Suggest a name for a function that merges two sorted lists.",
    "How do I squash the last three commits in git?",
    "Explain Python's GIL in three sentences.",
    "Convert this curl command to httpx: curl -X POST -d '{}' <URL_1>",
    "What HTTP status should a rate-limited request return?",
    "How do I read a YAML file and keep comments in Python?",
    "Write a TypeScript type for a paginated API response.",
]
ADHOC_OPERATIONS = [
    "Draft a shift schedule announcement for next week.",
    "Summarise this incident ticket for the morning stand-up.",
    "Write a reminder about the quarterly access review.",
    "Summarise this incident ticket for the morning stand-up.",
    "Summarise this incident ticket for the morning stand-up.",
]


def pick(weighted: list[tuple[str, int]]) -> str:
    return rng.choices([w[0] for w in weighted], weights=[w[1] for w in weighted])[0]


def amount(lo: int, hi: int) -> str:
    return f"{rng.randrange(lo, hi, 5000):,}".replace(",", " ")


def loan_prompt() -> str:
    product, purpose, (lo, hi), (ylo, yhi) = rng.choice(PRODUCTS)
    income = rng.randrange(5200, 18500, 100)
    obligation = rng.choice(OBLIGATIONS).format(n=rng.randrange(300, 2400, 50))
    return (
        f"{pick(LOAN_INSTRUCTIONS)}:\n"
        f"Applicant: <PERSON_1>, PESEL <PESEL_1>, account <IBAN_1>.\n"
        f"Product: {product}, {amount(lo, hi)} PLN over {rng.randint(ylo, yhi)} years.\n"
        f"Purpose: {purpose.format(city=rng.choice(CITIES))}.\n"
        f"Net monthly income: {income} PLN ({rng.choice(EMPLOYMENT).format(y=rng.randint(2008, 2023))}).\n"
        f"Existing obligations: {obligation}.\n"
        f"Collateral: {rng.choice(COLLATERAL)}.\n"
        "Include DTI, key risks and a recommendation."
    )


def release_prompt() -> str:
    lines = []
    for _ in range(rng.randint(5, 9)):
        area = rng.choice(AREAS)
        lines.append(f"- {rng.choice(COMMIT_TYPES)}({area}): {rng.choice(CHANGES).format(a=area)}")
    return f"{pick(RELEASE_INSTRUCTIONS)}:\n" + "\n".join(lines) + "\nGroup them into Features, Fixes and Chores."


def clock(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def main() -> None:
    rows: list[dict] = []
    n = 0

    def add(**kw: object) -> None:
        nonlocal n
        n += 1
        rows.append({"id": f"seed-{n:05d}", **kw})

    for wd in range(WORKDAYS):
        # credit-analysts: loan application summaries, every workday, with regenerations
        for run in range(rng.randint(5, 6)):
            user = rng.choice(ANALYSTS)
            start = rng.randint(8 * 60 + 5, 11 * 60 + 40)
            session = f"{user}-w{wd}-{run}"
            text = loan_prompt()
            t = start
            for attempt in range(1 + rng.choice([0, 1, 1, 2, 2])):
                add(
                    user=user,
                    groups=["credit-analysts"],
                    workdays_ago=wd,
                    time=clock(t),
                    session=session,
                    text=text,
                    model="@local",
                    tokens_in=rng.randint(280, 380),
                    tokens_out=rng.randint(560, 760),
                    latency_ms=rng.randint(5200, 9400),
                    data_class="confidential",
                    kind="loan-summary" if attempt == 0 else "loan-summary-retry",
                )
                t += rng.randint(3, 5)
        # developers: release notes on release days (every 2-3 workdays → Mon/Thu-like rhythm)
        if wd % 5 in (0, 3):
            for run in range(rng.randint(2, 3)):
                user = rng.choice(DEVELOPERS)
                t = rng.randint(13 * 60, 16 * 60 + 30)
                session = f"{user}-rel-w{wd}-{run}"
                text = release_prompt()
                for _attempt in range(1 + rng.choice([0, 0, 1])):
                    add(
                        user=user,
                        groups=["developers"],
                        workdays_ago=wd,
                        time=clock(t),
                        session=session,
                        text=text,
                        model="@cloud",
                        tokens_in=rng.randint(220, 420),
                        tokens_out=rng.randint(280, 460),
                        latency_ms=rng.randint(2400, 4200),
                        data_class="internal",
                        kind="release-notes",
                    )
                    t += rng.randint(2, 4)
        # developers: SQL migrations by only three people (below k)
        if wd % 2 == 0:
            user = rng.choice(DEVELOPERS[:3])
            add(
                user=user,
                groups=["developers"],
                workdays_ago=wd,
                time=clock(rng.randint(10 * 60, 17 * 60)),
                session=f"{user}-sql-w{wd}",
                text=rng.choice(SQL_PROMPTS).format(
                    c=rng.choice(["status", "created_by", "region", "score"]),
                    t=rng.choice(["orders", "accounts", "invoices", "events"]),
                ),
                model="@cloud",
                tokens_in=rng.randint(40, 80),
                tokens_out=rng.randint(120, 260),
                latency_ms=rng.randint(1800, 3200),
                data_class="internal",
                kind="sql-migration",
            )
    # ad-hoc questions (noise), spread over the window
    for group, users, prompts, model, dc in (
        ("credit-analysts", ANALYSTS, ADHOC_ANALYSTS, "@local", "internal"),
        ("developers", DEVELOPERS, ADHOC_DEVELOPERS, "@cloud", "internal"),
        ("operations", OPERATIONS, ADHOC_OPERATIONS * 4, "@cloud", "internal"),
    ):
        for i, text in enumerate(prompts):
            user = rng.choice(users)
            add(
                user=user,
                groups=[group],
                days_ago=rng.randint(0, 27),
                time=clock(rng.randint(8 * 60, 17 * 60)),
                session=f"{user}-adhoc-{group}-{i}",
                text=text,
                model=model,
                tokens_in=rng.randint(20, 120),
                tokens_out=rng.randint(80, 300),
                latency_ms=rng.randint(900, 3000),
                data_class=dc,
                kind="adhoc",
            )
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} records to {OUT.name}")


if __name__ == "__main__":
    main()
