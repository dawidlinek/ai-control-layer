# Automation Insights demo history

`history.jsonl` is synthetic, already-redacted usage history for scenario 14 (concept §14), generated
deterministically by `generate.py` (`uv run python deploy/seed/insights/generate.py`).

- Read directly by the insights miner when `ACL_INSIGHTS_SEED_DIR` points here (compose mounts it at
  `/seed/insights`). It is **never written to the audit log**: the hash chain records real traffic only.
- Personal data appears only as pseudonyms (`<PERSON_1>`, `<PESEL_1>`, `<IBAN_1>`), as the gateway stores it.
- Dates are relative (`workdays_ago`, `days_ago`) so the history is always recent; models are roles (`@local`,
  `@cloud`, `@large`) resolved against the current policy's routing targets and priced with its model pricing.
- `kind` is ground truth for tests (loan-summary, release-notes, sql-migration, adhoc); the miner ignores it.

Stories: credit-analysts summarise loan applications every workday (~40 min/day, 6 people, confidential, local
model); developers write release notes twice a week on the cloud model; 3 developers generate SQL migrations (a real
cluster that management does not see because k = 5); ad-hoc questions are noise; operations has not opted in.
