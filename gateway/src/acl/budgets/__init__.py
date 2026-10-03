"""Budgets and loop governance (concept §8). Phase 2D.

    ledger.py     in-memory hierarchical counters (org → group → user → agent → session), token bucket, windows
    breaker.py    circuit breakers per node (closed → open → half_open → closed)
    loops.py      per-session call / result / input history for SEC-LOOP-01
    estimate.py   pre-dispatch token / USD / GPU-second estimates
    nodes.py      which nodes and limits a request touches
    service.py    BudgetService: owns the above; flow hooks `on_commit` / `on_usage`; guard spend; admin views
    store.py      periodic flush to the DB (`db_models.py`) and reload on startup
    wiring.py     `install(app, settings)`: service `"budgets"`, flow hook, middleware, startup / shutdown

Controls (`acl.controls.budget`, `acl.controls.loops`) only read; every counter changes in the hooks.

Follow-ups (out of scope for 2D): a per-user / per-data-class scoped response cache (needs a chat-flow seam, see
`budgets.cache`); counting model-emitted tool
calls (egress) as `tool_call` points for the loop detector.
"""
