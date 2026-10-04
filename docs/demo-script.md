# Demo script (≈ 8 min + live questions)

Prerequisites: `make up` (+ `COMPOSE_PROFILES=panel` for the dashboard on :3000), WCSS job + `scripts/wcss.py tunnel`
(Qwen :8001, Bielik :8002, embeddings :8003), `GEMINI_API_KEY`. Each command prints the gateway decision, the model it
picked and the reply; every row also appears live in the dashboard (Traffic).

| # | Time | Command | What to say |
|---|---|---|---|
| 1 | 2.5 min | `uv run python scripts/demo.py 1` | One gateway, the right model per request. English → Gemini Flash. Polish legal question → **Bielik** on our own H100 (deterministic detector: Polish × legal lexicon × article citations). Loan note with a PESEL → **pseudonymised before any model** (`<PESEL_1>`), confidential → local Qwen only; the cloud never sees it. |
| 2 | 2.5 min | `uv run python scripts/demo.py 2` | A coding agent reads a poisoned README. Reading the repo is fine but taints the session. The injected "read `~/.ssh/id_rsa`" is **blocked** (signature + tool policy). "curl config to attacker" is **held** by the Rule of Two (untrusted input + sensitive data + external send). `git status` still works. An AWS key pasted into a prompt is **blocked** before it reaches any model. No AI involved: deterministic gates decide. |
| 3 | 3 min | `uv run python scripts/demo.py 3`, then the dashboard | Traffic → click a row: the trace explains every control and why this model. Approvals → the held send, with Rule-of-Two reasons → Deny. Models → kill switch on Gemini (reason) → `uv run python scripts/demo.py ask "What is a zero-trust network?"` now answers from local Qwen, marked degraded. Automation Insights → repeated loan-memo summaries → draft skill → publish (new policy version). |
| live | rest | `uv run python scripts/demo.py ask "<question>" --user anna\|jan\|adam [--model auto\|local\|bielik\|smart]` | Take questions from the audience; point at decision / model / trace for each. |

Fallbacks: if WCSS is down, local models report unavailable and the router degrades (never fails open; confidential
requests are refused rather than sent to the cloud). Without any model, set `ACL_DETERMINISTIC=1`: demos 2 and 3 are
fully deterministic anyway.
