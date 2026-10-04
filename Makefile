# Thin wrapper: every target runs scripts/dev.py (works on Windows without make:
#   uv run python scripts/dev.py <target>)
DEV := uv run python scripts/dev.py
TARGETS := env up down logs ps demo seed test test-live e2e bench mutation adaptive replay lint fmt contracts

.PHONY: $(TARGETS)
$(TARGETS):
	@$(DEV) $@ $(ARGS)
