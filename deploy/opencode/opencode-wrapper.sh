#!/bin/sh
# `opencode` inside the locked container: always the pinned CLI, never with switches that bypass the guard.
# - OPENCODE_PURE skips every external plugin; OPENCODE_CONFIG* / OPENCODE_PERMISSION add config sources; the
#   experimental flags enable tool paths this guard has not been verified against: all OPENCODE_* from the caller
#   are dropped, then the safe defaults below are set.
# - A cloned repository may ship its own opencode.json / .opencode/ (extra MCP servers, plugins, agents):
#   OPENCODE_DISABLE_PROJECT_CONFIG ignores them. The managed config is the only repo-independent policy source.
set -eu
for var in $(env | sed -n 's/^\(OPENCODE_[A-Z0-9_]*\)=.*/\1/p'); do
  unset "$var"
done
export OPENCODE_DISABLE_PROJECT_CONFIG=1
export OPENCODE_DISABLE_AUTOUPDATE=1
export OPENCODE_DISABLE_LSP_DOWNLOAD=1
export OPENCODE_DISABLE_MODELS_FETCH=1   # the model list comes from the managed config, not models.dev
exec /opt/opencode-cli/node_modules/.bin/opencode "$@"
