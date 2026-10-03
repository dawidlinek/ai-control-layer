#!/bin/sh
# Derives LibreChat's JWT / credential-encryption / session secrets from ONE generated secret
# (LIBRECHAT_APP_SECRET in .env), so `make env` only has to generate a single value, and starts the
# localhost->Keycloak forwarder (see oidc-forward.cjs).
set -eu
: "${LIBRECHAT_APP_SECRET:?LIBRECHAT_APP_SECRET is not set (run make env)}"

derive() { printf '%s:%s' "$1" "$LIBRECHAT_APP_SECRET" | sha256sum | cut -d' ' -f1; }

JWT_SECRET="$(derive jwt)"
JWT_REFRESH_SECRET="$(derive jwt-refresh)"
CREDS_KEY="$(derive creds-key)"                 # 32 bytes, hex
CREDS_IV="$(derive creds-iv | cut -c1-32)"      # 16 bytes, hex
OPENID_SESSION_SECRET="$(derive openid-session)"
export JWT_SECRET JWT_REFRESH_SECRET CREDS_KEY CREDS_IV OPENID_SESSION_SECRET

if [ -n "${OIDC_LOCAL_PORT:-}" ]; then
  node /opt/oidc-forward.cjs &
fi

exec "$@"
