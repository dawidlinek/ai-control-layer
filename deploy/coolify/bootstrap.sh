#!/bin/sh
# One-shot init for the Coolify stack (deploy/compose.coolify.yml). Idempotent; safe on every redeploy.
#   1. policy volume: seeded from the repo's policy/ ONLY when empty, so edits made in the panel survive redeploys
#      (to reset to the repo version: delete the volume in Coolify and redeploy).
#   2. insights seed volume: always replaced with the repo's deploy/seed/insights (read-only demo history).
#   3. Keycloak database: created in the shared Postgres if missing.
set -eu

if [ -z "$(ls -A /policy 2>/dev/null)" ]; then
  echo "bootstrap: seeding policy volume from the repo"
  cp -R /defaults/policy/. /policy/
else
  echo "bootstrap: policy volume already populated, leaving it alone"
fi
chown -R 10001:10001 /policy   # the gateway runs as uid 10001 and is the policy writer

rm -rf /seed-insights/* 2>/dev/null || true
cp -R /defaults/insights/. /seed-insights/
echo "bootstrap: insights seed refreshed"

export PGHOST=postgres PGUSER=acl PGDATABASE=acl
: "${PGPASSWORD:?POSTGRES_PASSWORD is not set}"
i=0
until pg_isready -q; do
  i=$((i + 1)); [ "$i" -ge 60 ] && { echo "bootstrap: postgres not ready" >&2; exit 1; }
  sleep 2
done
if [ "$(psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'keycloak'")" != "1" ]; then
  psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE keycloak OWNER acl"
  echo "bootstrap: created database keycloak"
fi
echo "bootstrap: done"
