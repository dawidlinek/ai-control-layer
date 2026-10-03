#!/bin/sh
# Start-up checks for the locked OpenCode container. Fails closed: if the lockdown is not in place, do not run.
set -eu

CFG=/etc/opencode/opencode.json
GUARD=/opt/opencode-guard/dist/index.js

die() { echo "opencode-lockdown: $1" >&2; exit 78; }

[ "$(id -u)" != "0" ] || die "refusing to run as root"
[ -r "$CFG" ] || die "managed config $CFG is missing"
[ ! -w "$CFG" ] || die "managed config $CFG is writable by this user"
[ ! -w /etc/opencode ] || die "/etc/opencode is writable by this user"
[ -f "$GUARD" ] || die "guard plugin $GUARD is missing"
[ ! -w "$GUARD" ] || die "guard plugin is writable by this user"
[ -n "${ACL_GATEWAY_URL:-}" ] || die "ACL_GATEWAY_URL is not set"
[ -n "${ACL_OIDC_ISSUER:-}" ] || die "ACL_OIDC_ISSUER is not set"

mkdir -p "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME"
if [ ! -e /workspace/.seeded ]; then
  cp -a /opt/demo-seed/. /workspace/
  : > /workspace/.seeded
fi

exec "$@"
