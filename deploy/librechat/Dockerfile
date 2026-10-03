# LibreChat with two DEMO-ONLY adjustments for a plain-HTTP, localhost Keycloak (see deploy/README-clients.md):
#   1. OPENID_ALLOW_INSECURE_HTTP=true lets openid-client (v6) talk to an http:// issuer. LibreChat v0.8.8 offers
#      no switch for it (HTTPS is mandatory), so the discovery call is patched at build time. The build fails if
#      the patch point is not found, so an upstream change cannot silently drop it. Production: HTTPS issuer, no patch.
#   2. oidc-forward.cjs makes `http://localhost:<port>` (the issuer Keycloak puts into tokens) reachable from
#      inside this container by forwarding it to the Keycloak container.
FROM registry.librechat.ai/librechat-ai/librechat:v0.8.8

USER root
COPY patch-openid.cjs /tmp/patch-openid.cjs
RUN node /tmp/patch-openid.cjs /app/api/strategies/openidStrategy.js && rm /tmp/patch-openid.cjs
COPY oidc-forward.cjs /opt/oidc-forward.cjs
COPY entrypoint.sh /librechat-entrypoint.sh
RUN chmod 0555 /opt/oidc-forward.cjs /librechat-entrypoint.sh
USER node
