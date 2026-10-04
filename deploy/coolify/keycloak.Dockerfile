# Keycloak for deploy/compose.coolify.yml (build context: deploy/). The realm file is baked in because Coolify does not
# keep the repository checkout, so a bind mount of ./keycloak/realm-export.json would mount an empty directory.
FROM quay.io/keycloak/keycloak:26.3
COPY keycloak/realm-export.json /opt/keycloak/data/import/realm-export.json
