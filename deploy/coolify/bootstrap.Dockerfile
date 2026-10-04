# Init image for deploy/compose.coolify.yml (build context: repository root). Carries the repo's default policy and
# insights seed so the stack needs no bind mounts of repository files (Coolify does not keep the checkout around).
FROM postgres:17-alpine
COPY policy /defaults/policy
COPY deploy/seed/insights /defaults/insights
COPY deploy/coolify/bootstrap.sh /bootstrap.sh
ENTRYPOINT ["/bin/sh", "/bootstrap.sh"]
