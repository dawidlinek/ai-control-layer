# syntax=docker/dockerfile:1
# Rogatka Dashboard: multi-stage build, Next.js standalone output, non-root runtime.
#   docker build -t acl-panel panel/
# Normal build (no NEXT_PUBLIC_API_MOCKING): the MSW mock layer is not part of the bundle.

FROM node:22-alpine AS base
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    NEXT_TELEMETRY_DISABLED=1
# pnpm version comes from "packageManager" in package.json
RUN corepack enable
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store pnpm install --frozen-lockfile

FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN pnpm build

FROM node:22-alpine AS runner
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app
RUN addgroup -S -g 1001 rogatka && adduser -S -u 1001 -G rogatka rogatka
COPY --from=build --chown=rogatka:rogatka /app/.next/standalone ./
COPY --from=build --chown=rogatka:rogatka /app/.next/static ./.next/static
COPY --from=build --chown=rogatka:rogatka /app/public ./public
USER rogatka
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/signed-out || exit 1
CMD ["node", "server.js"]
