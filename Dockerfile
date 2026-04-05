ARG NODE_VERSION=20-alpine

# --- Builder ---
FROM node:${NODE_VERSION} AS builder
WORKDIR /app

# argon2 native build deps
RUN apk add --no-cache python3 make g++

RUN corepack enable

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile || pnpm install

COPY tsconfig.json tsconfig.build.json drizzle.config.ts ./
COPY src ./src
COPY drizzle ./drizzle

RUN pnpm build

# --- Runner ---
FROM node:${NODE_VERSION} AS runner
WORKDIR /app
ENV NODE_ENV=production

RUN apk add --no-cache tini \
 && addgroup -S app && adduser -S app -G app

RUN corepack enable

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --prod --frozen-lockfile || pnpm install --prod

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/drizzle ./drizzle

USER app

EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sh", "-c", "node --env-file-if-exists=.env dist/db/migrate.js && node --env-file-if-exists=.env dist/index.js"]
