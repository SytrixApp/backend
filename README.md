# Sytrix Backend

End-to-end encrypted TOTP vault — backend API.

The server is a zero-knowledge storage and authentication layer. It never
sees TOTP secrets, master passwords, or data-encryption keys. All
cryptography happens on the client; the backend stores opaque ciphertext
blobs and enforces session/rate-limit policies.

- **Runtime**: Node 20+ (also runs under Bun)
- **Framework**: [Hono](https://hono.dev) — runtime-agnostic, deployable to
  Vercel serverless and standalone Node
- **Database**: PostgreSQL (Supabase-compatible, no Supabase lock-in)
- **ORM**: [Drizzle](https://orm.drizzle.team)

---

## Table of contents

1. [Security model](#security-model)
2. [Project layout](#project-layout)
3. [Local development](#local-development)
4. [Environment variables](#environment-variables)
5. [API reference](#api-reference)
6. [Client cryptography specification](#client-cryptography-specification)
7. [Deployment](#deployment)
8. [Testing](#testing)
9. [Roadmap](#roadmap)

---

## Security model

Sytrix uses a Bitwarden-style key hierarchy. Three distinct keys exist; the
server only ever touches one of them (and only as an opaque byte string).

| Key                  | Who derives it            | What it does                                        | Server sees? |
| -------------------- | ------------------------- | --------------------------------------------------- | ------------ |
| `master_key`         | Client, from the password | Encrypts the `data_key` (never transmitted)         | No           |
| `password_hash`      | Client, from the password | Authentication credential sent to the server       | Yes (re-hashed with argon2id) |
| `data_key`           | Client, random 32 bytes   | Encrypts every vault item (AES-256-GCM)            | No (only the ciphertext wrapping it) |
| `recovery_key`       | Client, derived from a recovery code | Alternate wrapping of `data_key` used for recovery | No           |

At rest, the server stores per-user:

- `password_hash` (argon2id of the client-provided password hash — defence in depth if the DB leaks)
- `kdf_salt`, `kdf_params` (so the client can re-derive `master_key` at login)
- `encrypted_data_key` (ciphertext — `data_key` encrypted under `master_key`)
- `encrypted_data_key_recovery` (ciphertext — `data_key` encrypted under `recovery_key`)
- `recovery_code_hash` (sha256 of the recovery code, used to authorise `/auth/recover`)

For each vault item, it stores only:

- `encrypted_data` (AES-256-GCM ciphertext + authentication tag)
- `nonce` (12 bytes, unique per item)
- `user_id`, timestamps, and a soft-delete flag

**Consequence**: losing both the password and the recovery code means the
data is unrecoverable. This is a deliberate trade-off for zero-knowledge.

### Additional hardening

- **Account enumeration resistance**: `/auth/prelogin` returns deterministic
  fake `kdf_salt`/`kdf_params` for unknown emails (derived via HMAC under
  the server secret), so an attacker cannot distinguish known from unknown
  accounts by timing or response shape.
- **Timing-uniform login**: login always runs an argon2 verification (using
  a throwaway dummy hash for unknown users) so response time does not leak
  account existence.
- **Refresh token reuse detection**: refresh tokens belong to a family. On
  rotation, the old token is marked `replaced_by` the new one. Presenting
  an already-rotated token revokes **every** token in the family — the
  industry-standard OAuth 2.0 BCP mitigation against stolen refresh tokens.
- **Rate limiting**: login (per IP + per email), register, refresh and
  recover are all rate-limited via a Postgres-backed fixed-window bucket.

---

## Project layout

```
backend/
├── src/
│   ├── index.ts              # Node self-host entry
│   ├── app.ts                # Hono app construction (routes + middlewares)
│   ├── env.ts                # Zod-validated env loader
│   ├── db/
│   │   ├── client.ts         # postgres-js + drizzle
│   │   ├── schema.ts         # Drizzle table definitions
│   │   └── migrate.ts        # Idempotent SQL file runner
│   ├── services/             # Business logic (auth, token, vault)
│   ├── routes/               # HTTP handlers with Zod validators
│   ├── middleware/           # Auth, rate limiting, error handling
│   └── lib/                  # crypto, errors
├── api/
│   └── index.ts              # Vercel serverless entry
├── drizzle/migrations/       # Hand-authored SQL, applied in lexical order
├── test/                     # Vitest integration tests
├── Dockerfile                # Multi-stage self-host image
├── docker-compose.yml        # Local dev: postgres + backend
├── vercel.json               # Rewrites to api/index.ts
└── package.json
```

---

## Local development

### Prerequisites

- Node 20.6+ (22 recommended)
- pnpm (`corepack enable`)
- A reachable PostgreSQL 15+ instance (local or Supabase)

### Setup

```bash
pnpm install
cp .env.example .env
# Edit .env — set DATABASE_URL and JWT_SECRET (≥ 32 chars)
pnpm db:migrate
pnpm dev
```

The API is served on `http://localhost:3000`. Smoke-test with:

```bash
curl http://localhost:3000/health
# → {"status":"ok","db":"ok"}
```

### Scripts

| Command                | What it does                                         |
| ---------------------- | ---------------------------------------------------- |
| `pnpm dev`             | Run with tsx watcher                                 |
| `pnpm build`           | Compile TypeScript to `dist/`                        |
| `pnpm start`           | Run the compiled output                              |
| `pnpm typecheck`       | `tsc --noEmit`                                       |
| `pnpm db:migrate`      | Apply pending migrations (dev, uses tsx)             |
| `pnpm db:migrate:prod` | Apply migrations against the compiled `dist/`       |
| `pnpm test`            | Run the Vitest integration suite                     |

---

## Environment variables

| Name           | Required | Description                                                                                                                    |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `DATABASE_URL` | yes      | PostgreSQL connection string. For Supabase, use the **Transaction pooler** URL (`aws-0-<region>.pooler.supabase.com:6543`).    |
| `JWT_SECRET`   | yes      | HS256 signing key for access tokens. **Minimum 32 characters.** Generate with `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`. |
| `NODE_ENV`     | no       | `development` (default), `production`, or `test`.                                                                              |
| `PORT`         | no       | Self-host listen port (default `3000`). Ignored on Vercel.                                                                     |

---

## API reference

All endpoints live under `/api/v1`. Content type is `application/json`.
Errors come back as `{ "error": { "code": "<string>", "message": "<string>" } }`
with a matching HTTP status.

Binary payloads (salts, ciphertexts, nonces) are **base64** encoded in
both directions.

### Auth

#### `POST /auth/register`

Create a new account.

```json
{
  "email": "user@example.com",
  "passwordHash": "<client-derived password hash, base64 or base64url>",
  "kdfSalt": "<16 bytes, base64>",
  "kdfParams": { "algo": "argon2id", "iterations": 3, "memory": 65536, "parallelism": 1 },
  "encryptedDataKey": "<AES-GCM(data_key) under master_key, base64>",
  "encryptedDataKeyRecovery": "<AES-GCM(data_key) under recovery_key, base64>",
  "recoveryCode": "<plaintext recovery code, 16-256 chars>"
}
```

Response `201`:
```json
{ "userId": "uuid" }
```

#### `POST /auth/prelogin`

Fetch the KDF parameters needed to derive the login password hash.

```json
{ "email": "user@example.com" }
```

Response `200`:
```json
{ "kdfSalt": "<base64>", "kdfParams": { "algo": "argon2id", "iterations": 3, "memory": 65536, "parallelism": 1 } }
```

For unknown emails, the response is identical in shape with deterministic
fake values — do not rely on this to check account existence.

#### `POST /auth/login`

```json
{
  "email": "user@example.com",
  "passwordHash": "<same derivation as register>",
  "deviceLabel": "iPhone 15"
}
```

Response `200`:
```json
{
  "accessToken": "<JWT, ~15 min>",
  "refreshToken": "<opaque, 60 day sliding>",
  "refreshExpiresAt": "2025-06-04T12:00:00.000Z",
  "encryptedDataKey": "<base64>",
  "userId": "uuid"
}
```

#### `POST /auth/refresh`

```json
{ "refreshToken": "<current refresh token>" }
```

Response `200` contains a new `accessToken` and a freshly rotated
`refreshToken`. The presented token is invalidated. **Replaying it will
revoke the entire session family.**

#### `POST /auth/logout`

```json
{ "refreshToken": "<token to revoke>" }
```

#### `POST /auth/logout-all`

`Authorization: Bearer <access_token>`. Revokes every refresh token of the
current user.

#### `POST /auth/recover`

Unauthenticated. Rotates the password, KDF, and both data-key wrappings
using the recovery code as the authorisation factor.

```json
{
  "email": "user@example.com",
  "recoveryCode": "<the original recovery code>",
  "newPasswordHash": "...",
  "newKdfSalt": "...",
  "newKdfParams": { ... },
  "newEncryptedDataKey": "...",
  "newEncryptedDataKeyRecovery": "...",
  "newRecoveryCode": "<freshly generated, shown once to the user>"
}
```

All existing sessions are revoked.

#### `POST /auth/change-password`

`Authorization: Bearer <access_token>`.

```json
{
  "currentPasswordHash": "...",
  "newPasswordHash": "...",
  "newKdfSalt": "...",
  "newKdfParams": { ... },
  "newEncryptedDataKey": "..."
}
```

The recovery code is unchanged (the underlying `data_key` hasn't
changed). All sessions are revoked.

### Vault

All `/vault/*` endpoints require `Authorization: Bearer <access_token>`.

#### `GET /vault/items?since=<ISO-8601>`

Without `since`: returns all non-deleted items.
With `since`: returns every item whose `updatedAt > since`, including
soft-deleted ones so clients can propagate deletions.

Response `200`:
```json
{
  "items": [
    {
      "id": "uuid",
      "encryptedData": "<base64>",
      "nonce": "<12 bytes base64>",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-01-01T00:00:00.000Z",
      "deletedAt": null
    }
  ]
}
```

#### `POST /vault/items`

```json
{ "encryptedData": "<base64>", "nonce": "<12-byte base64>" }
```

#### `PATCH /vault/items/:id`

Last-write-wins by `updatedAt`. Body identical to `POST`.

#### `DELETE /vault/items/:id`

Soft delete. The row remains with `deletedAt` set so incremental sync can
see the tombstone; a future job can hard-delete after N days.

### Account

All require auth.

- `GET /account/me` — user profile (id, email, timestamps)
- `GET /account/sessions` — list active refresh tokens
- `DELETE /account/sessions/:id` — revoke a specific session

### Health

- `GET /health` — liveness + DB connectivity check

---

## Client cryptography specification

This is the **contract** the Sytrix client must follow. The server will
reject anything that doesn't round-trip through a compliant implementation.

### 1. Key derivation (Argon2id)

At registration, generate a random 16-byte `kdf_salt`.

Recommended parameters (what the server accepts, range-validated):

```
algo:        argon2id
iterations:  3           (t-cost)
memory:      65536 KiB   (64 MiB)
parallelism: 1
```

Clients may increase these values; older accounts keep their original
parameters (they are stored per-user and returned by `/auth/prelogin`).

Derive:

```
master_key = Argon2id(password, salt=kdf_salt, params)   // 32 bytes
```

### 2. Password hash sent to the server

Derive a separate credential from `master_key` using HKDF-SHA256. Using
HKDF (cheap) on top of Argon2id (expensive) means the server-visible value
cannot be used to recompute `master_key`:

```
password_hash = HKDF-SHA256(
  ikm  = master_key,
  salt = empty,
  info = "sytrix/auth/password-hash/v1",
  L    = 32
)
```

Send `password_hash` base64-encoded. The server re-hashes it with its own
server-side argon2id before storing, so a DB leak still requires cracking
argon2 to test credentials.

### 3. Data key

Generate a fresh random key on registration:

```
data_key = random(32)   // cryptographically secure RNG
```

This is the only key that ever touches vault items. Rotating passwords
does **not** rotate `data_key` — only its wrapping changes — so old items
remain decryptable.

### 4. Wrapping the data key under the master key

```
wrap_key_master = HKDF-SHA256(master_key, info="sytrix/wrap/master/v1", L=32)
nonce_m         = random(12)
ct_m            = AES-256-GCM(key=wrap_key_master, nonce=nonce_m, plaintext=data_key, aad="sytrix-wrap-master")
encrypted_data_key = nonce_m || ct_m         // concatenation, base64-encoded
```

### 5. Recovery code

Generate a high-entropy recovery code — recommended 32 random bytes,
encoded as base32 for human readability. Display it **once** to the user
at registration.

```
recovery_key = HKDF-SHA256(
  ikm  = utf8(recovery_code),
  salt = empty,
  info = "sytrix/recovery/v1",
  L    = 32
)

wrap_key_recovery = recovery_key
nonce_r           = random(12)
ct_r              = AES-256-GCM(key=wrap_key_recovery, nonce=nonce_r, plaintext=data_key, aad="sytrix-wrap-recovery")
encrypted_data_key_recovery = nonce_r || ct_r
```

Send the **plaintext recovery code** in `POST /auth/register`. The server
stores only `sha256(recovery_code)` and uses it to authorise
`POST /auth/recover`. (The recovery code is a high-entropy secret, so a
plain sha256 is sufficient — it cannot be brute-forced.)

### 6. Vault item encryption

For each item, serialise the cleartext as UTF-8 JSON with a stable shape:

```json
{
  "version": 1,
  "issuer": "GitHub",
  "label": "alice@github.com",
  "secret": "JBSWY3DPEHPK3PXP",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "notes": "",
  "icon": null
}
```

Then encrypt:

```
nonce       = random(12)                          // unique per item, never reused
ciphertext  = AES-256-GCM(
  key        = data_key,
  nonce      = nonce,
  plaintext  = utf8(JSON.stringify(item)),
  aad        = utf8(item_id || "new")             // bind to the item id once assigned
)

// Send to the server:
POST /vault/items
{ "encryptedData": base64(ciphertext), "nonce": base64(nonce) }
```

**Important**: never reuse a nonce with the same `data_key`. Generate a
fresh random 12-byte nonce for every create **and** every update.

### 7. Login flow

```
1. POST /auth/prelogin { email }
   → { kdfSalt, kdfParams }
2. master_key   = Argon2id(password, kdfSalt, kdfParams)
3. password_hash = HKDF(master_key, "sytrix/auth/password-hash/v1")
4. POST /auth/login { email, passwordHash, deviceLabel }
   → { accessToken, refreshToken, encryptedDataKey }
5. wrap_key_master = HKDF(master_key, "sytrix/wrap/master/v1")
6. data_key = AES-256-GCM-decrypt(wrap_key_master, encryptedDataKey, aad="sytrix-wrap-master")
```

Store `accessToken` in memory and `refreshToken` in a secure, persistent
store (Keychain on iOS, Keystore on Android, an encrypted file or IndexedDB
wrapped by WebAuthn on web).

### 8. Sync strategy

- On app start: `GET /vault/items` → decrypt all items into memory.
- On resume / pull-to-refresh: `GET /vault/items?since=<lastSyncAt>` →
  merge by id, treating rows with `deletedAt !== null` as tombstones.
- On mutation: push immediately via `POST` / `PATCH` / `DELETE`, then
  re-sync on next opportunity.

Conflict resolution is last-write-wins via the server's `updatedAt`.

---

## Deployment

### Vercel

```bash
vercel link
vercel env add DATABASE_URL        # Supabase transaction pooler URL
vercel env add JWT_SECRET          # ≥ 32 chars
vercel deploy
```

`vercel.json` rewrites every incoming request to `api/index.ts`, which
builds the same Hono app used in self-host mode.

Migrations are **not** run during the Vercel build (doing so would re-apply
on every commit, occasionally mid-deploy). Run them from CI or locally
before shipping:

```bash
pnpm build
pnpm db:migrate:prod
```

### Self-host (Docker)

```bash
# Dev environment with an ephemeral local Postgres:
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))") \
  docker compose up --build

# Production: point DATABASE_URL at your managed Postgres
docker build -t sytrix-backend .
docker run -d \
  -e DATABASE_URL=postgres://... \
  -e JWT_SECRET=... \
  -p 3000:3000 \
  sytrix-backend
```

The container automatically runs pending migrations before starting the
server.

---

## Testing

```bash
pnpm test
```

The suite is **integration-level**: it spins up the real Hono app against
the real `DATABASE_URL` and truncates tables between tests. **Always point
it at a dedicated test database, never at production.**

Coverage includes:

- Register, login, duplicate detection, wrong-password rejection
- Prelogin enumeration guard
- Refresh token rotation with reuse detection
- Recovery happy path and invalid-code rejection
- Vault CRUD, incremental sync (including tombstones), multi-user isolation
- Request validation (base64 shape, nonce length)

---

## Roadmap

Explicitly out of scope for the MVP, reserved for v2:

- Account-level second factor (WebAuthn / passkeys)
- Item sharing between users
- Server-side folders / tags (they can already live inside the encrypted
  blob for now)
- Real-time sync (WebSocket / SSE)
- Encrypted import/export flows
- User-visible audit log
