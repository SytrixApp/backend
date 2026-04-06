import { sql } from "drizzle-orm";
import {
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

// Custom bytea type: reads as Buffer, writes accepts Buffer | Uint8Array.
// `postgres-js` returns bytea as Buffer by default.
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

export type KdfParams = {
  algo: "argon2id";
  iterations: number;
  memory: number; // KiB
  parallelism: number;
};

export const users = pgTable(
  "users",
  {
    id: uuid().primaryKey().defaultRandom(),
    email: text().notNull(),
    // argon2id(serverSide) of the client-provided password_hash
    passwordHash: text("password_hash").notNull(),
    // Salt used by the CLIENT to derive its master_key (so the client can re-derive at login)
    kdfSalt: bytea("kdf_salt").notNull(),
    kdfParams: jsonb("kdf_params").$type<KdfParams>().notNull(),
    // data_key encrypted by master_key (AES-256-GCM), opaque to the server
    encryptedDataKey: bytea("encrypted_data_key").notNull(),
    // data_key encrypted by a key derived from the recovery code
    encryptedDataKeyRecovery: bytea("encrypted_data_key_recovery").notNull(),
    // sha256(recovery_code) — used to verify the recovery code at /auth/recover.
    // The recovery code is a high-entropy random value (32 bytes), so sha256 is sufficient.
    recoveryCodeHash: text("recovery_code_hash").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("users_email_unique").on(sql`lower(${t.email})`)],
);

export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: uuid().primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    // sha256 of the plaintext refresh token (hex)
    tokenHash: text("token_hash").notNull(),
    // Groups rotated tokens together so reuse of any ancestor can revoke the whole family.
    familyId: uuid("family_id").notNull(),
    deviceLabel: text("device_label"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    // When this token is rotated, we set replacedBy to the id of the new token.
    // Presenting a token whose replacedBy is set = reuse attempt → revoke the whole family.
    replacedBy: uuid("replaced_by"),
  },
  (t) => [
    index("refresh_tokens_user_id_idx").on(t.userId),
    uniqueIndex("refresh_tokens_token_hash_unique").on(t.tokenHash),
    index("refresh_tokens_family_id_idx").on(t.familyId),
  ],
);

export const vaultItems = pgTable(
  "vault_items",
  {
    id: uuid().primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    // Opaque blob: AES-256-GCM ciphertext (+ auth tag) of {issuer, label, secret, algo, digits, period, notes, icon}
    encryptedData: bytea("encrypted_data").notNull(),
    // 12-byte nonce for AES-GCM
    nonce: bytea("nonce").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (t) => [
    index("vault_items_user_updated_idx").on(t.userId, t.updatedAt),
    index("vault_items_user_deleted_idx").on(t.userId, t.deletedAt),
    // Enforce AES-GCM nonce uniqueness per user at DB level.
    // Nonce reuse with the same key breaks AES-GCM confidentiality completely.
    uniqueIndex("vault_items_user_nonce_unique").on(t.userId, t.nonce),
  ],
);

export const rateLimitBuckets = pgTable("rate_limit_buckets", {
  key: text().primaryKey(),
  count: integer().notNull().default(0),
  windowStart: timestamp("window_start", { withTimezone: true }).notNull().defaultNow(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type RefreshToken = typeof refreshTokens.$inferSelect;
export type VaultItem = typeof vaultItems.$inferSelect;
