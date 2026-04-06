import { createHmac, randomBytes } from "node:crypto";
import { eq, sql as dsql } from "drizzle-orm";
import { db } from "../db/client.js";
import { users, type KdfParams } from "../db/schema.js";
import { hashPasswordHash, verifyPasswordHash, safeEqual, sha256Hex, hmacSha256Hex } from "../lib/crypto.js";
import { badRequest, conflict, unauthorized } from "../lib/errors.js";
import {
  issueAccessToken,
  issueRefreshToken,
  revokeAllRefreshTokens,
  type IssuedRefresh,
} from "./token.service.js";
import { loadEnv } from "../env.js";

const env = loadEnv();

// Server-side HMAC secret for recovery code hashing.
// Falls back to JWT_SECRET so existing deployments work without a new env var.
// Setting RECOVERY_HMAC_SECRET to a distinct value is strongly recommended.
function recoveryHmacSecret(): string {
  return env.RECOVERY_HMAC_SECRET ?? env.JWT_SECRET;
}

function hashRecoveryCode(code: string): string {
  return hmacSha256Hex(recoveryHmacSecret(), code);
}

export type RegisterInput = {
  email: string;
  passwordHash: string;
  kdfSalt: Buffer;
  kdfParams: KdfParams;
  encryptedDataKey: Buffer;
  encryptedDataKeyRecovery: Buffer;
  recoveryCode: string; // plaintext — hashed server-side and never stored in clear
};

export async function register(input: RegisterInput): Promise<{ userId: string }> {
  const email = input.email.trim().toLowerCase();

  const [existing] = await db
    .select({ id: users.id })
    .from(users)
    .where(dsql`lower(${users.email}) = ${email}`)
    .limit(1);
  if (existing) throw conflict("An account with this email already exists");

  const serverHash = await hashPasswordHash(input.passwordHash);

  const [row] = await db
    .insert(users)
    .values({
      email,
      passwordHash: serverHash,
      kdfSalt: input.kdfSalt,
      kdfParams: input.kdfParams,
      encryptedDataKey: input.encryptedDataKey,
      encryptedDataKeyRecovery: input.encryptedDataKeyRecovery,
      recoveryCodeHash: hashRecoveryCode(input.recoveryCode),
    })
    .returning({ id: users.id });

  return { userId: row!.id };
}

/**
 * Return the KDF salt and params for a given email so the client can derive its master_key
 * locally before sending password_hash to /login.
 *
 * To avoid account enumeration, we return deterministic fake values for unknown emails — same
 * email always yields the same fake salt/params (HMAC of the email under a server secret).
 * Attackers cannot distinguish "email exists" from "email doesn't exist" by this endpoint alone.
 */
export async function prelogin(emailRaw: string): Promise<{ kdfSalt: Buffer; kdfParams: KdfParams }> {
  const email = emailRaw.trim().toLowerCase();

  // Always compute the fake salt BEFORE the DB query so both code paths
  // (email found vs. not found) perform the same amount of work, keeping
  // response timing constant and preventing account enumeration via timing.
  const fakeSalt = Buffer.from(
    createHmac("sha256", env.JWT_SECRET).update(`prelogin-salt:${email}`).digest().subarray(0, 16),
  );
  const fakeParams: KdfParams = { algo: "argon2id", iterations: 3, memory: 65536, parallelism: 1 };

  const [user] = await db
    .select({ kdfSalt: users.kdfSalt, kdfParams: users.kdfParams })
    .from(users)
    .where(dsql`lower(${users.email}) = ${email}`)
    .limit(1);

  if (user) return { kdfSalt: user.kdfSalt, kdfParams: user.kdfParams };
  return { kdfSalt: fakeSalt, kdfParams: fakeParams };
}

export type LoginResult = {
  accessToken: string;
  refreshToken: string;
  refreshExpiresAt: Date;
  encryptedDataKey: Buffer;
  userId: string;
};

export async function login(emailRaw: string, passwordHash: string, deviceLabel?: string): Promise<LoginResult> {
  const email = emailRaw.trim().toLowerCase();
  const [user] = await db
    .select()
    .from(users)
    .where(dsql`lower(${users.email}) = ${email}`)
    .limit(1);

  // Do an argon2 verify even if the user doesn't exist to keep timing roughly uniform.
  const storedHash = user?.passwordHash ?? DUMMY_ARGON2_HASH;
  const ok = await verifyPasswordHash(storedHash, passwordHash);
  if (!user || !ok) throw unauthorized("Invalid email or password");

  const accessToken = await issueAccessToken(user.id);
  const refresh: IssuedRefresh = await issueRefreshToken(user.id, deviceLabel);
  return {
    accessToken,
    refreshToken: refresh.token,
    refreshExpiresAt: refresh.expiresAt,
    encryptedDataKey: user.encryptedDataKey,
    userId: user.id,
  };
}

// Precomputed dummy hash of a random value — used to keep login timing constant.
// A fresh random input means a single unverifiable hash per boot; good enough for our purpose.
const DUMMY_ARGON2_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$" +
  randomBytes(16).toString("base64").replace(/=+$/, "") +
  "$" +
  randomBytes(32).toString("base64").replace(/=+$/, "");

export type RecoverInput = {
  email: string;
  recoveryCode: string; // plaintext — client just recovered with it and is now rotating keys
  newPasswordHash: string;
  newKdfSalt: Buffer;
  newKdfParams: KdfParams;
  newEncryptedDataKey: Buffer;
  newEncryptedDataKeyRecovery: Buffer;
  newRecoveryCode: string; // freshly generated client-side; we hash and store
};

/**
 * Recovery flow:
 * - Client uses the recovery code to decrypt `encrypted_data_key_recovery` locally and retrieve
 *   the original `data_key`. (Happens entirely client-side.)
 * - Client re-encrypts `data_key` under a new password-derived key and a freshly generated
 *   recovery code, then calls this endpoint.
 * - Server verifies the presented recovery code against the stored sha256 hash before rotating.
 */
export async function recover(input: RecoverInput): Promise<{ userId: string }> {
  const email = input.email.trim().toLowerCase();
  const [user] = await db
    .select()
    .from(users)
    .where(dsql`lower(${users.email}) = ${email}`)
    .limit(1);

  // Compute the presented hash before the early return so timing is uniform
  // whether or not the email exists (prevents account enumeration via timing).
  const presentedHash = hashRecoveryCode(input.recoveryCode);

  if (!user || !safeEqual(presentedHash, user.recoveryCodeHash)) {
    throw unauthorized("Invalid email or recovery code");
  }

  const newServerHash = await hashPasswordHash(input.newPasswordHash);

  await db
    .update(users)
    .set({
      passwordHash: newServerHash,
      kdfSalt: input.newKdfSalt,
      kdfParams: input.newKdfParams,
      encryptedDataKey: input.newEncryptedDataKey,
      encryptedDataKeyRecovery: input.newEncryptedDataKeyRecovery,
      recoveryCodeHash: hashRecoveryCode(input.newRecoveryCode),
      updatedAt: new Date(),
    })
    .where(eq(users.id, user.id));

  // Revoke all sessions so old devices must re-login with the new password.
  await revokeAllRefreshTokens(user.id);

  return { userId: user.id };
}

export type ChangePasswordInput = {
  userId: string;
  currentPasswordHash: string;
  newPasswordHash: string;
  newKdfSalt: Buffer;
  newKdfParams: KdfParams;
  // data_key re-encrypted under the NEW password-derived key. recovery ciphertext is unchanged.
  newEncryptedDataKey: Buffer;
};

export async function changePassword(input: ChangePasswordInput): Promise<void> {
  const [user] = await db.select().from(users).where(eq(users.id, input.userId)).limit(1);
  if (!user) throw unauthorized();

  const ok = await verifyPasswordHash(user.passwordHash, input.currentPasswordHash);
  if (!ok) throw unauthorized("Current password is incorrect");

  const newServerHash = await hashPasswordHash(input.newPasswordHash);
  await db
    .update(users)
    .set({
      passwordHash: newServerHash,
      kdfSalt: input.newKdfSalt,
      kdfParams: input.newKdfParams,
      encryptedDataKey: input.newEncryptedDataKey,
      updatedAt: new Date(),
    })
    .where(eq(users.id, input.userId));

  // Revoke all sessions — all devices must re-login with the new password.
  await revokeAllRefreshTokens(input.userId);
}

export function validateEmail(email: string): string {
  const trimmed = email.trim();
  // Minimal sanity check — don't try to validate RFC 5321 fully.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    throw badRequest("Invalid email");
  }
  return trimmed;
}
