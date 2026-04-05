import { SignJWT, jwtVerify } from "jose";
import { and, eq, isNull } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import { db } from "../db/client.js";
import { refreshTokens } from "../db/schema.js";
import { loadEnv } from "../env.js";
import { randomBase64Url, sha256Hex } from "../lib/crypto.js";
import { unauthorized } from "../lib/errors.js";

const env = loadEnv();
const JWT_KEY = new TextEncoder().encode(env.JWT_SECRET);

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 min
const REFRESH_TOKEN_TTL_MS = 60 * 24 * 60 * 60 * 1000; // 60 days

export type AccessTokenPayload = {
  sub: string;
  jti: string;
  exp: number;
};

export async function issueAccessToken(userId: string): Promise<string> {
  const jti = randomUUID();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: userId, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TOKEN_TTL_SECONDS)
    .setSubject(userId)
    .sign(JWT_KEY);
}

export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
  try {
    const { payload } = await jwtVerify(token, JWT_KEY, { algorithms: ["HS256"] });
    if (!payload.sub || typeof payload.sub !== "string") throw new Error("missing sub");
    return { sub: payload.sub, jti: String(payload.jti ?? ""), exp: payload.exp ?? 0 };
  } catch {
    throw unauthorized("Invalid or expired access token");
  }
}

export type IssuedRefresh = { token: string; id: string; familyId: string; expiresAt: Date };

/** Create a brand-new refresh token family (at login). */
export async function issueRefreshToken(userId: string, deviceLabel?: string): Promise<IssuedRefresh> {
  const token = randomBase64Url(32);
  const familyId = randomUUID();
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
  const [row] = await db
    .insert(refreshTokens)
    .values({
      userId,
      tokenHash: sha256Hex(token),
      familyId,
      deviceLabel: deviceLabel ?? null,
      expiresAt,
    })
    .returning({ id: refreshTokens.id });
  return { token, id: row!.id, familyId, expiresAt };
}

/**
 * Rotate a refresh token: validate the presented token, issue a new one in the same family,
 * and mark the old one replacedBy/revoked. Detects reuse.
 */
export async function rotateRefreshToken(presentedToken: string): Promise<{
  userId: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
}> {
  const presentedHash = sha256Hex(presentedToken);

  return await db.transaction(async (tx) => {
    const [existing] = await tx.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, presentedHash)).limit(1);
    if (!existing) throw unauthorized("Invalid refresh token");

    // Reuse detection: token was already rotated or already revoked → burn the whole family.
    if (existing.revokedAt || existing.replacedBy) {
      await tx
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.familyId, existing.familyId), isNull(refreshTokens.revokedAt)));
      throw unauthorized("Refresh token reuse detected — all sessions in this family have been revoked");
    }

    if (existing.expiresAt.getTime() < Date.now()) {
      await tx.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.id, existing.id));
      throw unauthorized("Refresh token expired");
    }

    // Issue new token in the same family.
    const newToken = randomBase64Url(32);
    const newExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    const [inserted] = await tx
      .insert(refreshTokens)
      .values({
        userId: existing.userId,
        tokenHash: sha256Hex(newToken),
        familyId: existing.familyId,
        deviceLabel: existing.deviceLabel,
        expiresAt: newExpiresAt,
      })
      .returning({ id: refreshTokens.id });

    await tx
      .update(refreshTokens)
      .set({ revokedAt: new Date(), replacedBy: inserted!.id, lastUsedAt: new Date() })
      .where(eq(refreshTokens.id, existing.id));

    const accessToken = await issueAccessToken(existing.userId);
    return { userId: existing.userId, accessToken, refreshToken: newToken, expiresAt: newExpiresAt };
  });
}

/** Revoke a single refresh token (by plaintext). No-op if not found. */
export async function revokeRefreshToken(presentedToken: string): Promise<void> {
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.tokenHash, sha256Hex(presentedToken)), isNull(refreshTokens.revokedAt)));
}

/** Revoke every active refresh token of a user. */
export async function revokeAllRefreshTokens(userId: string): Promise<void> {
  await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)));
}
