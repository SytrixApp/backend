import argon2 from "argon2";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// Server-side re-hashing of the client-provided password_hash. The client already did
// an expensive Argon2id on the user's password; this is a second, server-side Argon2id
// so that if the DB leaks, an attacker still needs to crack argon2 before obtaining
// anything testable against the client's stored material.
const SERVER_ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB — OWASP 2023 min
  timeCost: 2,
  parallelism: 1,
};

export async function hashPasswordHash(clientPasswordHash: string): Promise<string> {
  return argon2.hash(clientPasswordHash, SERVER_ARGON2_OPTIONS);
}

export async function verifyPasswordHash(storedHash: string, clientPasswordHash: string): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, clientPasswordHash);
  } catch {
    return false;
  }
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export function randomBase64Url(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

/** Constant-time string comparison. Returns false for different lengths. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
