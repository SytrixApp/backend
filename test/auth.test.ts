import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applyMigrations, closeDb, resetDb } from "./helpers/db.js";
import { makeClient, randomEmail, sampleRegisterPayload } from "./helpers/client.js";

const client = makeClient();

beforeAll(async () => {
  await applyMigrations();
});
beforeEach(async () => {
  await resetDb();
});
afterAll(async () => {
  await closeDb();
});

describe("auth", () => {
  it("registers a user then logs in", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    const reg = await client.post("/api/v1/auth/register", payload);
    expect(reg.status).toBe(201);
    expect(reg.body.userId).toBeTypeOf("string");

    const login = await client.post("/api/v1/auth/login", {
      email: payload.email,
      passwordHash: payload.passwordHash,
    });
    expect(login.status).toBe(200);
    expect(login.body.accessToken).toBeTypeOf("string");
    expect(login.body.refreshToken).toBeTypeOf("string");
    expect(login.body.encryptedDataKey).toBe(payload.encryptedDataKey);
  });

  it("rejects duplicate registration", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    await client.post("/api/v1/auth/register", payload);
    const second = await client.post("/api/v1/auth/register", payload);
    expect(second.status).toBe(409);
  });

  it("rejects login with wrong password", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    await client.post("/api/v1/auth/register", payload);
    const login = await client.post("/api/v1/auth/login", {
      email: payload.email,
      passwordHash: "x".repeat(64),
    });
    expect(login.status).toBe(401);
  });

  it("prelogin returns real salt for known emails and fake for unknown", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    await client.post("/api/v1/auth/register", payload);

    const known = await client.post("/api/v1/auth/prelogin", { email: payload.email });
    expect(known.status).toBe(200);
    expect(known.body.kdfSalt).toBe(payload.kdfSalt);

    const unknown = await client.post("/api/v1/auth/prelogin", { email: randomEmail() });
    expect(unknown.status).toBe(200);
    expect(unknown.body.kdfSalt).toBeTypeOf("string"); // deterministic fake, shape matches
    expect(unknown.body.kdfParams.algo).toBe("argon2id");
  });

  it("rotates refresh tokens and detects reuse", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    await client.post("/api/v1/auth/register", payload);
    const login = await client.post("/api/v1/auth/login", {
      email: payload.email,
      passwordHash: payload.passwordHash,
    });
    const firstRefresh = login.body.refreshToken;

    const rotated = await client.post("/api/v1/auth/refresh", { refreshToken: firstRefresh });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refreshToken).not.toBe(firstRefresh);

    // Reusing the original (now-rotated) token must fail and burn the family.
    const reuse = await client.post("/api/v1/auth/refresh", { refreshToken: firstRefresh });
    expect(reuse.status).toBe(401);

    // After reuse, even the most recently issued token is revoked.
    const postReuse = await client.post("/api/v1/auth/refresh", { refreshToken: rotated.body.refreshToken });
    expect(postReuse.status).toBe(401);
  });

  it("recover rotates keys with valid recovery code", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    await client.post("/api/v1/auth/register", payload);

    const newPayload = sampleRegisterPayload(payload.email);
    const recover = await client.post("/api/v1/auth/recover", {
      email: payload.email,
      recoveryCode: payload.recoveryCode,
      newPasswordHash: newPayload.passwordHash,
      newKdfSalt: newPayload.kdfSalt,
      newKdfParams: newPayload.kdfParams,
      newEncryptedDataKey: newPayload.encryptedDataKey,
      newEncryptedDataKeyRecovery: newPayload.encryptedDataKeyRecovery,
      newRecoveryCode: newPayload.recoveryCode,
    });
    expect(recover.status).toBe(200);

    // Old password no longer works.
    const oldLogin = await client.post("/api/v1/auth/login", {
      email: payload.email,
      passwordHash: payload.passwordHash,
    });
    expect(oldLogin.status).toBe(401);

    // New one does.
    const newLogin = await client.post("/api/v1/auth/login", {
      email: payload.email,
      passwordHash: newPayload.passwordHash,
    });
    expect(newLogin.status).toBe(200);
  });

  it("rejects recover with wrong recovery code", async () => {
    const payload = sampleRegisterPayload(randomEmail());
    await client.post("/api/v1/auth/register", payload);

    const newPayload = sampleRegisterPayload(payload.email);
    const recover = await client.post("/api/v1/auth/recover", {
      email: payload.email,
      recoveryCode: "wrong-recovery-code-value-that-is-long-enough",
      newPasswordHash: newPayload.passwordHash,
      newKdfSalt: newPayload.kdfSalt,
      newKdfParams: newPayload.kdfParams,
      newEncryptedDataKey: newPayload.encryptedDataKey,
      newEncryptedDataKeyRecovery: newPayload.encryptedDataKeyRecovery,
      newRecoveryCode: newPayload.recoveryCode,
    });
    expect(recover.status).toBe(401);
  });
});
