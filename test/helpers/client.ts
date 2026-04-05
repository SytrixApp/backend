import { randomBytes } from "node:crypto";
import { buildApp } from "../../src/app.js";

export function makeClient() {
  const app = buildApp();

  async function request(method: string, path: string, opts: { body?: unknown; token?: string } = {}) {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (opts.token) headers["authorization"] = `Bearer ${opts.token}`;
    const res = await app.request(path, {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = text;
    }
    return { status: res.status, body: json as any };
  }

  return {
    get: (p: string, o?: { token?: string }) => request("GET", p, o),
    post: (p: string, body?: unknown, o?: { token?: string }) => request("POST", p, { body, ...o }),
    patch: (p: string, body?: unknown, o?: { token?: string }) => request("PATCH", p, { body, ...o }),
    delete: (p: string, o?: { token?: string }) => request("DELETE", p, o),
  };
}

export function randomEmail(): string {
  return `test-${randomBytes(6).toString("hex")}@sytrix.test`;
}

export function b64(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64");
}

/** Produces a valid register payload with random opaque blobs. Server doesn't decrypt them. */
export function sampleRegisterPayload(email: string) {
  return {
    email,
    passwordHash: randomBytes(32).toString("base64"),
    kdfSalt: b64(randomBytes(16)),
    kdfParams: { algo: "argon2id" as const, iterations: 3, memory: 65536, parallelism: 1 },
    encryptedDataKey: b64(randomBytes(60)),
    encryptedDataKeyRecovery: b64(randomBytes(60)),
    recoveryCode: randomBytes(24).toString("base64"),
  };
}

export function sampleItem() {
  return {
    encryptedData: b64(randomBytes(80)),
    nonce: b64(randomBytes(12)),
  };
}
