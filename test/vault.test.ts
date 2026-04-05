import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applyMigrations, closeDb, resetDb } from "./helpers/db.js";
import { makeClient, randomEmail, sampleItem, sampleRegisterPayload } from "./helpers/client.js";

const client = makeClient();

async function registerAndLogin() {
  const payload = sampleRegisterPayload(randomEmail());
  await client.post("/api/v1/auth/register", payload);
  const login = await client.post("/api/v1/auth/login", {
    email: payload.email,
    passwordHash: payload.passwordHash,
  });
  return { token: login.body.accessToken as string, payload };
}

beforeAll(async () => {
  await applyMigrations();
});
beforeEach(async () => {
  await resetDb();
});
afterAll(async () => {
  await closeDb();
});

describe("vault", () => {
  it("requires auth", async () => {
    const res = await client.get("/api/v1/vault/items");
    expect(res.status).toBe(401);
  });

  it("full CRUD and incremental sync", async () => {
    const { token } = await registerAndLogin();

    const empty = await client.get("/api/v1/vault/items", { token });
    expect(empty.status).toBe(200);
    expect(empty.body.items).toEqual([]);

    // Create
    const created = await client.post("/api/v1/vault/items", sampleItem(), { token });
    expect(created.status).toBe(201);
    const itemId = created.body.item.id as string;
    expect(itemId).toBeTypeOf("string");

    // List
    const list = await client.get("/api/v1/vault/items", { token });
    expect(list.body.items).toHaveLength(1);

    // Update
    const updated = await client.patch(`/api/v1/vault/items/${itemId}`, sampleItem(), { token });
    expect(updated.status).toBe(200);
    expect(updated.body.item.updatedAt).not.toBe(created.body.item.updatedAt);

    // Incremental sync: since=createdAt should return the update
    const since = created.body.item.createdAt;
    const incr = await client.get(`/api/v1/vault/items?since=${encodeURIComponent(since)}`, { token });
    expect(incr.body.items.some((i: any) => i.id === itemId)).toBe(true);

    // Delete (soft)
    const del = await client.delete(`/api/v1/vault/items/${itemId}`, { token });
    expect(del.status).toBe(200);

    // Default list hides soft-deleted
    const afterDelete = await client.get("/api/v1/vault/items", { token });
    expect(afterDelete.body.items).toEqual([]);

    // Incremental list includes the deletion
    const incr2 = await client.get(`/api/v1/vault/items?since=${encodeURIComponent(since)}`, { token });
    const deletedRow = incr2.body.items.find((i: any) => i.id === itemId);
    expect(deletedRow?.deletedAt).toBeTruthy();
  });

  it("isolates users", async () => {
    const a = await registerAndLogin();
    const b = await registerAndLogin();

    const aItem = await client.post("/api/v1/vault/items", sampleItem(), { token: a.token });
    const id = aItem.body.item.id as string;

    const bSees = await client.get("/api/v1/vault/items", { token: b.token });
    expect(bSees.body.items).toEqual([]);

    const bDelete = await client.delete(`/api/v1/vault/items/${id}`, { token: b.token });
    expect(bDelete.status).toBe(404);

    const bUpdate = await client.patch(`/api/v1/vault/items/${id}`, sampleItem(), { token: b.token });
    expect(bUpdate.status).toBe(404);
  });

  it("rejects malformed nonce length", async () => {
    const { token } = await registerAndLogin();
    const bad = await client.post(
      "/api/v1/vault/items",
      { encryptedData: Buffer.from("data").toString("base64"), nonce: Buffer.alloc(10).toString("base64") },
      { token },
    );
    expect(bad.status).toBe(400);
  });
});
