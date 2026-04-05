import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { requireAuth, type AuthVariables } from "../middleware/auth.js";
import { createItem, listItems, softDeleteItem, updateItem } from "../services/vault.service.js";
import { badRequest } from "../lib/errors.js";

const Base64 = z
  .string()
  .min(1)
  .refine((v) => /^[A-Za-z0-9+/_-]+=*$/.test(v), "Invalid base64")
  .transform((v) => Buffer.from(v, "base64"));

const ItemBody = z.object({
  encryptedData: Base64,
  nonce: Base64.refine((b) => b.length === 12, "Nonce must be 12 bytes (AES-GCM)"),
});

const ListQuery = z.object({
  since: z.string().datetime().optional(),
});

const IdParam = z.object({ id: z.string().uuid() });

export const vaultRoutes = new Hono<{ Variables: AuthVariables }>();

vaultRoutes.use("*", requireAuth);

vaultRoutes.get("/items", zValidator("query", ListQuery), async (c) => {
  const { since } = c.req.valid("query");
  const sinceDate = since ? new Date(since) : undefined;
  if (sinceDate && Number.isNaN(sinceDate.getTime())) throw badRequest("Invalid 'since' timestamp");
  const items = await listItems(c.get("userId"), sinceDate);
  return c.json({ items });
});

vaultRoutes.post("/items", zValidator("json", ItemBody), async (c) => {
  const body = c.req.valid("json");
  const item = await createItem(c.get("userId"), body.encryptedData, body.nonce);
  return c.json({ item }, 201);
});

vaultRoutes.patch(
  "/items/:id",
  zValidator("param", IdParam),
  zValidator("json", ItemBody),
  async (c) => {
    const { id } = c.req.valid("param");
    const body = c.req.valid("json");
    const item = await updateItem(c.get("userId"), id, body.encryptedData, body.nonce);
    return c.json({ item });
  },
);

vaultRoutes.delete("/items/:id", zValidator("param", IdParam), async (c) => {
  const { id } = c.req.valid("param");
  await softDeleteItem(c.get("userId"), id);
  return c.json({ ok: true });
});
