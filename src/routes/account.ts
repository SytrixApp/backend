import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { and, eq, isNull, gt } from "drizzle-orm";
import { db } from "../db/client.js";
import { refreshTokens, users } from "../db/schema.js";
import { requireAuth, type AuthVariables } from "../middleware/auth.js";
import { notFound } from "../lib/errors.js";

export const accountRoutes = new Hono<{ Variables: AuthVariables }>();

accountRoutes.use("*", requireAuth);

accountRoutes.get("/me", async (c) => {
  const userId = c.get("userId");
  const [user] = await db
    .select({
      id: users.id,
      email: users.email,
      createdAt: users.createdAt,
      updatedAt: users.updatedAt,
    })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  if (!user) throw notFound("User not found");
  return c.json({
    id: user.id,
    email: user.email,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  });
});

accountRoutes.get("/sessions", async (c) => {
  const userId = c.get("userId");
  const rows = await db
    .select({
      id: refreshTokens.id,
      deviceLabel: refreshTokens.deviceLabel,
      createdAt: refreshTokens.createdAt,
      lastUsedAt: refreshTokens.lastUsedAt,
      expiresAt: refreshTokens.expiresAt,
    })
    .from(refreshTokens)
    .where(
      and(
        eq(refreshTokens.userId, userId),
        isNull(refreshTokens.revokedAt),
        gt(refreshTokens.expiresAt, new Date()),
      ),
    );
  return c.json({
    sessions: rows.map((r) => ({
      id: r.id,
      deviceLabel: r.deviceLabel,
      createdAt: r.createdAt.toISOString(),
      lastUsedAt: r.lastUsedAt.toISOString(),
      expiresAt: r.expiresAt.toISOString(),
    })),
  });
});

const IdParam = z.object({ id: z.string().uuid() });

accountRoutes.delete("/sessions/:id", zValidator("param", IdParam), async (c) => {
  const userId = c.get("userId");
  const { id } = c.req.valid("param");
  const [row] = await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(refreshTokens.id, id),
        eq(refreshTokens.userId, userId),
        isNull(refreshTokens.revokedAt),
      ),
    )
    .returning({ id: refreshTokens.id });
  if (!row) throw notFound("Session not found");
  return c.json({ ok: true });
});
