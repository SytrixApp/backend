import { Hono } from "hono";
import { sql } from "drizzle-orm";
import { db } from "../db/client.js";

export const healthRoutes = new Hono();

healthRoutes.get("/", async (c) => {
  try {
    await db.execute(sql`select 1`);
    return c.json({ status: "ok", db: "ok" });
  } catch (err) {
    return c.json({ status: "degraded", db: "error" }, 503);
  }
});
