import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { sql } from "drizzle-orm";
import { db, sql as pg } from "../../src/db/client.js";

/**
 * Ensures the test database has the latest schema. Requires DATABASE_URL to point at a test
 * Postgres (e.g. the docker-compose db service). Idempotent — mirrors src/db/migrate.ts.
 */
export async function applyMigrations() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS __sytrix_migrations (
      id text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
  const dir = "./drizzle/migrations";
  const files = (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) {
    const id = file.replace(/\.sql$/, "");
    const [already] = await db.execute<{ id: string }>(
      sql`SELECT id FROM __sytrix_migrations WHERE id = ${id}`,
    );
    if (already) continue;
    const contents = await readFile(join(dir, file), "utf8");
    const statements = contents.includes("--> statement-breakpoint")
      ? contents.split("--> statement-breakpoint").map((s) => s.trim()).filter(Boolean)
      : [contents];
    await db.transaction(async (tx) => {
      for (const stmt of statements) {
        await tx.execute(sql.raw(stmt));
      }
      await tx.execute(sql`INSERT INTO __sytrix_migrations (id) VALUES (${id})`);
    });
  }
}

/** Wipe tables between tests. Keeps schema. */
export async function resetDb() {
  await db.execute(sql`TRUNCATE TABLE vault_items, refresh_tokens, rate_limit_buckets, users RESTART IDENTITY CASCADE`);
}

export async function closeDb() {
  await pg.end({ timeout: 5 });
}
