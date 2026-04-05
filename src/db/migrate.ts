import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { sql } from "drizzle-orm";
import { db, sql as pg } from "./client.js";

const MIGRATIONS_DIR = "./drizzle/migrations";

async function ensureMigrationsTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS __sytrix_migrations (
      id text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

async function main() {
  console.log("Running migrations...");
  await ensureMigrationsTable();

  const entries = await readdir(MIGRATIONS_DIR);
  const sqlFiles = entries.filter((f) => f.endsWith(".sql")).sort();

  for (const file of sqlFiles) {
    const id = file.replace(/\.sql$/, "");
    const [already] = await db.execute<{ id: string }>(
      sql`SELECT id FROM __sytrix_migrations WHERE id = ${id}`,
    );
    if (already) {
      console.log(`  ✓ ${id} (already applied)`);
      continue;
    }

    const contents = await readFile(join(MIGRATIONS_DIR, file), "utf8");
    // Split on Drizzle's statement-breakpoint marker when present, else run as a single block.
    const statements = contents.includes("--> statement-breakpoint")
      ? contents.split("--> statement-breakpoint").map((s) => s.trim()).filter(Boolean)
      : [contents];

    await db.transaction(async (tx) => {
      for (const stmt of statements) {
        await tx.execute(sql.raw(stmt));
      }
      await tx.execute(sql`INSERT INTO __sytrix_migrations (id) VALUES (${id})`);
    });
    console.log(`  ✓ ${id}`);
  }

  console.log("Migrations complete.");
  await pg.end();
}

main().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
