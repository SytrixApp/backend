import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { loadEnv } from "../env.js";
import * as schema from "./schema.js";

const env = loadEnv();

// `postgres-js` with `prepare: false` is required for Supabase "Transaction" pooler (port 6543).
// It is also safe for direct Postgres connections.
const client = postgres(env.DATABASE_URL, {
  prepare: false,
  max: env.NODE_ENV === "production" ? 10 : 5,
});

export const db = drizzle(client, { schema, casing: "snake_case" });
export type DB = typeof db;
export { client as sql };
