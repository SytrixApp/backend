import { createMiddleware } from "hono/factory";
import { sql } from "drizzle-orm";
import type { Context } from "hono";
import { db } from "../db/client.js";
import { rateLimited } from "../lib/errors.js";

export type RateLimitOptions = {
  /** Logical name of the bucket (e.g. "login", "register"). Combined with the key into the row id. */
  name: string;
  /** Max requests allowed within the window. */
  limit: number;
  /** Window size in seconds. */
  windowSec: number;
  /** How to build the rate-limit key from the request. */
  key: (c: Context) => string;
};

/**
 * Fixed-window rate limit check against the Postgres bucket table. Shared core used by both the
 * middleware wrapper and direct in-handler checks.
 *
 * Fixed-window is the simplest approach to get right atomically with a single SQL statement, and
 * it's sufficient for login/register/refresh protection at MVP scale. Swap for a leaky bucket or
 * Redis-based limiter if load justifies it.
 */
async function bumpAndCheck(name: string, keyValue: string, limit: number, windowSec: number): Promise<void> {
  const bucketKey = `${name}:${keyValue}`;
  const [row] = await db.execute<{ count: number }>(sql`
    INSERT INTO rate_limit_buckets (key, count, window_start)
    VALUES (${bucketKey}, 1, now())
    ON CONFLICT (key) DO UPDATE
    SET
      count = CASE
        WHEN rate_limit_buckets.window_start + (${windowSec} || ' seconds')::interval < now()
          THEN 1
        ELSE rate_limit_buckets.count + 1
      END,
      window_start = CASE
        WHEN rate_limit_buckets.window_start + (${windowSec} || ' seconds')::interval < now()
          THEN now()
        ELSE rate_limit_buckets.window_start
      END
    RETURNING count
  `);
  const count = Number(row?.count ?? 0);
  if (count > limit) {
    throw rateLimited(`Rate limit exceeded for ${name}`);
  }
}

export function rateLimit(opts: RateLimitOptions) {
  return createMiddleware(async (c, next) => {
    await bumpAndCheck(opts.name, opts.key(c), opts.limit, opts.windowSec);
    await next();
  });
}

/**
 * Direct rate-limit check for use inside handlers when the key depends on a validated body value.
 */
export async function checkRateLimit(opts: {
  name: string;
  limit: number;
  windowSec: number;
  keyValue: string;
}): Promise<void> {
  await bumpAndCheck(opts.name, opts.keyValue, opts.limit, opts.windowSec);
}

/** Best-effort client IP. Falls back to a placeholder so the limiter still functions. */
export function clientIp(c: Context): string {
  const xff = c.req.header("x-forwarded-for");
  if (xff) return xff.split(",")[0]!.trim();
  const real = c.req.header("x-real-ip");
  if (real) return real.trim();
  return "unknown";
}
