import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { HttpError } from "../lib/errors.js";
import { loadEnv } from "../env.js";

const env = loadEnv();

export function errorHandler(err: Error, c: Context) {
  if (err instanceof HttpError) {
    return c.json(
      {
        error: {
          code: err.code,
          message: err.message,
          ...(err.details !== undefined ? { details: err.details } : {}),
        },
      },
      err.status as ContentfulStatusCode,
    );
  }

  // Unknown error — log and return 500. Never leak details in production.
  console.error("[unhandled]", err);
  return c.json(
    {
      error: {
        code: "internal",
        message: env.NODE_ENV === "production" ? "Internal server error" : err.message,
      },
    },
    500,
  );
}
