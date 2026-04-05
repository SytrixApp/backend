import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { getRequestListener } from "@hono/node-server";
import { authRoutes } from "./routes/auth.js";
import { vaultRoutes } from "./routes/vault.js";
import { accountRoutes } from "./routes/account.js";
import { healthRoutes } from "./routes/health.js";
import { errorHandler } from "./middleware/error.js";
import { rateLimit, clientIp } from "./middleware/rate-limit.js";
import { loadEnv } from "./env.js";

export function buildApp() {
  const env = loadEnv();
  const app = new Hono();

  if (env.NODE_ENV !== "test") app.use("*", logger());

  app.use(
    "*",
    cors({
      origin: "*", // tighten per deployment; configurable via env later
      allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
      allowHeaders: ["Authorization", "Content-Type"],
      maxAge: 86400,
    }),
  );

  app.get("/", (c) =>
    c.json({
      name: "sytrix-backend",
      version: "0.1.0",
      docs: "https://github.com/SytrixApp/backend",
    }),
  );

  app.route("/health", healthRoutes);

  // Global coarse limiter on the /api/v1 surface.
  const api = new Hono();
  if (env.NODE_ENV !== "test") {
    api.use("*", rateLimit({ name: "api", limit: 300, windowSec: 60, key: clientIp }));
  }
  api.route("/auth", authRoutes);
  api.route("/vault", vaultRoutes);
  api.route("/account", accountRoutes);
  app.route("/api/v1", api);

  app.onError(errorHandler);
  app.notFound((c) => c.json({ error: { code: "not_found", message: "Route not found" } }, 404));

  return app;
}

// Default export: a Vercel-compatible Node request listener. Exporting this here
// (in addition to the real serverless entry at api/index.ts) guards against a
// build/cache quirk where Vercel's function resolver occasionally loads
// src/app.js instead of api/index.js. Both files now produce the same handler,
// so the behaviour is identical regardless of which entry the runtime picks.
export default getRequestListener(buildApp().fetch);

