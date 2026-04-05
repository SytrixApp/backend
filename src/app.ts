import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
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
