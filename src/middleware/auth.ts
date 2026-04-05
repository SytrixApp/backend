import { createMiddleware } from "hono/factory";
import { verifyAccessToken } from "../services/token.service.js";
import { unauthorized } from "../lib/errors.js";

export type AuthVariables = {
  userId: string;
};

export const requireAuth = createMiddleware<{ Variables: AuthVariables }>(async (c, next) => {
  const header = c.req.header("authorization") ?? c.req.header("Authorization");
  if (!header || !header.toLowerCase().startsWith("bearer ")) {
    throw unauthorized("Missing bearer token");
  }
  const token = header.slice(7).trim();
  const payload = await verifyAccessToken(token);
  c.set("userId", payload.sub);
  await next();
});
