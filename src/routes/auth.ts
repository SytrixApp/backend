import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import {
  changePassword,
  login,
  prelogin,
  recover,
  register,
  validateEmail,
} from "../services/auth.service.js";
import {
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllRefreshTokens,
} from "../services/token.service.js";
import { requireAuth, type AuthVariables } from "../middleware/auth.js";
import { rateLimit, clientIp, checkRateLimit } from "../middleware/rate-limit.js";

const Base64 = z
  .string()
  .min(1)
  .refine((v) => /^[A-Za-z0-9+/_-]+=*$/.test(v), "Invalid base64")
  .transform((v) => Buffer.from(v, "base64"));

const KdfParams = z.object({
  algo: z.literal("argon2id"),
  iterations: z.number().int().min(1).max(10),
  memory: z.number().int().min(8 * 1024).max(1024 * 1024), // 8 MiB .. 1 GiB
  parallelism: z.number().int().min(1).max(16),
});

const RegisterBody = z.object({
  email: z.string().email(),
  passwordHash: z.string().min(32).max(512),
  kdfSalt: Base64,
  kdfParams: KdfParams,
  encryptedDataKey: Base64,
  encryptedDataKeyRecovery: Base64,
  recoveryCode: z.string().min(16).max(256),
});

const PreloginBody = z.object({ email: z.string().email() });

const LoginBody = z.object({
  email: z.string().email(),
  passwordHash: z.string().min(32).max(512),
  deviceLabel: z.string().max(100).optional(),
});

const RefreshBody = z.object({ refreshToken: z.string().min(16) });
const LogoutBody = z.object({ refreshToken: z.string().min(16) });

const RecoverBody = z.object({
  email: z.string().email(),
  recoveryCode: z.string().min(16).max(256),
  newPasswordHash: z.string().min(32).max(512),
  newKdfSalt: Base64,
  newKdfParams: KdfParams,
  newEncryptedDataKey: Base64,
  newEncryptedDataKeyRecovery: Base64,
  newRecoveryCode: z.string().min(16).max(256),
});

const ChangePasswordBody = z.object({
  currentPasswordHash: z.string().min(32).max(512),
  newPasswordHash: z.string().min(32).max(512),
  newKdfSalt: Base64,
  newKdfParams: KdfParams,
  newEncryptedDataKey: Base64,
});

export const authRoutes = new Hono<{ Variables: AuthVariables }>();

authRoutes.post(
  "/register",
  rateLimit({ name: "register", limit: 30, windowSec: 3600, key: clientIp }),
  zValidator("json", RegisterBody),
  async (c) => {
    const body = c.req.valid("json");
    validateEmail(body.email);
    const result = await register(body);
    return c.json({ userId: result.userId }, 201);
  },
);

authRoutes.post(
  "/prelogin",
  rateLimit({ name: "prelogin", limit: 30, windowSec: 60, key: clientIp }),
  zValidator("json", PreloginBody),
  async (c) => {
    const { email } = c.req.valid("json");
    const { kdfSalt, kdfParams } = await prelogin(email);
    return c.json({ kdfSalt: kdfSalt.toString("base64"), kdfParams });
  },
);

authRoutes.post(
  "/login",
  rateLimit({ name: "login:ip", limit: 10, windowSec: 900, key: clientIp }),
  zValidator("json", LoginBody),
  async (c) => {
    const body = c.req.valid("json");
    // Per-email limit, checked here because we need the validated body.
    await checkRateLimit({
      name: "login:email",
      limit: 5,
      windowSec: 900,
      keyValue: body.email.toLowerCase(),
    });
    const result = await login(body.email, body.passwordHash, body.deviceLabel);
    return c.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      refreshExpiresAt: result.refreshExpiresAt.toISOString(),
      encryptedDataKey: result.encryptedDataKey.toString("base64"),
      userId: result.userId,
    });
  },
);

authRoutes.post(
  "/refresh",
  rateLimit({ name: "refresh", limit: 60, windowSec: 60, key: clientIp }),
  zValidator("json", RefreshBody),
  async (c) => {
    const { refreshToken } = c.req.valid("json");
    const result = await rotateRefreshToken(refreshToken);
    return c.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      refreshExpiresAt: result.expiresAt.toISOString(),
    });
  },
);

authRoutes.post("/logout", zValidator("json", LogoutBody), async (c) => {
  const { refreshToken } = c.req.valid("json");
  await revokeRefreshToken(refreshToken);
  return c.json({ ok: true });
});

authRoutes.post("/logout-all", requireAuth, async (c) => {
  await revokeAllRefreshTokens(c.get("userId"));
  return c.json({ ok: true });
});

authRoutes.post(
  "/recover",
  rateLimit({ name: "recover", limit: 3, windowSec: 3600, key: clientIp }),
  zValidator("json", RecoverBody),
  async (c) => {
    const body = c.req.valid("json");
    const result = await recover(body);
    return c.json({ userId: result.userId });
  },
);

authRoutes.post(
  "/change-password",
  requireAuth,
  zValidator("json", ChangePasswordBody),
  async (c) => {
    const body = c.req.valid("json");
    await changePassword({ userId: c.get("userId"), ...body });
    return c.json({ ok: true });
  },
);
