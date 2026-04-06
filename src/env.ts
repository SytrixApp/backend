import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z
    .string()
    .refine((s) => Buffer.byteLength(s, "utf8") >= 64, "JWT_SECRET must be at least 64 bytes when UTF-8 encoded (generate with: node -e \"console.log(require('crypto').randomBytes(64).toString('base64url'))\")"),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  // Comma-separated list of allowed CORS origins. Defaults to localhost only.
  // Example: "https://app.example.com,https://admin.example.com"
  ALLOWED_ORIGINS: z.string().optional(),
  // Set to "true" when the server runs behind a trusted reverse proxy that sets X-Forwarded-For.
  // If unset, X-Forwarded-For headers are ignored to prevent IP spoofing.
  TRUST_PROXY: z.enum(["true", "false"]).default("false"),
  // Server-side HMAC secret for recovery code hashing. Falls back to JWT_SECRET if unset.
  // Recommended: generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`
  RECOVERY_HMAC_SECRET: z.string().min(16).optional(),
});

export type Env = z.infer<typeof EnvSchema>;

let cached: Env | null = null;

export function loadEnv(): Env {
  if (cached) return cached;
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid environment variables:\n${issues}`);
  }
  cached = parsed.data;
  return cached;
}
