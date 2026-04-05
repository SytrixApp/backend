import { handle } from "hono/vercel";
import { buildApp } from "../src/app.js";

// Vercel serverless entry. The `vercel.json` rewrite sends every /api/* and /health
// request here, and Hono's internal router handles path dispatch from there.
export const runtime = "nodejs";

const app = buildApp();
const handler = handle(app);
export default handler;
export const GET = handler;
export const POST = handler;
export const PATCH = handler;
export const DELETE = handler;
export const OPTIONS = handler;
