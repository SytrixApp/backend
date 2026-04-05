import { handle } from "hono/vercel";
import { buildApp } from "../src/app.js";

// Vercel adapter. The `vercel.json` rewrite sends every /api/* request here,
// and Hono's internal router handles path dispatch.
export const config = { runtime: "nodejs" };

const app = buildApp();
export default handle(app);
