import { getRequestListener } from "@hono/node-server";
import { buildApp } from "../src/app.js";

// Vercel serverless entry. `hono/vercel` targets the Edge / Next.js App Router
// runtime (Web Request/Response). Vercel's classic Node runtime — which we need
// because argon2 ships a native addon — passes Node.js IncomingMessage objects,
// so we use @hono/node-server's request listener bridge instead.
export const runtime = "nodejs";

const app = buildApp();
export default getRequestListener(app.fetch);
