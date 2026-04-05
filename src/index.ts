import { serve } from "@hono/node-server";
import { buildApp } from "./app.js";
import { loadEnv } from "./env.js";

const env = loadEnv();
const app = buildApp();

serve({ fetch: app.fetch, port: env.PORT }, (info) => {
  console.log(`Sytrix backend listening on http://localhost:${info.port}`);
});
