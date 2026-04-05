import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    testTimeout: 20000,
    hookTimeout: 30000,
    // Tests share a real Postgres database and mutate the same tables. Run them serially
    // to avoid cross-file truncation races.
    fileParallelism: false,
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
  },
});
