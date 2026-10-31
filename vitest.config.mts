import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = fileURLToPath(new URL("./src", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      // Keep in sync with tsconfig.json "paths". Switch @contracts to src/lib/contracts once AGREED.
      "@contracts": `${src}/lib/agent/stubs/contracts.ts`,
      "@": src,
    },
  },
  test: {
    include: ["tests/**/*.test.ts", "src/eval/**/*.test.ts"],
    environment: "node",
    globals: true,
  },
});
