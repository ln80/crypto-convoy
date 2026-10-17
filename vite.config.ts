import { resolve } from "node:path";
import { defineConfig } from "vite";
import dts from "vite-plugin-dts";

const entry = (path: string) => resolve(import.meta.dirname, path);

export default defineConfig({
  build: {
    lib: {
      entry: {
        index: entry("src/index.ts"),
        browser: entry("src/browser/index.ts"),
        testing: entry("src/testing/index.ts"),
      },
      formats: ["es", "cjs"],
      fileName: (format, name) => `${name}.${format === "es" ? "js" : "cjs"}`,
    },
    rollupOptions: {
      external: [/^libsodium-wrappers-sumo/, /^@noble\//, /^@scure\//],
    },
    sourcemap: true,
    emptyOutDir: true,
  },
  plugins: [dts({ include: ["src"], exclude: ["src/**/CLAUDE.md"], bundleTypes: true })],
});
