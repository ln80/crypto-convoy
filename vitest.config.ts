import { defineConfig } from "vitest/config";

const node = { environment: "node" as const, passWithNoTests: true, setupFiles: ["test/support/setup.ts"] };

export default defineConfig({
  test: {
    ...node,
    projects: [
      { test: { name: "unit", include: ["test/unit/**/*.test.ts"], ...node } },
      {
        test: {
          name: "properties",
          include: ["test/properties/**/*.test.ts"],
          testTimeout: 30_000,
          ...node,
          // The memory test forces collection to measure what the library keeps, not garbage.
          execArgv: ["--expose-gc"],
        },
      },
      {
        test: {
          name: "security",
          include: ["test/security/**/*.test.ts"],
          fileParallelism: false,
          testTimeout: 30_000,
          ...node,
        },
      },
      { test: { name: "browser", include: ["test/browser/**/*.test.ts"], ...node } },
      {
        test: {
          name: "compatibility",
          include: ["test/compatibility/**/*.test.ts"],
          // The scenario runs a product's whole life, with an Argon2id and a proved OPRF per PIN step.
          testTimeout: 30_000,
          ...node,
        },
      },
      {
        test: {
          name: "fuzz",
          include: ["test/fuzz/**/*.test.ts"],
          fileParallelism: false,
          testTimeout: 120_000,
          ...node,
        },
      },
    ],
  },
});
