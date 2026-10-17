/**
 * Architecture boundaries (AGENTS.md rule 9, D-15): dependency allowlist,
 * platform-neutral core, one-way layers, public entry points only.
 */
import { dirname, join, normalize } from "node:path";
import { describe, expect, it } from "vitest";
import { codeOnly, importsOf, read, tsFiles } from "../support/source.js";

const files = tsFiles("src");

/** Which `src/` area a file belongs to: its first directory, or its own name. */
const areaOf = (path: string) => {
  const parts = path.split("/");
  return parts.length > 2 ? parts[1]! : parts[1]!.replace(/\.ts$/, "");
};

const EXTERNAL: Record<string, readonly string[]> = {
  "libsodium-wrappers-sumo": ["suites"],
  "@noble/curves": ["suites", "testing"],
  "@scure/bip39": ["suites"],
};

// Each area lists the areas it may import. Layers go one way (architecture guide).
const BASE = ["errors", "internal", "ports"];
const ALLOWED: Record<string, readonly string[]> = {
  errors: [],
  internal: ["errors"],
  ports: ["errors"],
  encoding: [...BASE],
  suites: [...BASE, "encoding"],
  blocks: [...BASE, "encoding", "suites"],
  records: [...BASE, "encoding", "suites", "blocks"],
  content: [...BASE, "encoding", "suites", "blocks", "records"],
  team: [...BASE, "encoding", "suites", "blocks", "records", "content"],
  account: [...BASE, "encoding", "suites", "blocks", "records", "team", "content"],
  index: [...BASE, "encoding", "suites", "blocks", "records", "team", "content", "account"],
  browser: [...BASE, "encoding", "suites", "index"],
  testing: [...BASE, "encoding", "suites", "blocks", "records", "index"],
};

const internalTarget = (from: string, spec: string) => {
  const target = normalize(join(dirname(from), spec)).replace(/\.js$/, ".ts");
  return areaOf(target.endsWith(".ts") ? target : `${target}.ts`);
};

describe("boundaries", () => {
  it.each(files)("%s imports only allowed modules", (file) => {
    const area = areaOf(file);
    expect(ALLOWED[area], `unknown area "${area}": add it to the boundary test`).toBeDefined();
    for (const spec of importsOf(read(file))) {
      if (spec.startsWith(".")) {
        const target = internalTarget(file, spec);
        if (target === area) continue;
        expect(ALLOWED[area], `${file} imports ${spec} (${target})`).toContain(target);
      } else {
        const pkg = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]!;
        expect(EXTERNAL[pkg], `${file} imports ${spec}, not in the dependency allowlist`).toBeDefined();
        expect(EXTERNAL[pkg], `${file} imports ${pkg} outside its allowed areas`).toContain(area);
      }
    }
  });

  it.each(files.filter((f) => areaOf(f) !== "browser"))("%s uses no DOM or Node-only globals", (file) => {
    const code = codeOnly(read(file));
    expect(code).not.toMatch(/\b(window|document|indexedDB|localStorage|sessionStorage|navigator)\b/);
    expect(code).not.toMatch(/\b(?:globalThis\.)?(?:location|history)\s*\./);
    expect(code).not.toMatch(/\b(Buffer|process|require)\b/);
  });

  it("publishes exactly three entry points", () => {
    const pkg = JSON.parse(read("package.json")) as { exports: Record<string, unknown> };
    expect(Object.keys(pkg.exports)).toEqual([".", "./browser", "./testing"]);
  });
});
