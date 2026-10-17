/**
 * Every non-deferred security property names test files under Verification;
 * each must exist and cite the property id (guide: testing).
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT, read } from "../support/source.js";

const STRICT = true;
/** Verification files of plan 004, written in its phase G; `todo` until then. */
const PENDING = new Set([
  "test/security/secure-account.test.ts",
  "test/security/reconcile.test.ts",
  "test/properties/reconcile.properties.test.ts",
  "test/security/recovery-proof.test.ts",
  "test/security/invite-proof.test.ts",
]);

const entries = read("docs/security-properties.md")
  .split(/^(?=### SP-\d+:)/m)
  .filter((chunk) => chunk.startsWith("### SP-"))
  .map((chunk) => ({
    id: chunk.match(/^### (SP-\d+):/)![1]!,
    deferred: /^Status: deferred/im.test(chunk),
    files: [...chunk.matchAll(/`(test\/[^`]+\.test\.ts)`/g)].map((m) => m[1]!),
  }))
  .filter((entry) => !entry.deferred);

describe("traceability", () => {
  it("finds the properties", () => {
    expect(entries.length).toBe(22);
    for (const entry of entries) expect(entry.files.length, entry.id).toBeGreaterThan(0);
  });

  for (const { id, files } of entries) {
    for (const file of files) {
      const exists = existsSync(join(ROOT, file));
      if (!exists && (!STRICT || PENDING.has(file))) {
        it.todo(`${id}: ${file}`);
        continue;
      }
      it(`${id}: ${file} exists and cites ${id}`, () => {
        expect(exists).toBe(true);
        expect(read(file)).toMatch(new RegExp(`\\b${id}\\b`));
      });
    }
  }
});
