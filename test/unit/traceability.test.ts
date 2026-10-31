/**
 * Every non-deferred security property names test files under Verification;
 * each must exist and cite the property id (guide: testing). A property may also name a formal
 * model and its lemmas (plan 027): the model must exist, cite the id, and define each lemma.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT, read } from "../support/source.js";

const STRICT = true;

const entries = read("docs/security-properties.md")
  .split(/^(?=### SP-\d+:)/m)
  .filter((chunk) => chunk.startsWith("### SP-"))
  .map((chunk) => ({
    id: chunk.match(/^### (SP-\d+):/)![1]!,
    deferred: /^Status: deferred/im.test(chunk),
    files: [...chunk.matchAll(/`(test\/[^`]+\.test\.ts)`/g)].map((m) => m[1]!),
    models: [...chunk.matchAll(/^- `(formal\/[^`]+\.spthy)`: lemmas? (.*)$/gm)].map((m) => ({
      file: m[1]!,
      lemmas: [...m[2]!.matchAll(/`([A-Za-z0-9_]+)`/g)].map((l) => l[1]!),
    })),
  }))
  .filter((entry) => !entry.deferred);

describe("traceability", () => {
  it("finds the properties", () => {
    expect(entries.length).toBe(23);
    for (const entry of entries) expect(entry.files.length, entry.id).toBeGreaterThan(0);
  });

  for (const { id, models } of entries) {
    for (const { file, lemmas } of models) {
      it(`${id}: ${file} exists, cites ${id} and defines ${lemmas.join(", ")}`, () => {
        expect(existsSync(join(ROOT, file))).toBe(true);
        const model = read(file);
        expect(model).toMatch(new RegExp(`\\b${id}\\b`));
        expect(lemmas.length).toBeGreaterThan(0);
        for (const lemma of lemmas) expect(model, lemma).toMatch(new RegExp(`^lemma ${lemma}:`, "m"));
      });
    }
  }

  for (const { id, files } of entries) {
    for (const file of files) {
      const exists = existsSync(join(ROOT, file));
      if (!exists && !STRICT) {
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
