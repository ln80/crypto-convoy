/**
 * SP-18: every parser refuses malformed input with a typed error, before any crypto.
 * Threats: TH-25. Bounded fuzzing; extended per parser as they are added.
 */
import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { fromBase64url } from "../../src/encoding/base64url.js";
import { Reader } from "../../src/encoding/canonical.js";
import { decodeAnchor, decodeLinkKey } from "../../src/encoding/link.js";
import { ConvoyError } from "../../src/errors.js";
import { parsers } from "../support/parsers.js";
import { sampleRecords } from "../support/records.js";

const RUNS = { numRuns: 5_000 };

/** A parser may succeed or throw a ConvoyError; anything else is a bug. */
function onlyTypedErrors(parse: () => unknown) {
  try {
    parse();
  } catch (error) {
    expect(error).toBeInstanceOf(ConvoyError);
  }
}

describe("SP-18: decoders", () => {
  const text = fc.oneof(fc.string(), fc.string({ unit: "binary" }), fc.base64String().map((s) => "1" + s));
  test.prop([text], RUNS)("base64url", (value) => {
    onlyTypedErrors(() => fromBase64url(value));
  });
  test.prop([text], RUNS)("link key", (value) => {
    onlyTypedErrors(() => decodeLinkKey(value));
  });
  test.prop([text], RUNS)("anchor", (value) => {
    onlyTypedErrors(() => decodeAnchor(value));
  });
  test.prop([fc.uint8Array({ maxLength: 64 })], RUNS)("canonical reader", (bytes) => {
    onlyTypedErrors(() => {
      const reader = new Reader(bytes);
      reader.string();
      reader.list((r) => r.optional((o) => o.u64()), 128);
      reader.end();
    });
  });
});

describe("SP-18: record parsers", () => {
  const sample = sampleRecords();
  const parse = parsers(sample.submissionId);
  const anyJson = fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.integer(),
    fc.double(),
    fc.string(),
    fc.base64String(),
    fc.array(fc.jsonValue(), { maxLength: 3 }),
    fc.jsonValue(),
  );

  for (const [type, json] of Object.entries(sample.records)) {
    const keys = Object.keys(json);
    test.prop([fc.constantFrom(...keys), anyJson], RUNS)(`${type}: one field replaced`, (key, value) => {
      onlyTypedErrors(() => parse[type as keyof typeof parse]({ ...json, [key]: value }));
    });
    test.prop([fc.constantFrom(...keys)], { numRuns: keys.length * 2 })(`${type}: one field removed`, (key) => {
      const { [key]: _, ...rest } = json as Record<string, unknown>;
      expect(() => parse[type as keyof typeof parse](rest)).toThrow(ConvoyError);
    });
    test.prop([fc.jsonValue()], RUNS)(`${type}: arbitrary JSON`, (value) => {
      onlyTypedErrors(() => parse[type as keyof typeof parse](value));
    });
  }
});
