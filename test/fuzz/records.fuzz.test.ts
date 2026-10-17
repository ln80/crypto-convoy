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
