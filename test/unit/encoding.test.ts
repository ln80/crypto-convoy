/** Labels, base64url and errors (§1, §9). */
import { describe, expect, it } from "vitest";
import { fromBase64url, toBase64url } from "../../src/encoding/base64url.js";
import { LABELS } from "../../src/encoding/labels.js";
import { ConvoyError, isConvoyError } from "../../src/errors.js";
import { read } from "../support/source.js";

describe("labels", () => {
  it("are exactly the §1 table, in order", () => {
    const protocol = read("docs/protocol.md");
    const start = protocol.indexOf("| Short name |");
    const table = protocol.slice(start, protocol.indexOf("\n\n", start));
    const names = [...table.matchAll(/^\| `([a-z-]+)` \|/gm)].map((m) => m[1]);
    expect([...LABELS]).toEqual(names);
  });
});

describe("base64url", () => {
  it("round-trips every length up to 40", () => {
    for (let length = 0; length <= 40; length++) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + length) & 0xff);
      const text = toBase64url(bytes);
      expect(text).toBe(Buffer.from(bytes).toString("base64url"));
      expect([...fromBase64url(text)]).toEqual([...bytes]);
    }
  });

  it.each(["A", "AAAAA", "AB==", "AB+/", "A B", "AB\n", "Ab"])("refuses %j", (text) => {
    expect(() => fromBase64url(text)).toThrow(expect.objectContaining({ code: "MALFORMED_RECORD" }));
  });

  it("refuses a wrong length", () => {
    expect(() => fromBase64url(toBase64url(new Uint8Array(31)), 32)).toThrow(ConvoyError);
  });
});

describe("errors", () => {
  it("carry a fixed message, code and reason", () => {
    const error = new ConvoyError("TRUST_FAILURE", "rollback");
    expect(error.message).toBe("A signature, owner, chain or context check failed. (rollback)");
    expect(isConvoyError(error, "TRUST_FAILURE")).toBe(true);
    expect(isConvoyError(error, "STORE_ERROR")).toBe(false);
    expect(isConvoyError(new Error("x"))).toBe(false);
  });
});
