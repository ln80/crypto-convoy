/**
 * Replay of canonical.v1.json and link.v1.json (§1, §3.5).
 * SP-17: unknown link prefixes are refused.
 */
import { describe, expect, it } from "vitest";
import { Reader, enc } from "../../src/encoding/canonical.js";
import { decodeAnchor, decodeInvite, decodeLinkKey, encodeAnchor, encodeInvite, encodeLinkKey } from "../../src/encoding/link.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { loadVectors, tohex, toField, unhex, type VectorField } from "../support/vectors.js";

interface Canonical {
  cases: { name: string; fields: VectorField[]; encoded: string }[];
  refused: { name: string; read: string; encoded: string }[];
}
interface Links {
  valid: { name: string; kind: string; value: string; bytes?: string; version?: number; hash?: string; inviteId?: string; secret?: string }[];
  refused: { name: string; kind: string; value: string; error: string }[];
}

const canonical = loadVectors<Canonical>("canonical.v1.json");
const links = loadVectors<Links>("link.v1.json");

describe("canonical.v1", () => {
  it.each(canonical.cases)("$name", ({ fields, encoded }) => {
    expect(tohex(enc(...fields.map(toField)))).toBe(encoded);
  });

  const readers: Record<string, (r: Reader) => unknown> = {
    u32: (r) => r.u32(),
    u64: (r) => r.u64(),
    bytes: (r) => r.bytes(),
    string: (r) => r.string(),
    "optional-u8": (r) => r.optional((inner) => inner.u8()),
  };
  it.each(canonical.refused)("refuses $name", ({ read, encoded }) => {
    const reader = new Reader(unhex(encoded));
    expect(() => {
      readers[read]!(reader);
      reader.end();
    }).toThrow(expect.objectContaining({ code: "MALFORMED_RECORD" }));
  });
});

/** The checks a reader applies to each kind of link value (§3.5, §2). */
function decode(kind: string, value: string) {
  if (kind === "anchor") return decodeAnchor(value);
  if (kind === "invite") return decodeInvite(value);
  const key = decodeLinkKey(value);
  if (kind === "inbox-key" && cc1.isLowOrder(key)) throw new Error("low order not refused");
  return key;
}

describe("link.v1", () => {
  it.each(links.valid)("decodes and re-encodes $name", (vector) => {
    if (vector.kind === "invite") {
      const invite = decodeInvite(vector.value);
      expect(invite.anchor.version).toBe(vector.version);
      expect(tohex(invite.anchor.hash)).toBe(vector.hash);
      expect(invite.inviteId).toBe(vector.inviteId);
      expect(tohex(invite.secret)).toBe(vector.secret);
      expect(encodeInvite(invite)).toBe(vector.value);
    } else if (vector.kind === "anchor") {
      const anchor = decodeAnchor(vector.value);
      expect(anchor.version).toBe(vector.version);
      expect(tohex(anchor.hash)).toBe(vector.hash);
      expect(encodeAnchor(anchor)).toBe(vector.value);
    } else {
      expect(tohex(decodeLinkKey(vector.value))).toBe(vector.bytes);
      expect(encodeLinkKey(unhex(vector.bytes!))).toBe(vector.value);
    }
  });

  it.each(links.refused.filter((v) => v.name !== "low-order inbox key" && !v.name.startsWith("low-order")))(
    "SP-17 / SP-18: refuses $name with $error",
    ({ kind, value, error }) => {
      expect(() => decode(kind, value)).toThrow(expect.objectContaining({ code: error }));
    },
  );

  it.each(links.refused.filter((v) => v.name.startsWith("low-order")))("flags $name as low order", ({ value }) => {
    expect(cc1.isLowOrder(decodeLinkKey(value))).toBe(true);
  });
});
