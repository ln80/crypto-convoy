/**
 * Invariants of the building blocks (§1, §3).
 * SP-03: any changed byte, or a value moved to another context, fails to open.
 */
import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { open, seal } from "../../src/blocks/seal.js";
import { streamDecrypt, streamEncrypt } from "../../src/blocks/stream.js";
import { unwrap, wrap } from "../../src/blocks/wrap.js";
import { fromBase64url, toBase64url } from "../../src/encoding/base64url.js";
import { Reader, bytes, enc, string, u32, u64 } from "../../src/encoding/canonical.js";
import { cc1 } from "../../src/suites/cc1/index.js";

const flipped = (value: Uint8Array, index: number, bit: number) => {
  const out = Uint8Array.from(value);
  out[index % out.length]! ^= 1 << bit;
  return out;
};
const id = fc.string({ minLength: 1, maxLength: 20 });
const data = fc.uint8Array({ maxLength: 300 });
const key = cc1.randomBytes(32);
const fails = (code: string) => expect.objectContaining({ code });

describe("canonical encoding", () => {
  test.prop([id, fc.nat(0xffffffff), fc.maxSafeNat(), data])("round-trips", (s, n, big, b) => {
    const reader = new Reader(enc(string(s), u32(n), u64(big), bytes(b)));
    expect([reader.string(), reader.u32(), reader.u64(), [...reader.bytes()]]).toEqual([s, n, big, [...b]]);
    reader.end();
  });

  test.prop([id, data, fc.nat()])("refuses every truncation", (s, b, cut) => {
    const encoded = enc(string(s), bytes(b));
    const reader = new Reader(encoded.subarray(0, cut % encoded.length));
    expect(() => (reader.string(), reader.bytes(), reader.end())).toThrow(fails("MALFORMED_RECORD"));
  });

  test.prop([data])("base64url round-trips", (b) => {
    expect([...fromBase64url(toBase64url(b))]).toEqual([...b]);
  });
});

describe("SP-03: wrap", () => {
  test.prop([data, id])("round-trips", (plaintext, team) => {
    const wrapped = wrap(cc1, key, "item-key", [string(team)], plaintext);
    expect([...unwrap(cc1, key, "item-key", [string(team)], wrapped)]).toEqual([...plaintext]);
  });

  test.prop([data, fc.nat(), fc.nat(7), fc.boolean()])("refuses any flipped bit", (plaintext, index, bit, inNonce) => {
    const wrapped = wrap(cc1, key, "item-key", [string("t")], plaintext);
    const tampered = inNonce
      ? { ...wrapped, nonce: flipped(wrapped.nonce, index, bit) }
      : { ...wrapped, ciphertext: flipped(wrapped.ciphertext, index, bit) };
    expect(() => unwrap(cc1, key, "item-key", [string("t")], tampered)).toThrow(fails("DECRYPTION_FAILED"));
  });

  test.prop([data, id, id])("refuses another context", (plaintext, a, b) => {
    fc.pre(a !== b);
    const wrapped = wrap(cc1, key, "item-key", [string(a)], plaintext);
    expect(() => unwrap(cc1, key, "item-key", [string(b)], wrapped)).toThrow(fails("DECRYPTION_FAILED"));
  });
});

describe("SP-03: seal", () => {
  const pair = cc1.generateEncryptionKeyPair();
  test.prop([data, fc.nat(), fc.nat(7)])("round-trips and refuses any flipped bit", (body, index, bit) => {
    const sealed = seal(cc1, pair.publicKey, "grant-seal", [string("t")], body);
    expect([...open(cc1, pair, "grant-seal", [string("t")], sealed)]).toEqual([...body]);
    expect(() => open(cc1, pair, "grant-seal", [string("t")], flipped(sealed, index, bit))).toThrow(
      fails("DECRYPTION_FAILED"),
    );
  });

  test.prop([data, id])("refuses another context", (body, team) => {
    fc.pre(team !== "t");
    const sealed = seal(cc1, pair.publicKey, "grant-seal", [string("t")], body);
    expect(() => open(cc1, pair, "grant-seal", [string(team)], sealed)).toThrow(fails("DECRYPTION_FAILED"));
  });
});

describe("SP-03: stream", () => {
  test.prop([data, fc.nat(), fc.nat(7)])("round-trips and refuses any flipped bit", (plaintext, index, bit) => {
    const { ciphertext, hash } = streamEncrypt(cc1, key, "item-part", [u32(0)], plaintext);
    expect([...hash]).toEqual([...cc1.hash(ciphertext)]);
    expect([...streamDecrypt(cc1, key, "item-part", [u32(0)], ciphertext)]).toEqual([...plaintext]);
    expect(() => streamDecrypt(cc1, key, "item-part", [u32(0)], flipped(ciphertext, index, bit))).toThrow(
      fails("DECRYPTION_FAILED"),
    );
  });

  test.prop([data, fc.integer({ min: 1, max: 1000 })])("refuses another part index", (plaintext, index) => {
    const { ciphertext } = streamEncrypt(cc1, key, "item-part", [u32(0)], plaintext);
    expect(() => streamDecrypt(cc1, key, "item-part", [u32(index)], ciphertext)).toThrow(fails("DECRYPTION_FAILED"));
  });
});
