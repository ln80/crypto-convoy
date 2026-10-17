/** Suite cc1: strict Ed25519 and X25519 checks of §2, bounds, randomness source. */
import { ed25519 } from "@noble/curves/ed25519.js";
import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it } from "vitest";
import { ARGON2_BOUNDS, cc1 } from "../../src/suites/cc1/index.js";
import { ED25519_SMALL_ORDER, X25519_LOW_ORDER, inList, isCanonicalScalar } from "../../src/suites/cc1/small-order.js";
import { CURRENT_SUITE, suiteFor } from "../../src/suites/registry.js";
import { tohex, unhex } from "../support/vectors.js";

const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const toLe = (n: bigint) => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const fromLe = (b: Uint8Array) => b.reduceRight((n, byte) => (n << 8n) | BigInt(byte), 0n);

const keyPair = cc1.signingKeyPair(cc1.generateSigningSeed());
const message = new TextEncoder().encode("message");
const signature = cc1.sign(keyPair.secretKey, message);

describe("strict Ed25519 (§2)", () => {
  it("accepts a valid signature", () => expect(cc1.verify(keyPair.publicKey, message, signature)).toBe(true));

  it("refuses a non-canonical S (S + L)", () => {
    const forged = Uint8Array.from(signature);
    forged.set(toLe(fromLe(signature.subarray(32)) + L), 32);
    expect(cc1.verify(keyPair.publicKey, message, forged)).toBe(false);
  });

  it("isCanonicalScalar is exactly S < L", () => {
    expect(isCanonicalScalar(toLe(L - 1n))).toBe(true);
    expect(isCanonicalScalar(toLe(L))).toBe(false);
    expect(isCanonicalScalar(toLe(L + 1n))).toBe(false);
    expect(isCanonicalScalar(toLe(0n))).toBe(true);
  });

  it.each(ED25519_SMALL_ORDER.map(tohex))("refuses small-order R %s", (r) => {
    const forged = Uint8Array.from(signature);
    forged.set(unhex(r), 0);
    expect(cc1.verify(keyPair.publicKey, message, forged)).toBe(false);
  });

  it.each(ED25519_SMALL_ORDER.map(tohex))("refuses small-order public key %s", (pk) => {
    expect(cc1.isValidSigningPublicKey(unhex(pk))).toBe(false);
  });

  it("refuses a mixed-order public key (valid key plus a torsion point)", () => {
    const torsion = ed25519.Point.fromBytes(ED25519_SMALL_ORDER[2]!);
    const mixed = ed25519.Point.fromBytes(keyPair.publicKey).add(torsion).toBytes();
    expect(cc1.isValidSigningPublicKey(mixed)).toBe(false);
  });

  it("refuses wrong lengths", () => {
    expect(cc1.verify(keyPair.publicKey.subarray(1), message, signature)).toBe(false);
    expect(cc1.verify(keyPair.publicKey, message, signature.subarray(1))).toBe(false);
  });

  it("the small-order list is exactly the 8-torsion, sign bit ignored", () => {
    for (const entry of ED25519_SMALL_ORDER.slice(0, 5)) {
      expect(ed25519.Point.fromBytes(entry).isSmallOrder()).toBe(true);
    }
    for (const entry of ED25519_SMALL_ORDER) {
      const signBit = Uint8Array.from(entry);
      signBit[31]! |= 0x80;
      expect(inList(ED25519_SMALL_ORDER, signBit)).toBe(true);
    }
  });
});

describe("X25519 low-order keys (§2)", () => {
  it.each(X25519_LOW_ORDER.map(tohex))("%s gives an all-zero shared secret", (pk) => {
    expect(() => sodium.crypto_scalarmult(cc1.randomBytes(32), unhex(pk))).toThrow();
    expect(cc1.isLowOrder(unhex(pk))).toBe(true);
  });

  it("accepts a generated key", () => expect(cc1.isLowOrder(cc1.generateEncryptionKeyPair().publicKey)).toBe(false));

  it("recomputes the public key from the secret key", () => {
    const pair = cc1.generateEncryptionKeyPair();
    expect(tohex(cc1.encryptionPublicKey(pair.secretKey))).toBe(tohex(pair.publicKey));
  });
});

describe("Argon2id bounds (§2, D-17)", () => {
  const salt = new Uint8Array(16);
  const pin = new TextEncoder().encode("1234");
  it.each([
    ["opslimit below the floor", ARGON2_BOUNDS.minOpslimit - 1, ARGON2_BOUNDS.minMemlimit],
    ["opslimit above the ceiling", ARGON2_BOUNDS.maxOpslimit + 1, ARGON2_BOUNDS.minMemlimit],
    ["memlimit below the floor", ARGON2_BOUNDS.minOpslimit, ARGON2_BOUNDS.minMemlimit - 1],
    ["memlimit above the ceiling", ARGON2_BOUNDS.minOpslimit, ARGON2_BOUNDS.maxMemlimit + 1],
  ])("refuses %s", (_, ops, mem) => {
    expect(() => cc1.passwordHash(pin, salt, ops, mem)).toThrow(expect.objectContaining({ code: "MALFORMED_RECORD" }));
  });
});

describe("recovery phrase (§5.2)", () => {
  it("generates 12 valid words and derives a 64-byte seed", () => {
    const phrase = cc1.generateRecoveryPhrase();
    expect(phrase.split(" ")).toHaveLength(12);
    expect(cc1.recoverySeed(phrase)).toHaveLength(64);
    expect(tohex(cc1.recoverySeed(`  ${phrase.toUpperCase().toLowerCase()}  `))).toBe(tohex(cc1.recoverySeed(phrase)));
  });

  it("refuses a bad checksum or a wrong word count with WRONG_CREDENTIAL", () => {
    const words = cc1.generateRecoveryPhrase().split(" ");
    for (const phrase of [words.slice(0, 11).join(" "), "abandon ".repeat(12).trim(), "not a phrase"]) {
      expect(() => cc1.recoverySeed(phrase)).toThrow(expect.objectContaining({ code: "WRONG_CREDENTIAL" }));
    }
  });
});

describe("registry", () => {
  it("writes with cc1 and reads cc1", () => {
    expect(CURRENT_SUITE.id).toBe("cc1");
    expect(suiteFor("cc1")).toBe(cc1);
  });
});
