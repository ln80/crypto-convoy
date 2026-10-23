/**
 * Replay of wrap.v1.json, seal.v1.json and stream.v1.json (§3.1, §3.2, §3.4), with member keys bundles (§4.3).
 * SP-03: tampered or moved ciphertexts fail. SP-18: no partial data. SP-07: the bundle's anchor floor (D-48).
 */
import { describe, expect, it } from "vitest";
import { open, seal } from "../../src/blocks/seal.js";
import { streamDecrypt, streamDecryptChunks, streamEncrypt } from "../../src/blocks/stream.js";
import { unwrap, wrap } from "../../src/blocks/wrap.js";
import type { Label } from "../../src/encoding/labels.js";
import { createMemberKeys } from "../../src/records/member-keys.js";
import { openMemberKeysWrap, type MemberKeysWrap } from "../../src/records/member-keys-wrap.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { loadAttachment, loadVectors, tohex, toField, unhex, withRandom, type VectorField } from "../support/vectors.js";

interface WrapCase {
  name: string;
  label: Label;
  context: VectorField[];
  inputs: { key: string; nonce: string; plaintext: string };
  outputs: { ciphertext: string };
}
interface BundleCase {
  name: string;
  signingSeed: string;
  encryptionSecretKey: string;
  teamStateKey: string;
  floor?: { version: number; hash: string };
  plaintext: string;
  wrapped: { nonce: string; ciphertext: string };
  error?: string;
}
interface Wraps {
  cases: WrapCase[];
  bundles: { key: string; context: VectorField[]; cases: BundleCase[]; refused: BundleCase[] };
  tampered: (Partial<WrapCase> & { name: string; from: string; key?: string; nonce?: string; ciphertext?: string })[];
}
interface Seals {
  recipient: { secretKey: string; publicKey: string };
  cases: { name: string; label: Label; context: VectorField[]; body: string; sealed: string }[];
  refused: { name: string; label: Label; context: VectorField[]; sealed: string; error: string }[];
  lowOrderPublicKeys: { publicKey: string; error: string }[];
}
interface Streams {
  key: string;
  label: Label;
  context: VectorField[];
  cases: {
    name: string;
    plaintextLength: number;
    plaintextHash: string;
    ciphertextLength: number;
    ciphertextHash: string;
    ciphertext?: string;
    ciphertextFile?: string;
  }[];
}

const wraps = loadVectors<Wraps>("wrap.v1.json");
const seals = loadVectors<Seals>("seal.v1.json");
const streams = loadVectors<Streams>("stream.v1.json");

describe("wrap.v1", () => {
  it.each(wraps.cases)("$name", ({ label, context, inputs, outputs }) => {
    const suite = withRandom(cc1, unhex(inputs.nonce));
    const wrapped = wrap(suite, unhex(inputs.key), label, context.map(toField), unhex(inputs.plaintext));
    expect(tohex(wrapped.ciphertext)).toBe(outputs.ciphertext);
    expect(tohex(unwrap(cc1, unhex(inputs.key), label, context.map(toField), wrapped))).toBe(inputs.plaintext);
  });

  it.each(wraps.tampered)("SP-03: refuses $name", (tamper) => {
    const base = wraps.cases.find((c) => c.name === tamper.from)!;
    const run = () =>
      unwrap(cc1, unhex(tamper.key ?? base.inputs.key), tamper.label ?? base.label, (tamper.context ?? base.context).map(toField), {
        nonce: unhex(tamper.nonce ?? base.inputs.nonce),
        ciphertext: unhex(tamper.ciphertext ?? base.outputs.ciphertext),
      });
    expect(run).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });
});

describe("wrap.v1: member keys bundles (§4.3)", () => {
  const { key, cases, refused } = wraps.bundles;
  const [first] = cases;
  const signing = cc1.signingKeyPair(unhex(first!.signingSeed));
  const published = createMemberKeys(
    cc1,
    {
      teamId: "team-1", accountId: "acct-1", memberKeysVersion: 1, signingPublicKey: signing.publicKey,
      encryptionPublicKey: cc1.encryptionPublicKey(unhex(first!.encryptionSecretKey)), recoveryPublicKey: signing.publicKey, createdAt: 1,
    },
    signing.secretKey,
  );
  const record = (wrapped: BundleCase["wrapped"]): MemberKeysWrap => ({
    v: 1, suite: cc1, accountId: "acct-1", teamId: "team-1", memberKeysVersion: 1, accountKeyVersion: 1,
    wrappedKeys: { nonce: unhex(wrapped.nonce), ciphertext: unhex(wrapped.ciphertext) },
  });

  it.each(cases)("opens a $name", ({ wrapped, teamStateKey, floor }) => {
    const bundle = openMemberKeysWrap(record(wrapped), unhex(key), published);
    expect(tohex(bundle.teamStateKey)).toBe(teamStateKey);
    expect(bundle.floor ? { version: bundle.floor.version, hash: tohex(bundle.floor.hash) } : undefined).toEqual(floor);
  });

  it.each(refused)("refuses a $name", ({ wrapped, error }) => {
    expect(() => openMemberKeysWrap(record(wrapped), unhex(key), published)).toThrow(expect.objectContaining({ code: error }));
  });
});

describe("seal.v1", () => {
  const keyPair = { publicKey: unhex(seals.recipient.publicKey), secretKey: unhex(seals.recipient.secretKey) };

  it.each(seals.cases)("opens $name", ({ label, context, body, sealed }) => {
    expect(tohex(open(cc1, keyPair, label, context.map(toField), unhex(sealed)))).toBe(body);
  });

  it("round-trips a fresh seal", () => {
    const { label, context, body } = seals.cases[0]!;
    const sealed = seal(cc1, keyPair.publicKey, label, context.map(toField), unhex(body));
    expect(tohex(open(cc1, keyPair, label, context.map(toField), sealed))).toBe(body);
  });

  it.each(seals.refused)("SP-03: refuses $name", ({ label, context, sealed, error }) => {
    expect(() => open(cc1, keyPair, label, context.map(toField), unhex(sealed))).toThrow(
      expect.objectContaining({ code: error }),
    );
  });

  it.each(seals.lowOrderPublicKeys)("refuses to seal to low-order key $publicKey", ({ publicKey, error }) => {
    const { label, context, body } = seals.cases[0]!;
    expect(() => seal(cc1, unhex(publicKey), label, context.map(toField), unhex(body))).toThrow(
      expect.objectContaining({ code: error }),
    );
  });
});

describe("stream.v1", () => {
  const pattern = (length: number) => Uint8Array.from({ length }, (_, i) => i % 251);
  const key = unhex(streams.key);
  const context = streams.context.map(toField);
  const ciphertextOf = (c: Streams["cases"][number]) =>
    c.ciphertext !== undefined ? unhex(c.ciphertext) : loadAttachment(c.ciphertextFile!);

  it.each(streams.cases)("decrypts $name", (vector) => {
    const ciphertext = ciphertextOf(vector);
    expect(ciphertext.length).toBe(vector.ciphertextLength);
    expect(tohex(cc1.hash(ciphertext))).toBe(vector.ciphertextHash);
    const plaintext = streamDecrypt(cc1, key, streams.label, context, ciphertext);
    expect(plaintext.length).toBe(vector.plaintextLength);
    expect(tohex(cc1.hash(plaintext))).toBe(vector.plaintextHash);
  });

  it.each(streams.cases)("encrypts $name to the same layout", (vector) => {
    const { ciphertext, hash } = streamEncrypt(cc1, key, streams.label, context, pattern(vector.plaintextLength));
    expect(ciphertext.length).toBe(vector.ciphertextLength);
    expect(tohex(hash)).toBe(tohex(cc1.hash(ciphertext)));
  });

  it.each(streams.cases)("streams $name in uneven slices", async (vector) => {
    const ciphertext = ciphertextOf(vector);
    async function* slices() {
      for (let offset = 0; offset < ciphertext.length; offset += 1_000_003) yield ciphertext.subarray(offset, offset + 1_000_003);
    }
    const expected = { size: vector.ciphertextLength, hash: unhex(vector.ciphertextHash) };
    const chunks: Uint8Array[] = [];
    for await (const chunk of streamDecryptChunks(cc1, key, streams.label, context, slices(), expected)) chunks.push(chunk);
    const total = chunks.reduce((n, c) => n + c.length, 0);
    expect(total).toBe(vector.plaintextLength);
  });
});
