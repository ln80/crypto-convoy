/**
 * SP-18: Invalid input fails before crypto, and decryption never returns partial data.
 * Threats: TH-25.
 */
import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it } from "vitest";
import { streamDecrypt, streamDecryptChunks, streamEncrypt } from "../../src/blocks/stream.js";
import { string } from "../../src/encoding/canonical.js";
import { labelled } from "../../src/encoding/labels.js";
import { createVault } from "../../src/account/vault.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { FAST } from "../support/fixtures.js";
import { team } from "../support/teams.js";

const CHUNK = cc1.sizes.streamChunk;
const key = cc1.randomBytes(32);
const context = [string("team-1"), string("item-1")];
const ad = labelled("item-part", ...context);
const failed = expect.objectContaining({ code: "DECRYPTION_FAILED" });

/** A stream with chosen tags, built with raw libsodium to produce what the library never writes. */
function craft(chunks: [Uint8Array, number][]): Uint8Array {
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const parts = [header, ...chunks.map(([m, tag]) => sodium.crypto_secretstream_xchacha20poly1305_push(state, m, ad, tag))];
  return new Uint8Array(Buffer.concat(parts));
}
const { TAG_MESSAGE: MESSAGE, TAG_FINAL: FINAL } = {
  TAG_MESSAGE: sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
  TAG_FINAL: sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
};
const full = new Uint8Array(CHUNK).fill(7);

describe("SP-18: buffered stream decryption is all or nothing", () => {
  const twoChunks = streamEncrypt(cc1, key, "item-part", context, new Uint8Array(CHUNK + 10)).ciphertext;

  it.each([
    ["the header only", twoChunks.subarray(0, 24)],
    ["nothing", new Uint8Array(0)],
    ["one byte cut from the end", twoChunks.subarray(0, -1)],
    ["the final chunk dropped", twoChunks.subarray(0, 24 + CHUNK + 17)],
    ["a 16-byte final piece", twoChunks.subarray(0, twoChunks.length - 11)],
    ["a trailing byte", new Uint8Array([...twoChunks, 0])],
  ])("refuses %s", (_, ciphertext) => {
    expect(() => streamDecrypt(cc1, key, "item-part", context, ciphertext)).toThrow(failed);
  });

  it("refuses a stream without a FINAL tag", () => {
    expect(() => streamDecrypt(cc1, key, "item-part", context, craft([[full, MESSAGE], [full, MESSAGE]]))).toThrow(failed);
  });

  it("refuses a FINAL tag before the end", () => {
    expect(() => streamDecrypt(cc1, key, "item-part", context, craft([[full, FINAL], [new Uint8Array(3), FINAL]]))).toThrow(failed);
  });

  it("refuses a short non-final chunk", () => {
    expect(() => streamDecrypt(cc1, key, "item-part", context, craft([[new Uint8Array(10), MESSAGE], [new Uint8Array(10), FINAL]]))).toThrow(failed);
  });

  it.each([
    ["PUSH", sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH],
    ["REKEY", sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY],
  ])("refuses a %s tag", (_, tag) => {
    expect(() => streamDecrypt(cc1, key, "item-part", context, craft([[new Uint8Array(5), tag]]))).toThrow(failed);
  });

  it("refuses the right stream under another context", () => {
    const ciphertext = streamEncrypt(cc1, key, "item-part", context, new Uint8Array(5)).ciphertext;
    expect(() => streamDecrypt(cc1, key, "item-part", [string("team-1"), string("item-2")], ciphertext)).toThrow(failed);
    expect(() => streamDecrypt(cc1, key, "submission-part", context, ciphertext)).toThrow(failed);
  });
});

describe("SP-18: the streaming read yields only authenticated chunks and ends with an error", () => {
  const plaintext = new Uint8Array(2 * CHUNK + 5).fill(1);
  const { ciphertext, hash } = streamEncrypt(cc1, key, "item-part", context, plaintext);
  async function* source(bytes: Uint8Array) {
    for (let offset = 0; offset < bytes.length; offset += 65536) yield bytes.subarray(offset, offset + 65536);
  }
  async function collect(bytes: Uint8Array, expected = { size: ciphertext.length, hash }) {
    const received: Uint8Array[] = [];
    let error: unknown;
    try {
      for await (const chunk of streamDecryptChunks(cc1, key, "item-part", context, source(bytes), expected)) received.push(chunk);
    } catch (e) {
      error = e;
    }
    return { received, error };
  }

  it("delivers everything for an intact stream", async () => {
    const { received, error } = await collect(ciphertext);
    expect(error).toBeUndefined();
    expect(received.map((c) => c.length)).toEqual([CHUNK, CHUNK, 5]);
  });

  it("ends with DECRYPTION_FAILED when the last chunk is missing", async () => {
    const { received, error } = await collect(ciphertext.subarray(0, 24 + 2 * (CHUNK + 17)));
    expect(error).toEqual(failed);
    expect(received.every((c) => c.length === CHUNK)).toBe(true);
  });

  it("never releases the final chunk when the hash differs from the manifest", async () => {
    const { received, error } = await collect(ciphertext, { size: ciphertext.length, hash: new Uint8Array(32) });
    expect(error).toEqual(failed);
    expect(received).toHaveLength(2);
  });

  it("stops as soon as the data exceeds the manifest size", async () => {
    const { received, error } = await collect(ciphertext, { size: 100, hash });
    expect(error).toEqual(failed);
    expect(received).toHaveLength(0);
  });
});

describe("SP-18: the buffered API refuses oversized parts before downloading", () => {
  it("never fetches a part whose manifest size exceeds maxBufferedSize", async () => {
    const { members, aliceTeam, w } = await team("bob");
    await aliceTeam.createItem("big", [{ content: new Uint8Array(2000) }]);

    const fetched: unknown[] = [];
    const base = w.server.as("bob");
    const store = { ...base, getPart: async (key: never) => (fetched.push(key), base.getPart(key)) };
    const small = await createVault(
      { store, oprf: w.oprf, localKeys: members.bob!.localKeys, clock: w.clock, settings: { ...FAST, maxBufferedSize: 1000 } },
      "bob",
    );
    await small.unlock();
    const session = await small.openTeam("team-1");
    await expect(session.openItem("big")).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    expect(fetched).toEqual([]);

    const streamed = await session.openItemStream("big", 0);
    let total = 0;
    for await (const chunk of streamed.chunks) total += chunk.length;
    expect(total).toBe(2000);
  });
});
