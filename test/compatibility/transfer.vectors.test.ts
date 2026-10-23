/**
 * Replay of transfer.v1.json and part-ref.v1.json (§3.8, §3.9).
 * SP-02: a transfer opens only for its receiver, account and team. SP-21: keyed part references.
 */
import { describe, expect, it } from "vitest";
import { partRef, partRefKey, partRefStream } from "../../src/blocks/part-ref.js";
import { decodeRequest, openTransfer } from "../../src/records/transfer.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { loadVectors, tohex, unhex } from "../support/vectors.js";

interface Transfers {
  receiver: { secretKey: string; publicKey: string; request: string };
  context: { accountId: string; teamId: string };
  valid: { name: string; transfer: string; bundles: Record<string, unknown>[] }[];
  refused: { name: string; transfer: string; error: string }[];
  refusedRequests: { name: string; request: string; error: string }[];
}
interface PartRefs {
  cases: { name: string; contentKey: string; content: string | { length: number }; refKey: string; partRef: string }[];
}

const t = loadVectors<Transfers>("transfer.v1.json");
const refs = loadVectors<PartRefs>("part-ref.v1.json");
const receiver = { publicKey: unhex(t.receiver.publicKey), secretKey: unhex(t.receiver.secretKey) };

describe("transfer.v1", () => {
  it("decodes the request", () => expect(tohex(decodeRequest(cc1, t.receiver.request))).toBe(t.receiver.publicKey));

  it.each(t.valid)("opens $name", ({ transfer, bundles }) => {
    const opened = openTransfer(cc1, receiver, t.context, transfer);
    const hexed = opened.map(({ floor, ...b }) => ({
      ...b,
      signingSeed: tohex(b.signingSeed),
      encryptionSecretKey: tohex(b.encryptionSecretKey),
      teamStateKey: tohex(b.teamStateKey),
      ...(floor ? { floor: { version: floor.version, hash: tohex(floor.hash) } } : {}),
    }));
    expect(hexed).toEqual(bundles);
  });

  it.each(t.refused)("SP-02: refuses a transfer $name", ({ transfer, error }) => {
    expect(() => openTransfer(cc1, receiver, t.context, transfer)).toThrow(expect.objectContaining({ code: error }));
  });

  it.each(t.refusedRequests)("refuses a request with $name", ({ request, error }) => {
    expect(() => decodeRequest(cc1, request)).toThrow(expect.objectContaining({ code: error }));
  });
});

describe("part-ref.v1", () => {
  const contentOf = (c: PartRefs["cases"][number]["content"]) =>
    typeof c === "string" ? unhex(c) : Uint8Array.from({ length: c.length }, (_, i) => i % 251);

  it.each(refs.cases)("$name", async ({ contentKey, content, refKey, partRef: expected }) => {
    const key = partRefKey(cc1, unhex(contentKey));
    expect(tohex(key)).toBe(refKey);
    const bytes = contentOf(content);
    expect(partRef(cc1, key, bytes)).toBe(expected);
    async function* chunks() {
      for (let i = 0; i < bytes.length; i += 1_000_000) yield bytes.subarray(i, i + 1_000_000);
    }
    expect(await partRefStream(cc1, key, chunks())).toBe(expected);
  });
});
