/**
 * D-27: a streamed part keeps memory near one chunk, whatever the part's size. Coarse bound:
 * the source is generated lazily and the ciphertext discarded, so growth is the library's own.
 */
import { describe, expect, it } from "vitest";
import { team } from "../support/teams.js";

const MiB = 1024 * 1024;

describe("streamed parts keep memory flat", () => {
  it("encrypts a 64 MiB part with less than 24 MiB of growth", async () => {
    expect(global.gc, "run with --expose-gc").toBeDefined();
    const { aliceTeam } = await team();
    const draft = aliceTeam.beginItem();
    async function* source() {
      for (let i = 0; i < 64; i++) yield new Uint8Array(MiB).fill(i);
    }
    global.gc?.();
    const before = process.memoryUsage().arrayBuffers;
    let peak = before;
    let size = 0;
    for await (const chunk of draft.addPartStream(source())) {
      size += chunk.length;
      global.gc?.();
      peak = Math.max(peak, process.memoryUsage().arrayBuffers);
    }
    expect(size).toBeGreaterThan(64 * MiB);
    expect(peak - before).toBeLessThan(24 * MiB);
    await draft.seal("big");
  }, 60_000);
});
