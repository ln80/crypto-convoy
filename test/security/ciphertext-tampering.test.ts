/**
 * SP-03: Encrypted data can't be modified or moved undetected.
 * Threats: TH-06, TH-29.
 */
import { describe, expect, it } from "vitest";
import { streamEncrypt } from "../../src/blocks/stream.js";
import { u32 } from "../../src/encoding/canonical.js";
import { decodeLinkKey } from "../../src/encoding/link.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { ContentStore, addParts, read } from "../support/content-store.js";
import { outsider } from "../support/link-client.js";
import { team } from "../support/teams.js";

const failed = expect.objectContaining({ code: "DECRYPTION_FAILED" });
const itemKey = (itemId: string) => ({ type: "item", teamId: "team-1", itemId }) as const;

async function twoItems() {
  const t = await team("bob");
  const content = new ContentStore();
  await addParts(t.aliceTeam.beginItem(), content, "item-1", [{ content: "first", meta: "a" }, "second"]).seal("item-1");
  await addParts(t.aliceTeam.beginItem(), content, "item-2", ["other", "other 2"]).seal("item-2");
  const bob = t.members.bob!;
  return { ...t, bob, content, session: await bob.vault.openTeam("team-1") };
}

describe("SP-03: tampered or moved content fails to open", () => {
  it("opens an intact item, part by part", async () => {
    const { session, content } = await twoItems();
    const opened = await session.openItem("item-1");
    expect(opened.parts.map((p) => read(p.meta))).toEqual(["a", ""]);
    expect(read(await opened.part(0, content.get("item-1", 0)))).toBe("first");
    expect(read(await opened.part(1, content.fetcher("item-1", 1)))).toBe("second");
  });

  it("refuses a flipped bit or a truncated part", async () => {
    const { session, content } = await twoItems();
    const opened = await session.openItem("item-1");
    const flipped = content.get("item-1", 0);
    flipped[30]! ^= 1;
    await expect(opened.part(0, flipped)).rejects.toEqual(failed);
    await expect(opened.part(1, content.get("item-1", 1).subarray(0, -1))).rejects.toEqual(failed);
  });

  it("refuses parts swapped within an item", async () => {
    const { session, content } = await twoItems();
    const opened = await session.openItem("item-1");
    await expect(opened.part(0, content.get("item-1", 1))).rejects.toEqual(failed);
    await expect(opened.part(1, content.get("item-1", 0))).rejects.toEqual(failed);
  });

  it("refuses a part of another item, even at the same index (D-26)", async () => {
    const { session, content } = await twoItems();
    const opened = await session.openItem("item-1");
    await expect(opened.part(0, content.get("item-2", 0))).rejects.toEqual(failed);
  });

  it("refuses an item record served under another id, or with another item's manifest", async () => {
    const { bob, session } = await twoItems();
    const other = (await bob.store.get(itemKey("item-2"))) as Record<string, unknown>;
    bob.store.replace({ type: "item", itemId: "item-1" }, other);
    await expect(session.openItem("item-1")).rejects.toEqual(expect.objectContaining({ code: "TRUST_FAILURE", reason: "context_mismatch" }));
    const mine = (await bob.store.inner.get(itemKey("item-1"))) as Record<string, unknown>;
    bob.store.reset().replace({ type: "item", itemId: "item-1" }, { ...mine, wrappedManifest: other["wrappedManifest"] });
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses an item record of another team, or with changed fields", async () => {
    const { bob, session, members } = await twoItems();
    await members.alice!.vault.createTeam("team-2");
    const teamB = await members.alice!.vault.openTeam("team-2");
    const foreignDraft = teamB.beginItem();
    foreignDraft.addPart(new TextEncoder().encode("b"));
    await foreignDraft.seal("item-1");
    const foreign = await members.alice!.store.get({ type: "item", teamId: "team-2", itemId: "item-1" });
    bob.store.replace({ type: "item", teamId: "team-1", itemId: "item-1" }, { ...(foreign as object), teamId: "team-1" });
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
    const mine = (await bob.store.inner.get(itemKey("item-1"))) as Record<string, unknown>;
    bob.store.reset().replace({ type: "item", itemId: "item-1" }, { ...mine, createdBy: "bob" });
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses a valid stream re-encrypted by a holder of the item key: the manifest binds each part (D-16)", async () => {
    const { session } = await twoItems();
    const key = decodeLinkKey(await session.shareLinkKey("item-1"));
    const forged = streamEncrypt(cc1, key, "item-part", [u32(0)], new TextEncoder().encode("forged"));
    const opened = await session.openItem("item-1");
    await expect(opened.part(0, forged.ciphertext)).rejects.toEqual(failed);
  });

  it("a share link key opens only its own item", async () => {
    const { session, bob, content } = await twoItems();
    const link = await session.shareLinkKey("item-1");
    const client = await outsider();
    const record1 = await bob.store.get(itemKey("item-1"));
    const record2 = await bob.store.get(itemKey("item-2"));
    const shared = client.openSharedItem(link, "team-1", "item-1", record1);
    expect(read(await shared.part(1, content.get("item-1", 1)))).toBe("second");
    expect(() => client.openSharedItem(link, "team-1", "item-2", record2)).toThrow(failed);
    expect(() => client.openSharedItem(link, "team-1", "item-2", record1)).toThrow(expect.objectContaining({ reason: "context_mismatch" }));
  });

  it("refuses a misused draft: no parts, or a part after sealing", async () => {
    const { aliceTeam } = await twoItems();
    await expect(aliceTeam.beginItem().seal("empty")).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    const draft = aliceTeam.beginItem();
    draft.addPart(new Uint8Array([1]));
    await draft.seal("item-3");
    expect(() => draft.addPart(new Uint8Array([2]))).toThrow(/sealed/);
  });
});
