/**
 * SP-03: Encrypted data can't be modified or moved undetected.
 * Threats: TH-06, TH-29.
 */
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { streamEncrypt } from "../../src/blocks/stream.js";
import { openSharedItem } from "../../src/content/link-share.js";
import { string, u32 } from "../../src/encoding/canonical.js";
import { decodeLinkKey } from "../../src/encoding/link.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { team } from "../support/teams.js";

const text = (s: string) => new TextEncoder().encode(s);
const failed = expect.objectContaining({ code: "DECRYPTION_FAILED" });
const part = (itemId: string, index: number) => ({ type: "item-part", teamId: "team-1", itemId, index });

async function twoItems() {
  const t = await team("bob");
  await t.aliceTeam.createItem("item-1", [{ content: text("first"), meta: text("a") }, { content: text("second") }]);
  await t.aliceTeam.createItem("item-2", [{ content: text("other") }, { content: text("other 2") }]);
  const bob = t.members.bob!;
  return { ...t, bob, session: await bob.vault.openTeam("team-1") };
}

describe("SP-03: tampered or moved content fails to open", () => {
  it("opens an intact item", async () => {
    const { session } = await twoItems();
    const parts = await session.openItem("item-1");
    expect(parts.map((p) => new TextDecoder().decode(p.content))).toEqual(["first", "second"]);
    expect(new TextDecoder().decode(parts[0]!.meta)).toBe("a");
  });

  it("refuses a flipped bit in a part", async () => {
    const { bob, session } = await twoItems();
    const bytes = (await bob.store.getPart({ type: "item-part", teamId: "team-1", itemId: "item-1", index: 0 }))!;
    bytes[30]! ^= 1;
    bob.store.replacePart(part("item-1", 0), bytes);
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses a truncated part", async () => {
    const { bob, session } = await twoItems();
    const bytes = (await bob.store.getPart({ type: "item-part", teamId: "team-1", itemId: "item-1", index: 1 }))!;
    bob.store.replacePart(part("item-1", 1), bytes.subarray(0, bytes.length - 1));
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses parts swapped within an item, or taken from another item", async () => {
    const { bob, session } = await twoItems();
    const first = (await bob.store.getPart({ type: "item-part", teamId: "team-1", itemId: "item-1", index: 0 }))!;
    const second = (await bob.store.getPart({ type: "item-part", teamId: "team-1", itemId: "item-1", index: 1 }))!;
    bob.store.replacePart(part("item-1", 0), second).replacePart(part("item-1", 1), first);
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
    bob.store.reset();
    const foreign = (await bob.store.getPart({ type: "item-part", teamId: "team-1", itemId: "item-2", index: 0 }))!;
    bob.store.replacePart(part("item-1", 0), foreign);
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses a dropped part", async () => {
    const { bob, session } = await twoItems();
    const inner = bob.store.inner;
    bob.store.inner = { ...inner, getPart: async (key) => (key.index === 1 ? null : inner.getPart(key)) } as typeof inner;
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses an item record served under another id, or another item's manifest", async () => {
    const { bob, session } = await twoItems();
    const other = (await bob.store.get({ type: "item", teamId: "team-1", itemId: "item-2" })) as Record<string, unknown>;
    bob.store.replace({ type: "item", itemId: "item-1" }, other);
    await expect(session.openItem("item-1")).rejects.toEqual(expect.objectContaining({ code: "TRUST_FAILURE", reason: "context_mismatch" }));
    const mine = (await bob.store.inner.get({ type: "item", teamId: "team-1", itemId: "item-1" })) as Record<string, unknown>;
    bob.store.reset().replace({ type: "item", itemId: "item-1" }, { ...mine, wrappedManifest: other["wrappedManifest"] });
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses an item of another team, or of another version", async () => {
    const { bob, session, members } = await twoItems();
    const teamB = await members.alice!.vault.createTeam("team-2");
    await teamB.createItem("item-1", [{ content: text("b") }]);
    const foreign = await members.alice!.store.get({ type: "item", teamId: "team-2", itemId: "item-1" });
    bob.store.replace({ type: "item", teamId: "team-1", itemId: "item-1" }, { ...(foreign as object), teamId: "team-1" });
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
    const mine = (await bob.store.inner.get({ type: "item", teamId: "team-1", itemId: "item-1" })) as Record<string, unknown>;
    bob.store.reset().replace({ type: "item", itemId: "item-1" }, { ...mine, createdBy: "bob" });
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("refuses a valid stream re-encrypted by a holder of the item key: the manifest binds each part (D-16)", async () => {
    const { bob, session } = await twoItems();
    const itemKey = decodeLinkKey(await session.shareLinkKey("item-1"));
    const replacement = streamEncrypt(cc1, itemKey, "item-part", [string("team-1"), string("item-1"), u32(0)], text("forged"));
    bob.store.replacePart(part("item-1", 0), replacement.ciphertext);
    await expect(session.openItem("item-1")).rejects.toEqual(failed);
  });

  it("a share link key opens only its own item", async () => {
    const { session, w } = await twoItems();
    const link = await session.shareLinkKey("item-1");
    const ports = { suite: cc1, store: w.server.anonymous(), clock: w.clock, settings: sessionInternals(session).ports.settings };
    expect((await openSharedItem(ports, link, "team-1", "item-1")).length).toBe(2);
    await expect(openSharedItem(ports, link, "team-1", "item-2")).rejects.toEqual(failed);
  });
});
