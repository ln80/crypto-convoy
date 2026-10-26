/**
 * SP-06: A removed member can't open items encrypted after a rotation.
 * Threats: TH-14.
 */
import { vaultInternals } from "../../src/account/vault.js";
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { openItemKey, parseItem } from "../../src/records/item.js";
import { ContentStore, addParts, read } from "../support/content-store.js";
import { bundleOf } from "../support/forge.js";
import { accessOf } from "../support/forge.js";
import { team, keysHandle } from "../support/teams.js";


describe("SP-06: a removed member can't open what comes after the rotation", () => {
  it("nothing bob held opens the new version or items created with it", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    const bob = members.bob!;
    const bobSession = await bob.vault.openTeam("team-1");
    const held = { v1: await sessionInternals(bobSession).teamKey(1), bundle: await bundleOf(bob.vault), accountKey: vaultInternals(bob.vault).account().key };

    const { version } = await aliceTeam.owner().rotate({ keep: ["carol"] });
    await addParts(aliceTeam.beginItem(), new ContentStore(), "after", ["new secret"]).seal("after");

    // Bob's session and every key he held.
    await expect(bobSession.openItem("after")).rejects.toEqual(expect.objectContaining({ code: "NOT_GRANTED" }));
    expect((await bob.vault.openTeam("team-1")).state).toBe("pending");
    const item = parseItem(await bob.store.get({ type: "item", teamId: "team-1", itemId: "after" }), { teamId: "team-1", itemId: "after" });
    for (const key of [held.v1, held.accountKey]) {
      expect(() => openItemKey(item, key)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
    }
    expect(await accessOf(bob.store, "bob", version)).toBeNull();
    const carolAccess = (await accessOf(bob.store, "carol", version))!;
    expect(() => carolAccess.open(held.bundle.pairs.encryption)).toThrow();

    // Items from before stay readable: history is not protected (AS-07).
    expect((await members.carol!.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("forgetting someone in the keep list costs them access, never leaks it", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().rotate({ keep: [] });
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("pending");
    expect((await aliceTeam.owner().overview(["alice"])).warnings.map((x) => x.code)).not.toContain("rotation-needed");
  });

  it("the overview flags holders that are no longer active", async () => {
    const { aliceTeam } = await team("bob");
    const codes = async (active: string[]) => (await aliceTeam.owner().overview(active)).warnings.map((x) => x.code);
    expect(await codes(["alice", "bob"])).not.toContain("rotation-needed");
    expect(await codes(["alice"])).toContain("rotation-needed");
  });

  it("Limit: re-admitting the member in a later rotation opens the gap", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().rotate({ keep: [] });
    const content = new ContentStore();
    await addParts(aliceTeam.beginItem(), content, "while-away", ["gap"]).seal("while-away");
    await aliceTeam.owner().approve([await keysHandle(aliceTeam, "bob", 1)]);
    const bob = await members.bob!.vault.openTeam("team-1");
    expect(bob.state).toBe("ready");
    expect(read(await (await bob.openItem("while-away")).part(0, content.get("while-away", 0)))).toBe("gap");
  });
});
