/**
 * SP-12: Compromised member keys can be replaced.
 * Threats: TH-13, TH-37.
 */
import { describe, expect, it } from "vitest";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { bundleOf, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

describe("SP-12: compromised member keys can be replaced", () => {
  it("a routine re-key is reported as such, and receives nothing until an owner rotates", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const rekeyed = await bob.vault.rekey("team-1");
    expect(rekeyed.state).toBe("ready"); // still reading with the old keys
    expect(await aliceTeam.memberRequest("bob")).toEqual({ accountId: "bob", memberKeysVersion: 2, continuity: "routine", granted: false });
    expect(await bob.store.list({ type: "grant", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 })).toEqual([]);
  });

  it("old keys signing their own replacement is a hint, never an approval", async () => {
    const { members, aliceTeam } = await team("bob");
    const stolen = await bundleOf(members.bob!.vault);
    const attacker = strangerKeys();
    await members.bob!.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, attacker, stolen.pairs) },
    ]);
    expect((await aliceTeam.memberRequest("bob")).continuity).toBe("routine");
    await aliceTeam.rotate({ keep: ["bob"] });
    const grants = await members.alice!.store.list({ type: "grant", teamId: "team-1", accountId: "bob", teamKeyVersion: 2 });
    expect(grants.map((g) => (g as { memberKeysVersion: number }).memberKeysVersion)).toEqual([1]);
  });

  it("an approving rotation seals the new version to the new keys only", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const old = await bundleOf(bob.vault);
    await bob.vault.rekey("team-1");
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: ["bob"] });

    const grants = await bob.store.list({ type: "grant", teamId: "team-1", accountId: "bob", teamKeyVersion: 2 });
    expect(grants.map((g) => (g as { memberKeysVersion: number }).memberKeysVersion)).toEqual([2]);
    const session = await bob.vault.openTeam("team-1");
    expect(session.state).toBe("ready");
    expect(session.currentVersion).toBe(2);

    // The old keys hold nothing for version 2: the only grant is sealed to the new keys.
    const grant = parseGrant(grants[0], { teamId: "team-1", accountId: "bob" });
    expect(() => openGrant(grant, old.pairs.encryption)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });

  it("keys replaced without proof from the current ones are flagged as unproven", async () => {
    const { members, aliceTeam } = await team("bob");
    await members.bob!.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) },
    ]);
    expect((await aliceTeam.memberRequest("bob")).continuity).toBe("unproven");
  });

  it("an owner's re-key also replaces their signing key in the owner list", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.setOwners(["alice", "bob"], { keep: ["bob"] });
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: ["bob"] });
    const session = await bob.vault.openTeam("team-1");
    expect(session.ownerChanges.at(-1)).toEqual({ version: 3, signer: "alice", added: [], removed: [], rekeyed: ["bob"] });
    await session.rotate({ keep: ["alice"] });
    expect(session.currentVersion).toBe(4);
  });
});
