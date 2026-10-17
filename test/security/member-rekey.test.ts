/**
 * SP-12: Compromised member keys can be replaced.
 * Threats: TH-13, TH-37.
 */
import { describe, expect, it } from "vitest";
import { isConvoyError } from "../../src/errors.js";
import { accessOf, bundleOf, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

describe("SP-12: compromised member keys can be replaced", () => {
  it("a routine re-key is reported as such, and receives nothing until an owner rotates", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    const rekeyed = await bob.vault.openTeam("team-1");
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
    expect((await accessOf(members.alice!.store, "bob", 2))!.memberKeysVersion).toBe(1);
  });

  it("an approving rotation seals the new version to the new keys only", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const old = await bundleOf(bob.vault);
    await bob.vault.rekey("team-1");
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: [{ accountId: "bob", memberKeysVersion: 2 }] });

    const access = (await accessOf(bob.store, "bob", 2))!;
    expect(access.memberKeysVersion).toBe(2);
    const session = await bob.vault.openTeam("team-1");
    expect(session.state).toBe("ready");
    expect(session.currentVersion).toBe(2);

    // The old keys hold nothing for version 2: the roster seals it to the new keys only.
    expect(() => access.open(old.pairs.encryption)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
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
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: [{ accountId: "bob", memberKeysVersion: 2 }] });
    const session = await bob.vault.openTeam("team-1");
    expect(session.ownerChanges.at(-1)).toEqual({ version: 3, signer: "alice", added: [], removed: [], rekeyed: ["bob"] });
    await session.rotate({ keep: ["alice"] });
    expect(session.currentVersion).toBe(4);
  });

  it("an approval holds only for the keys the owner reviewed", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    const reviewed = await aliceTeam.memberRequest("bob");
    expect(reviewed).toMatchObject({ memberKeysVersion: 2, continuity: "routine" });
    // A session thief publishes newer keys after the owner's review.
    await bob.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 3 }, record: forgeMemberKeys("bob", 3, strangerKeys()) },
    ]);
    await expect(aliceTeam.rotate({ keep: ["bob"], approveRekeys: [reviewed] })).rejects.toSatisfy((e) => isConvoyError(e, "STALE_VERSION"));
    expect(aliceTeam.currentVersion).toBe(1);
  });

  it("an owner's own approval is pinned too, so newer keys can't take over their owner key", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = members.alice!;
    await alice.vault.rekey("team-1");
    await alice.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "alice", memberKeysVersion: 3 }, record: forgeMemberKeys("alice", 3, strangerKeys()) },
    ]);
    await expect(aliceTeam.rotate({ keep: ["bob"], approveRekeys: [{ accountId: "alice", memberKeysVersion: 2 }] })).rejects.toSatisfy((e) =>
      isConvoyError(e, "STALE_VERSION"),
    );
    expect(aliceTeam.currentVersion).toBe(1);
  });
});
