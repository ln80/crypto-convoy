/**
 * SP-12: Compromised member keys can be replaced.
 * SP-23: a re-key with the recovery phrase is proven.
 * Threats: TH-13, TH-37.
 */
import { describe, expect, it } from "vitest";
import { isConvoyError } from "../../src/errors.js";
import { hasValidRecoveryProof } from "../../src/records/member-keys.js";
import { accessOf, bundleOf, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { requestOf, team } from "../support/teams.js";

describe("SP-12: compromised member keys can be replaced", () => {
  it("a re-key without the phrase is unproven, and receives nothing until an owner rotates", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    const rekeyed = await bob.vault.openTeam("team-1");
    expect(rekeyed.state).toBe("ready"); // still reading with the old keys
    expect(await requestOf(aliceTeam.owner(), "bob")).toMatchObject({
      status: "rekey-awaiting-approval",
      keys: { accountId: "bob", memberKeysVersion: 2 },
      proof: "none",
    });
    expect((await accessOf(bob.store, "bob", aliceTeam.currentVersion))!.memberKeysVersion).toBe(1);
  });

  it("keys only their own holder vouches for are never approved by a rotation that doesn't name them", async () => {
    const { members, aliceTeam } = await team("bob");
    const stolen = await bundleOf(members.bob!.vault);
    const attacker = strangerKeys();
    await members.bob!.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, attacker) },
    ]);
    expect((await requestOf(aliceTeam.owner(), "bob")).proof).toBe("none");
    const { version } = await aliceTeam.owner().rotate({ keep: ["bob"] });
    expect((await accessOf(members.alice!.store, "bob", version))!.memberKeysVersion).toBe(1);
  });

  it("an approving rotation seals the new version to the new keys only", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const old = await bundleOf(bob.vault);
    await bob.vault.rekey("team-1");
    const { version } = await aliceTeam.owner().rotate({ keep: ["bob"], approve: [{ accountId: "bob", memberKeysVersion: 2 }] });

    const access = (await accessOf(bob.store, "bob", version))!;
    expect(access.memberKeysVersion).toBe(2);
    const session = await bob.vault.openTeam("team-1");
    expect(session.state).toBe("ready");
    expect(session.currentVersion).toBe(version);

    // The old keys hold nothing for the new version: the roster seals it to the new keys only.
    expect(() => access.open(old.pairs.encryption)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });

  it("the vault deletes the replaced keys once the new ones are approved, and the team still opens (§6.8 step 4)", async () => {
    const { w, members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const wraps = async () =>
      (await bob.store.list({ type: "member-keys-wrap", accountId: "bob", accountKeyVersion: 1 })).map((j) => (j as { memberKeysVersion: number }).memberKeysVersion);
    await bob.vault.rekey("team-1");
    (await bob.vault.openTeam("team-1")).close();
    expect(await wraps()).toEqual([1, 2]); // not approved yet: the old keys still read

    await aliceTeam.owner().rotate({ keep: ["bob"], approve: [{ accountId: "bob", memberKeysVersion: 2 }] });
    const session = await bob.vault.openTeam("team-1");
    expect(session.state).toBe("ready");
    expect(await wraps()).toEqual([2]);
    // The team state was rewritten under the remaining keys: every later open still verifies.
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    const phone = await w.device("bob");
    await phone.vault.unlockWithPin("1234");
    expect((await phone.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("keys replaced without proof from the current ones are flagged as unproven", async () => {
    const { members, aliceTeam } = await team("bob");
    await members.bob!.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) },
    ]);
    expect((await requestOf(aliceTeam.owner(), "bob")).proof).toBe("none");
  });

  it("an owner's re-key also replaces their signing key in the owner list", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob"] });
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    await aliceTeam.owner().rotate({ keep: ["bob"], approve: [{ accountId: "bob", memberKeysVersion: 2 }] });
    const session = await bob.vault.openTeam("team-1");
    expect(session.ownerChanges.at(-1)).toEqual({ version: 4, signer: "alice", added: [], removed: [], rekeyed: ["bob"] });
    await session.owner().rotate({ keep: ["alice"] });
    expect(session.currentVersion).toBe(5);
  });

  it("an approval holds only for the keys the owner reviewed", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    const reviewed = (await requestOf(aliceTeam.owner(), "bob")).keys!;
    expect(reviewed).toEqual({ accountId: "bob", memberKeysVersion: 2 });
    // A session thief publishes newer keys after the owner's review.
    await bob.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 3 }, record: forgeMemberKeys("bob", 3, strangerKeys()) },
    ]);
    await expect(aliceTeam.owner().rotate({ keep: ["bob"], approve: [reviewed] })).rejects.toSatisfy((e) => isConvoyError(e, "STALE_VERSION"));
    expect(aliceTeam.currentVersion).toBe(2);
  });

  it("an owner's own approval is pinned too, so newer keys can't take over their owner key", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = members.alice!;
    await alice.vault.rekey("team-1");
    await alice.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "alice", memberKeysVersion: 3 }, record: forgeMemberKeys("alice", 3, strangerKeys()) },
    ]);
    await expect(aliceTeam.owner().rotate({ keep: ["bob"], approve: [{ accountId: "alice", memberKeysVersion: 2 }] })).rejects.toSatisfy((e) =>
      isConvoyError(e, "STALE_VERSION"),
    );
    expect(aliceTeam.currentVersion).toBe(2);
  });

  it("a re-key with the recovery phrase carries the proof; another phrase is refused (SP-23)", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    const held = await bundleOf(bob.vault);
    const { recoveryPhrase: other } = await w.account("mallory");
    await expect(bob.vault.rekey("team-1", { phrase: other })).rejects.toSatisfy((e) => isConvoyError(e, "WRONG_CREDENTIAL"));
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    const rekeyed = await bundleOf(bob.vault);
    expect(hasValidRecoveryProof(rekeyed.published, held.published.recoveryPublicKey)).toBe(true);
  });
});
