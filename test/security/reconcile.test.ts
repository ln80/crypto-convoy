/**
 * SP-22: Automatic owner actions never widen access; an owner's own re-key self-approves (D-47).
 * Threats: TH-14, TH-17, TH-37.
 */
import { describe, expect, it } from "vitest";
import { StoreConflictError } from "../../src/errors.js";
import { accessOf, bundleOf, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

describe("SP-22: reconcile only narrows access by itself", () => {
  it("rotates out a holder who is no longer active", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toEqual({ dryRun: false, rotatedTo: 3, removed: ["carol"], approvedRekeys: [], needsHuman: [] });
    expect((await members.carol!.vault.openTeam("team-1")).state).toBe("pending");
    expect(await accessOf(members.alice!.store, "carol", 3)).toBeNull();
    // Nothing left to do: a second run writes nothing.
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ removed: [], needsHuman: [] });
    expect(aliceTeam.currentVersion).toBe(3);
  });

  it("never re-grants a removed member the server lists as active again", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().reconcile(["alice"]);
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report.rotatedTo).toBeUndefined();
    expect(report.needsHuman).toEqual([{ accountId: "bob", reason: "outdated", keys: expect.objectContaining({ accountId: "bob", memberKeysVersion: 1 }), proof: "none" }]);
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("pending");
  });

  it("leaves unproven re-keys, owners' re-keys and inactive owners to a human", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    await aliceTeam.owner().setOwners(["alice", "bob"]);
    await members.carol!.vault.rekey("team-1"); // continuity only
    await members.bob!.vault.rekey("team-1", { phrase: members.bob!.recoveryPhrase }); // proven, but an owner
    const report = await aliceTeam.owner().reconcile(["alice", "carol"]);
    expect(report.rotatedTo).toBeUndefined();
    expect(report.needsHuman.map(({ accountId, reason }) => [accountId, reason])).toEqual([
      ["bob", "inactive-owner"],
      ["carol", "rekey-unproven"],
    ]);
    const active = await aliceTeam.owner().reconcile(["alice", "bob", "carol"]);
    expect(active.needsHuman.map(({ accountId, reason }) => [accountId, reason])).toEqual([
      ["bob", "owner-rekey"],
      ["carol", "rekey-unproven"],
    ]);
    expect(aliceTeam.owners()).toEqual(["alice", "bob"]);
  });

  it("keys a session thief publishes are never approved by reconcile", async () => {
    const { members, aliceTeam } = await team("bob");
    await members.bob!.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) },
    ]);
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven", proof: "none" }] });
    expect(aliceTeam.currentVersion).toBe(2);
  });

  it("a join without an accepted proof waits for a human", async () => {
    const { aliceTeam, w } = await team();
    const dave = await w.account("dave");
    await dave.vault.joinTeam("team-1");
    const report = await aliceTeam.owner().reconcile(["alice", "dave"]);
    expect(report).toMatchObject({ needsHuman: [{ accountId: "dave", reason: "awaiting-approval", proof: "none" }] });
  });

  it("a dry run returns the plan and writes nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    const before = members.alice!.store.commits.length;
    expect(await aliceTeam.owner().reconcile(["alice"], { dryRun: true })).toEqual({
      dryRun: true,
      rotatedTo: 3,
      removed: ["bob"],
      approvedRekeys: [],
      needsHuman: [],
    });
    expect(members.alice!.store.commits.length).toBe(before);
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("when another owner wrote first, it reloads and plans once more", async () => {
    const { members, aliceTeam } = await team("bob");
    let refused = false;
    members.alice!.store.onCommit((ops) => {
      if (!refused && ops.some((op) => op.op === "create" && op.key.type === "team-key-version")) {
        refused = true;
        throw new StoreConflictError("version must be current + 1");
      }
    });
    expect(await aliceTeam.owner().reconcile(["alice"])).toMatchObject({ rotatedTo: 3, removed: ["bob"] });
    expect(refused).toBe(true);
  });

  it("an object kept after its owner was removed can't act", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    await aliceTeam.owner().setOwners(["alice", "bob"]);
    const stale = aliceTeam.owner();
    await (await members.bob!.vault.openTeam("team-1")).owner().setOwners(["bob"]);
    // Its session still shows alice as an owner: the server refuses the write, reconcile reloads and stops.
    await expect(stale.reconcile(["alice", "bob"])).rejects.toEqual(expect.objectContaining({ code: "NOT_AN_OWNER" }));
    expect((await members.carol!.vault.openTeam("team-1")).state).toBe("ready");
    const reloaded = await members.alice!.vault.openTeam("team-1");
    expect(() => reloaded.owner()).toThrow(expect.objectContaining({ code: "NOT_AN_OWNER" }));
  });

  it("D-47: the caller's own re-key is approved when its session holds the keys, in a single-owner team too", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = members.alice!;
    const before = (await bundleOf(alice.vault)).published.signingPublicKey;
    await alice.vault.rekey("team-1");
    const session = await alice.vault.openTeam("team-1");
    expect(await session.owner().reconcile(["alice", "bob"])).toMatchObject({ rotatedTo: aliceTeam.currentVersion + 1, approvedRekeys: ["alice"], needsHuman: [] });
    const seen = await members.bob!.vault.openTeam("team-1");
    expect(seen.ownerChanges.at(-1)).toMatchObject({ signer: "alice", rekeyed: ["alice"] });
    expect(seen.owners()).toEqual(["alice"]);
    // The previous owner key is out of the owner list.
    const current = await accessOf(alice.store, "alice", seen.currentVersion);
    expect(current).not.toBeNull();
    expect(Buffer.from((await bundleOf(alice.vault)).published.signingPublicKey).equals(Buffer.from(before))).toBe(false);
  });

  it("D-47: keys published under the caller by someone else are left to a human", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = members.alice!;
    await alice.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "alice", memberKeysVersion: 2 }, record: forgeMemberKeys("alice", 2, strangerKeys()) },
    ]);
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "alice", reason: "owner-rekey" }] });
  });

  it("D-47: another owner's re-key stays with a human, even when proven", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"]);
    await members.bob!.vault.rekey("team-1", { phrase: members.bob!.recoveryPhrase });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "owner-rekey" }] });
  });
});

describe("SP-22: keys published during reconcile never stop its removals (D-64, review 032 B)", () => {
  it("a member publishing newer proven keys mid-run keeps the version with the keys it holds; the inactive holder is removed", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    const bob = members.bob!;
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    // When the owner re-reads bob's keys to approve them, bob has just published newer ones.
    const store = members.alice!.store;
    const inner = store.inner;
    let armed = true;
    store.inner = {
      ...inner,
      get: (key) => inner.get(key),
      getAccountKeyVersion: (id) => inner.getAccountKeyVersion(id),
      commit: (ops) => inner.commit(ops),
      list: async (query) => {
        if (armed && query.type === "member-keys" && "accountId" in query && query.accountId === "bob") {
          armed = false;
          await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
        }
        return inner.list(query);
      },
    };
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ rotatedTo: 3, removed: ["carol"], approvedRekeys: [] });
    expect(armed).toBe(false);
    expect(await accessOf(members.alice!.store, "carol", 3)).toBeNull();
    // bob still holds version 3 with the keys it held.
    expect(await accessOf(members.alice!.store, "bob", 3)).not.toBeNull();
    expect((await bob.vault.openTeam("team-1")).currentVersion).toBe(3);
  });

  it("with nothing left once the stale approval is dropped, no version is written", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    const store = members.alice!.store;
    const inner = store.inner;
    let armed = true;
    store.inner = {
      ...inner,
      get: (key) => inner.get(key),
      getAccountKeyVersion: (id) => inner.getAccountKeyVersion(id),
      commit: (ops) => inner.commit(ops),
      list: async (query) => {
        if (armed && query.type === "member-keys" && "accountId" in query && query.accountId === "bob") {
          armed = false;
          await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
        }
        return inner.list(query);
      },
    };
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ removed: [], approvedRekeys: [] });
    expect(aliceTeam.currentVersion).toBe(2);
  });
});
