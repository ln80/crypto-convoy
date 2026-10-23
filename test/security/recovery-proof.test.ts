/**
 * SP-23: A re-key proven by the recovery key is approved without an out-of-band check.
 * Threats: TH-10, TH-12, TH-13, TH-37, TH-41.
 */
import { describe, expect, it } from "vitest";
import { deriveRecoveryKeys } from "../../src/account/recovery-key.js";
import type { WireRecord, WriteOp } from "../../src/ports.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { replacePhrase } from "../support/fixtures.js";
import { accessOf, bundleOf, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

const create = (accountId: string, memberKeysVersion: number, record: WireRecord): WriteOp => ({
  op: "create",
  key: { type: "member-keys", teamId: "team-1", accountId, memberKeysVersion },
  record,
});

describe("SP-23: recovery-proven re-keys", () => {
  it("a re-key with the phrase is approved by reconcile; the old keys open nothing new", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const old = await bundleOf(bob.vault);
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    expect((await aliceTeam.owner().overview(["alice", "bob"])).accounts.find((a) => a.accountId === "bob")!.proof).toBe("recovery");

    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ rotatedTo: 3, approvedRekeys: ["bob"], needsHuman: [] });
    const access = (await accessOf(bob.store, "bob", 3))!;
    expect(access.memberKeysVersion).toBe(2);
    expect(() => access.open(old.pairs.encryption)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("a session thief without the phrase gets a hint at most", async () => {
    const { members, aliceTeam } = await team("bob");
    const stolen = await bundleOf(members.bob!.vault);
    await members.bob!.store.commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys()))]);
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven", proof: "none" }] });
  });

  it("a recovery signature by a key other than the held keys' one proves nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    // The thief signs with a recovery key of its own, and names it in the record.
    const own = cc1.signingKeyPair(cc1.randomBytes(32));
    await members.bob!.store.commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys(), { recoverySigner: own }))]);
    expect((await aliceTeam.owner().reconcile(["alice", "bob"])).needsHuman).toEqual([
      { accountId: "bob", reason: "rekey-unproven", keys: { accountId: "bob", memberKeysVersion: 2 }, proof: "none" },
    ]);
  });

  it("an owner's proven re-key still needs another owner's approval", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"]);
    await members.bob!.vault.rekey("team-1", { phrase: members.bob!.recoveryPhrase });
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "owner-rekey", proof: "recovery" }] });
    await aliceTeam.owner().approve([report.needsHuman[0]!.keys!]);
    expect((await members.bob!.vault.openTeam("team-1")).ownerChanges.at(-1)).toMatchObject({ rekeyed: ["bob"] });
  });

  it("Limit (TH-41): a leaked phrase proves the thief's keys, and the real member is cut out", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const held = await bundleOf(bob.vault);
    const { signing } = deriveRecoveryKeys(cc1, "bob", bob.recoveryPhrase);
    await bob.store.commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys(), { recovery: held.published.recoveryPublicKey, recoverySigner: signing }))]);
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
    // Detected, not prevented: bob's own keys hold nothing current any more.
    expect((await bob.vault.openTeam("team-1")).state).toBe("pending");
  });

  it("a phrase replaced with the PIN instead of the old one re-keys every team without proof (D-41)", async () => {
    const { members, aliceTeam } = await team("bob");
    const { report } = await replacePhrase(members.bob!.vault, { currentPin: members.bob!.pin });
    expect(report).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect((await aliceTeam.owner().reconcile(["alice", "bob"])).needsHuman).toMatchObject([{ accountId: "bob", reason: "rekey-unproven" }]);
  });

  it("a phrase replaced with the old one re-keys every team with proof", async () => {
    const { members, aliceTeam } = await team("bob");
    await replacePhrase(members.bob!.vault, { currentPhrase: members.bob!.recoveryPhrase });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"], needsHuman: [] });
  });

  it("D-49: a team re-keyed without proof is retried proven with the old phrase; an unrelated phrase is refused", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await replacePhrase(bob.vault, { currentPin: bob.pin });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven" }] });
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
    const other = (await team("x")).members.x!.recoveryPhrase;
    await expect(bob.vault.rekey("team-1", { phrase: other })).rejects.toMatchObject({ code: "WRONG_CREDENTIAL" });
  });
});

describe("SP-23: the server can't choose the recovery key a proof is checked against (review 009 A)", () => {
  it("a record served for a held version must have the roster's keys hash, else nothing is approved", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const attacker = strangerKeys();
    const fakeRecovery = cc1.signingKeyPair(cc1.randomBytes(32));
    // Bait at bob's next version, proven by the attacker's recovery key (A2, or A11 through the server rule).
    await w.server.as("bob").commit([create("bob", 2, forgeMemberKeys("bob", 2, attacker, { recoverySigner: fakeRecovery }))]);
    // A2 serves, for bob's held version, a record naming the attacker's recovery key.
    members.alice!.store.replace({ type: "member-keys", accountId: "bob", memberKeysVersion: 1 }, forgeMemberKeys("bob", 1, strangerKeys(), { recovery: fakeRecovery.publicKey }));
    await expect(aliceTeam.owner().reconcile(["alice", "bob"])).rejects.toMatchObject({ code: "TRUST_FAILURE", reason: "key_mismatch" });
    members.alice!.store.reset();
    // No rotation was written.
    expect(await members.alice!.store.get({ type: "team-key-version", teamId: "team-1", version: 3 })).toBeNull();
  });

  it("overview doesn't show such a re-key as proven either", async () => {
    const { members, w } = await team("bob");
    const owner = (await members.alice!.vault.openTeam("team-1")).owner();
    const fakeRecovery = cc1.signingKeyPair(cc1.randomBytes(32));
    await w.server.as("bob").commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys(), { recoverySigner: fakeRecovery }))]);
    members.alice!.store.replace({ type: "member-keys", accountId: "bob", memberKeysVersion: 1 }, forgeMemberKeys("bob", 1, strangerKeys(), { recovery: fakeRecovery.publicKey }));
    await expect(owner.overview(["alice", "bob"])).rejects.toMatchObject({ code: "TRUST_FAILURE", reason: "key_mismatch" });
  });
});

