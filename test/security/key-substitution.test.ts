/**
 * SP-04: Team keys go only to owner-approved member keys.
 * SP-12: Compromised member keys can be replaced (replaced keys are never approved).
 * Threats: TH-02, TH-37.
 */
import { describe, expect, it } from "vitest";
import { isConvoyError } from "../../src/errors.js";
import { bundleOf, forgeMemberKeys, forgeVersion, strangerKeys } from "../support/forge.js";
import { accessOf } from "../support/forge.js";
import { requestOf, team } from "../support/teams.js";

const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });

describe("SP-04: team keys go only to owner-approved member keys", () => {
  it("a member refuses its published keys when the server swaps them", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    bob.store.replace({ type: "member-keys", accountId: "bob" }, forgeMemberKeys("bob", 1, strangerKeys()));
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
  });

  it("a fake member injected in a version it signed itself is refused", async () => {
    const { members, aliceTeam } = await team("bob");
    const mallory = { accountId: "mallory", keys: strangerKeys() };
    const bob = members.bob!;
    bob.store.fork("team-1", aliceTeam.currentVersion + 1, await forgeVersion(bob.store, { version: aliceTeam.currentVersion + 1, owners: [mallory], signer: mallory }));
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("not_an_owner"));
  });

  it("a replaced sealed team key breaks the owner's signature", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    const bob = members.bob!;
    const version = aliceTeam.currentVersion;
    const record = (await bob.store.get({ type: "team-key-version", teamId: "team-1", version })) as { roster: Record<string, unknown>[] };
    const carol = record.roster.find((e) => e["accountId"] === "carol")!;
    const roster = record.roster.map((e) => (e["accountId"] === "bob" ? { ...e, sealedTeamKey: carol["sealedTeamKey"] } : e));
    bob.store.fork("team-1", version, { ...record, roster });
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("bad_signature"));
  });

  it("a roster entry naming other keys than the member's own is refused", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = await bundleOf(members.alice!.vault);
    const owner = { accountId: "alice", keys: alice.pairs, published: alice.published };
    const bob = members.bob!;
    const version = aliceTeam.currentVersion + 1;
    // A correctly signed version whose roster entry for bob holds keys that aren't his.
    const forged = await forgeVersion(bob.store, { version, owners: [owner], signer: owner, roster: [owner, { accountId: "bob", keys: strangerKeys() }] });
    bob.store.fork("team-1", version, forged);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
  });

  it("a version record from another team is refused as out of context", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await members.alice!.vault.createTeam("team-2");
    await bob.vault.joinTeam("team-2");
    await (await members.alice!.vault.openTeam("team-2")).owner().approve([{ accountId: "bob", memberKeysVersion: 1 }]);
    const other = await bob.store.get({ type: "team-key-version", teamId: "team-2", version: 2 });
    bob.store.fork("team-1", aliceTeam.currentVersion + 1, other);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("context_mismatch"));
  });

  it("a rotation seals only to the keys a member holds, never to keys the server publishes", async () => {
    const { members, aliceTeam } = await team("bob");
    const mallory = strangerKeys();
    const alice = members.alice!;
    // Newer keys published without approval: the rotation carries the held ones.
    await alice.store.commit([{ op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, mallory) }]);
    const { version } = await aliceTeam.owner().rotate({ keep: ["bob"] });
    expect((await accessOf(alice.store, "bob", version))!.memberKeysVersion).toBe(1);
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("ready");

    // The held keys' record swapped by the server: their hash no longer matches, and the rotation stops.
    const owner = await alice.vault.openTeam("team-1");
    alice.store.replace({ type: "member-keys", accountId: "bob", memberKeysVersion: 1 }, forgeMemberKeys("bob", 1, mallory));
    await expect(owner.owner().rotate({ keep: ["bob"] })).rejects.toEqual(trust("key_mismatch"));
    alice.store.reset();
    expect((await alice.vault.openTeam("team-1")).currentVersion).toBe(version);
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("keys published without proof from the current ones are flagged to the owner (TH-37)", async () => {
    const { members, aliceTeam } = await team("bob");
    await members.alice!.store.commit([{ op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) }]);
    expect((await requestOf(aliceTeam.owner(), "bob")).proof).toBe("none");
  });

  it("an owner can't approve keys the member has replaced", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const carol = await w.account("carol");
    await carol.vault.joinTeam("team-1");
    await carol.vault.rekey("team-1");
    await expect(aliceTeam.owner().approve([{ accountId: "carol", memberKeysVersion: 1 }])).rejects.toSatisfy((e) => isConvoyError(e, "STALE_VERSION"));
    expect(await accessOf(members.alice!.store, "carol", aliceTeam.currentVersion)).toBeNull();
    await aliceTeam.owner().approve([{ accountId: "carol", memberKeysVersion: 2 }]);
    expect((await carol.vault.openTeam("team-1")).state).toBe("ready");
  });
});
