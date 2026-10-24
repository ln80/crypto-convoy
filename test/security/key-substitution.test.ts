/**
 * SP-04: Team keys go only to owner-approved member keys.
 * SP-12: Compromised member keys can be replaced (replaced keys are never approved).
 * Threats: TH-02, TH-37.
 */
import { describe, expect, it } from "vitest";
import { isConvoyError } from "../../src/errors.js";
import { bundleOf, forgeMemberKeys, forgeVersion, strangerKeys } from "../support/forge.js";
import { accessOf } from "../support/forge.js";
import { requestOf, team, keysHandle } from "../support/teams.js";

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
    const team2 = await members.alice!.vault.openTeam("team-2");
    await team2.owner().approve([await keysHandle(team2, "bob", 1)]);
    const other = await bob.store.get({ type: "team-key-version", teamId: "team-2", version: 2 });
    bob.store.fork("team-1", aliceTeam.currentVersion + 1, other);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("context_mismatch"));
  });

  it("a rotation seals only to the keys a member holds, never to keys the server publishes", async () => {
    const { members, aliceTeam } = await team("bob");
    const mallory = strangerKeys();
    const alice = members.alice!;
    // Newer keys published under bob's account (his session, or the server) without approval: the rotation carries the held ones.
    await members.bob!.store.commit([{ op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, mallory) }]);
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
    await members.bob!.store.commit([{ op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) }]);
    expect((await requestOf(aliceTeam.owner(), "bob")).proof).toBe("none");
  });

  it("an owner can't approve keys the member has replaced", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const carol = await w.account("carol");
    await carol.vault.joinTeam("team-1");
    await carol.vault.rekey("team-1");
    await expect(aliceTeam.owner().approve([await keysHandle(aliceTeam, "carol", 1)])).rejects.toSatisfy((e) => isConvoyError(e, "STALE_VERSION"));
    expect(await accessOf(members.alice!.store, "carol", aliceTeam.currentVersion)).toBeNull();
    await aliceTeam.owner().approve([await keysHandle(aliceTeam, "carol", 2)]);
    expect((await carol.vault.openTeam("team-1")).state).toBe("ready");
  });
});

describe("SP-12: an approval holds for exactly the keys reviewed, by keys hash (D-55, review 013 A)", () => {
  const perAccount = (accountId: string) => ({ type: "member-keys", accountId });
  const noVersion3 = async (store: { get: (k: never) => Promise<unknown> }) =>
    expect(await store.get({ type: "team-key-version", teamId: "team-1", version: 3 } as never)).toBeNull();

  it("a member's proven re-key: another record served at rotation is refused, nothing written", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    // A2 answers the rotation's per-account fetch with its own keys for bob's reviewed version.
    members.alice!.store.replaceInList(perAccount("bob"), { memberKeysVersion: 2 }, forgeMemberKeys("bob", 2, strangerKeys()));
    await expect(aliceTeam.owner().reconcile(["alice", "bob"])).rejects.toEqual(trust("key_mismatch"));
    expect(aliceTeam.state).toBe("unverified");
    await noVersion3(bob.store);
  });

  it("an owner's own re-key (D-47): another record served at rotation never reaches the owner list", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    await alice.vault.rekey("team-1");
    const session = await alice.vault.openTeam("team-1");
    alice.store.replaceInList(perAccount("alice"), { memberKeysVersion: 2 }, forgeMemberKeys("alice", 2, strangerKeys()));
    await expect(session.owner().reconcile(["alice", "bob"])).rejects.toEqual(trust("key_mismatch"));
    await noVersion3(members.bob!.store);
  });

  it("a manual approval: the handle's keys hash pins the record the overview showed", async () => {
    const { members, aliceTeam } = await team("bob");
    await members.bob!.vault.rekey("team-1");
    const handle = (await requestOf(aliceTeam.owner(), "bob")).keys!;
    members.alice!.store.replaceInList(perAccount("bob"), { memberKeysVersion: 2 }, forgeMemberKeys("bob", 2, strangerKeys()));
    await expect(aliceTeam.owner().approve([handle])).rejects.toEqual(trust("key_mismatch"));
    await noVersion3(members.bob!.store);
    // A hand-built handle with a wrong hash is refused the same way.
    members.alice!.store.reset();
    const fresh = await members.alice!.vault.openTeam("team-1");
    await expect(fresh.owner().approve([{ ...handle, keysHash: "A".repeat(43) }])).rejects.toEqual(trust("key_mismatch"));
  });

  it("two records for one version, in the list the overview reads, are refused (review 014 A)", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    await alice.vault.rekey("team-1");
    const session = await alice.vault.openTeam("team-1");
    // The genuine record passes the custody check; the forged one would be the list's last.
    alice.store.addToList({ type: "member-keys", teamId: "team-1" }, forgeMemberKeys("alice", 2, strangerKeys()));
    await expect(session.owner().reconcile(["alice", "bob"])).rejects.toEqual(trust("key_mismatch"));
    await expect((await alice.vault.openTeam("team-1")).owner().overview(["alice", "bob"])).rejects.toEqual(trust("key_mismatch"));
    await noVersion3(members.bob!.store);
  });
});
