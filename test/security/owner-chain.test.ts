/**
 * SP-05: Only a current owner can change the owner list.
 * Threats: TH-03, TH-17, TH-33.
 */
import { describe, expect, it } from "vitest";
import { bundleOf, forgeGrant, forgeVersion, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });

/** v1 owners [alice]; v2 owners [alice, bob]; v3 owners [bob]: alice removed, carol kept. */
async function removedOwner() {
  const t = await team("bob", "carol");
  await t.aliceTeam.setOwners(["alice", "bob"], { keep: ["bob", "carol"] });
  const bob = await t.members.bob!.vault.openTeam("team-1");
  await bob.setOwners(["bob"], { keep: ["alice", "carol"] });
  return { ...t, alice: await bundleOf(t.members.alice!.vault), bob };
}

describe("SP-05: only a current owner can change the owner list", () => {
  it("refuses a version signed by a stranger", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const mallory = strangerKeys();
    bob.store.fork("team-1", 2, await forgeVersion(bob.store, { version: 2, owners: [{ accountId: "mallory", keys: mallory }], signer: { accountId: "mallory", keys: mallory } }));
    const session = await bob.vault.openTeam("team-1");
    expect(session.state).toBe("unverified");
    expect(session.failure).toEqual(trust("not_an_owner"));
  });

  it("refuses a version signed by a member who is not an owner", async () => {
    const { members } = await team("bob");
    const bobKeys = await bundleOf(members.bob!.vault);
    const forged = await forgeVersion(members.bob!.store, { version: 2, owners: [{ accountId: "bob", keys: bobKeys.pairs }], signer: { accountId: "bob", keys: bobKeys.pairs } });
    const alice = members.alice!;
    alice.store.fork("team-1", 2, forged);
    expect((await alice.vault.openTeam("team-1")).failure).toEqual(trust("not_an_owner"));
  });

  it("refuses a version signed by a removed owner", async () => {
    const { members, alice } = await removedOwner();
    const carol = members.carol!;
    carol.store.fork("team-1", 4, await forgeVersion(carol.store, { version: 4, owners: [{ accountId: "alice", keys: alice.pairs }], signer: { accountId: "alice", keys: alice.pairs } }));
    expect((await carol.vault.openTeam("team-1")).failure).toEqual(trust("not_an_owner"));
  });

  it("refuses a grant of a later version signed by a removed owner (TH-33)", async () => {
    const { members, alice } = await removedOwner();
    const carol = members.carol!;
    const session = await carol.vault.openTeam("team-1");
    expect(session.state).toBe("ready");
    carol.store.replace(
      { type: "grant", teamKeyVersion: 3, accountId: "carol" },
      forgeGrant({ member: { accountId: "carol", memberKeysVersion: 1, keys: (await bundleOf(carol.vault)).pairs }, teamKeyVersion: 3, signer: { accountId: "alice", keys: alice.pairs } }),
    );
    await expect(session.members()).rejects.toEqual(trust("not_an_owner"));
    expect(session.state).toBe("unverified");
  });

  it("refuses a gap in the chain", async () => {
    const { members } = await removedOwner();
    const carol = members.carol!;
    carol.store.drop({ type: "team-key-version", version: 2 });
    expect((await carol.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
  });

  it("refuses two records for one version (fork)", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    const aliceKeys = await bundleOf(alice.vault);
    await (await alice.vault.openTeam("team-1")).rotate({ keep: ["bob"] });
    alice.store.fork("team-1", 2, await forgeVersion(alice.store, { version: 2, owners: [{ accountId: "alice", keys: aliceKeys.pairs }], signer: { accountId: "alice", keys: aliceKeys.pairs } }));
    expect((await alice.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
  });

  it("an owner change can't be written without its signer's grant", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    const keys = await bundleOf(alice.vault);
    const version = await forgeVersion(alice.store, { version: 2, owners: [{ accountId: "alice", keys: keys.pairs }], signer: { accountId: "alice", keys: keys.pairs } });
    await expect(alice.store.commit([{ op: "create", key: { type: "team-key-version", teamId: "team-1", version: 2 }, record: version }])).rejects.toThrow();
    expect((await alice.vault.openTeam("team-1")).currentVersion).toBe(1);
  });

  it("refuses an owner whose key isn't that account's published key", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    const keys = await bundleOf(alice.vault);
    const fake = strangerKeys();
    const forged = await forgeVersion(alice.store, { version: 2, owners: [{ accountId: "alice", keys: keys.pairs }, { accountId: "bob", keys: fake }], signer: { accountId: "alice", keys: keys.pairs } });
    const bob = members.bob!;
    bob.store.fork("team-1", 2, forged);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
  });
});
