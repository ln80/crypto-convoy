/**
 * SP-04: Team keys go only to owner-approved member keys.
 * Threats: TH-02, TH-37.
 */
import { describe, expect, it } from "vitest";
import { bundleOf, forgeGrant, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });

describe("SP-04: team keys go only to owner-approved member keys", () => {
  it("a member refuses its published keys when the server swaps them", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    bob.store.replace({ type: "member-keys", accountId: "bob" }, forgeMemberKeys("bob", 1, strangerKeys()));
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
  });

  it("a fake member injected with a grant it signed itself is refused", async () => {
    const { members } = await team("bob");
    const mallory = strangerKeys();
    const bob = members.bob!;
    const session = await bob.vault.openTeam("team-1");
    bob.store.replace(
      { type: "grant", accountId: "bob" },
      forgeGrant({ member: { accountId: "bob", memberKeysVersion: 1, keys: mallory }, teamKeyVersion: 1, signer: { accountId: "mallory", keys: mallory } }),
    );
    await expect(session.members()).rejects.toEqual(trust("not_an_owner"));
  });

  it("a replaced sealed team key breaks the owner's signature", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const grant = (await bob.store.list({ type: "grant", teamId: "team-1", accountId: "bob" }))[0] as Record<string, unknown>;
    const other = (await bob.store.list({ type: "grant", teamId: "team-1", accountId: "alice" }))[0] as Record<string, unknown>;
    bob.store.replace({ type: "grant", accountId: "bob" }, { ...grant, sealedTeamKey: other["sealedTeamKey"] });
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("bad_signature"));
  });

  it("a grant meant for another member is refused as out of context", async () => {
    const { members } = await team("bob", "carol");
    const bob = members.bob!;
    const carolGrant = (await bob.store.list({ type: "grant", teamId: "team-1", accountId: "carol" }))[0];
    bob.store.replace({ type: "grant", accountId: "bob" }, carolGrant);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("context_mismatch"));
  });

  it("a grant from another team is refused as out of context", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    await members.alice!.vault.createTeam("team-2");
    const aliceTeam2 = await members.alice!.vault.openTeam("team-2");
    await bob.vault.joinTeam("team-2");
    await aliceTeam2.grant("bob", 1);
    const otherTeam = (await bob.store.list({ type: "grant", teamId: "team-2", accountId: "bob" }))[0];
    bob.store.replace({ type: "grant", teamId: "team-1", accountId: "bob" }, otherTeam);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("context_mismatch"));
  });

  it("a grant naming other keys than the member's own is refused", async () => {
    const { members } = await team("bob");
    const alice = await bundleOf(members.alice!.vault);
    const bob = members.bob!;
    bob.store.replace(
      { type: "grant", accountId: "bob" },
      forgeGrant({ member: { accountId: "bob", memberKeysVersion: 1, keys: strangerKeys() }, teamKeyVersion: 1, signer: { accountId: "alice", keys: alice.pairs } }),
    );
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
  });

  it("a rotation seals only to granted keys, not to keys the server publishes", async () => {
    const { members, aliceTeam } = await team("bob");
    const mallory = strangerKeys();
    const alice = members.alice!;
    alice.store.replace({ type: "member-keys", accountId: "bob" }, forgeMemberKeys("bob", 2, mallory));
    await aliceTeam.rotate({ keep: ["bob"] });
    alice.store.reset();
    const grants = await alice.store.list({ type: "grant", teamId: "team-1", teamKeyVersion: 2, accountId: "bob" });
    expect(grants).toHaveLength(1);
    expect((grants[0] as { memberKeysVersion: number }).memberKeysVersion).toBe(1);
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("keys published without proof from the current ones are flagged to the owner (TH-37)", async () => {
    const { members, aliceTeam } = await team("bob");
    await members.alice!.store.commit([{ op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) }]);
    expect((await aliceTeam.memberRequest("bob")).continuity).toBe("unproven");
  });
});
