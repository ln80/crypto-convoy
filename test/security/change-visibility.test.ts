/**
 * SP-15: Owner and membership changes are visible.
 * Threats: TH-17.
 */
import { describe, expect, it } from "vitest";
import { team } from "../support/teams.js";

describe("SP-15: owner and membership changes are visible", () => {
  it("each owner change is reported once, with its signer, on every member's client", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    const carol = members.carol!;
    expect((await carol.vault.openTeam("team-1")).ownerChanges).toEqual([]);

    await aliceTeam.setOwners(["alice", "bob"], { keep: ["bob", "carol"] });
    const bobTeam = await members.bob!.vault.openTeam("team-1");
    await bobTeam.setOwners(["bob"], { keep: ["alice", "carol"] });

    const seen = await carol.vault.openTeam("team-1");
    expect(seen.ownerChanges).toEqual([
      { version: 2, signer: "alice", added: ["bob"], removed: [], rekeyed: [] },
      { version: 3, signer: "bob", added: [], removed: ["alice"], rekeyed: [] },
    ]);
    // Already seen: not reported again.
    expect((await carol.vault.openTeam("team-1")).ownerChanges).toEqual([]);
  });

  it("a rotation without an owner change reports nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.rotate({ keep: ["bob"] });
    expect((await members.bob!.vault.openTeam("team-1")).ownerChanges).toEqual([]);
  });

  it("every member sees who approved each member", async () => {
    const { members, aliceTeam, w } = await team("bob");
    await aliceTeam.setOwners(["alice", "bob"], { keep: ["bob"] });
    const dave = await w.account("dave");
    await dave.vault.joinTeam("team-1");
    const bobTeam = await members.bob!.vault.openTeam("team-1");
    await bobTeam.grant("dave", 1);
    const view = await members.alice!.vault.openTeam("team-1");
    expect(await view.members()).toContainEqual({ accountId: "dave", memberKeysVersion: 1, grantedBy: "bob" });
  });

  it("Limit: members granted by a removed owner are a warning list, hidden once re-granted by another", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    await aliceTeam.setOwners(["alice", "bob"], { keep: ["bob", "carol"] });
    const bobTeam = await members.bob!.vault.openTeam("team-1");
    expect(await bobTeam.grantedBy(["alice"])).toEqual(["alice", "bob", "carol"]);
    await bobTeam.setOwners(["bob"], { keep: ["alice", "carol"] });
    expect(await bobTeam.grantedBy(["alice"])).toEqual([]);
  });
});
