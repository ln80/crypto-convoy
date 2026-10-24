/**
 * SP-16: Losing one owner never freezes a team with other owners.
 * Threats: TH-18.
 */
import { describe, expect, it } from "vitest";
import { requestOf, team, keysHandle } from "../support/teams.js";

describe("SP-16: another owner keeps the team running", () => {
  it("bob removes an unreachable alice, admits a member, rotates, and re-adds her with new keys", async () => {
    const { members, aliceTeam, w } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob"] });
    const bob = await members.bob!.vault.openTeam("team-1");

    // alice loses her credentials: bob acts alone.
    await bob.owner().setOwners(["bob"], { keep: [] });
    const dave = await w.account("dave");
    await dave.vault.joinTeam("team-1");
    await bob.owner().approve([await keysHandle(bob, "dave", 1)]);
    await bob.owner().rotate({ keep: ["dave"] });
    expect(bob.currentVersion).toBe(6);

    // alice comes back with a new account on the same id and new member keys.
    const back = await w.device("alice");
    await back.vault.recover(members.alice!.recoveryPhrase, "2468");
    await back.vault.rekey("team-1");
    const request = await requestOf(bob.owner(), "alice");
    expect(request).toMatchObject({ status: "outdated", proof: "none" });
    await bob.owner().approve([request.keys!]);
    await bob.owner().setOwners(["alice", "bob"], { keep: ["alice", "dave"] });
    const alice = await back.vault.openTeam("team-1");
    expect(alice.state).toBe("ready");
    expect(alice.owners()).toEqual(["alice", "bob"]);
  });
});
