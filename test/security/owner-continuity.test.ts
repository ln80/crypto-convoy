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

describe("SP-16: a listed owner steps down before leaving (D-65, review 032 C)", () => {
  it("two owners can't both leave: each steps down first, and the last can't", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob"] });
    await expect(members.bob!.vault.leaveTeam("team-1")).rejects.toEqual(expect.objectContaining({ code: "LAST_OWNER" }));
    // bob steps down himself, then leaves.
    await (await members.bob!.vault.openTeam("team-1")).owner().setOwners(["alice"]);
    await members.bob!.vault.leaveTeam("team-1");
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("not-joined");
    // alice, now the only owner, can't.
    await expect(members.alice!.vault.leaveTeam("team-1")).rejects.toEqual(expect.objectContaining({ code: "LAST_OWNER" }));
  });

  it("a member who isn't an owner leaves", async () => {
    const { members } = await team("bob");
    await members.bob!.vault.leaveTeam("team-1");
    expect((await members.bob!.vault.openTeam("team-1")).state).toBe("not-joined");
  });

  it("an owner left out of a rotation is a caller's mistake: MALFORMED_RECORD, before anything is written", async () => {
    const { aliceTeam } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob"] });
    const owner = aliceTeam.owner();
    await expect(owner.remove(["bob"])).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    await expect(owner.setOwners(["alice", "bob"], { keep: [] })).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    await expect(owner.rotate({ keep: [] })).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    expect(aliceTeam.currentVersion).toBe(3);
    expect(aliceTeam.state).toBe("ready");
  });
});
