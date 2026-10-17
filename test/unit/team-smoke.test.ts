/** A walk through the team lifecycle (§6), the honest path for the team security tests. */
import { describe, expect, it } from "vitest";
import { team } from "../support/teams.js";

describe("team lifecycle", () => {
  it("creates, joins, grants, rotates and changes owners", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    expect(aliceTeam.state).toBe("ready");
    expect(aliceTeam.owners()).toEqual(["alice"]);
    const bob = await members.bob!.vault.openTeam("team-1");
    expect(bob.state).toBe("ready");
    expect((await bob.members()).map((m) => [m.accountId, m.grantedBy])).toEqual([
      ["alice", "alice"],
      ["bob", "alice"],
      ["carol", "alice"],
    ]);

    await aliceTeam.setOwners(["alice", "bob"], { keep: ["bob", "carol"] });
    expect(aliceTeam.currentVersion).toBe(2);
    await bob.close();
    const bob2 = await members.bob!.vault.openTeam("team-1");
    expect(bob2.ownerChanges).toEqual([{ version: 2, signer: "alice", added: ["bob"], removed: [], rekeyed: [] }]);

    await bob2.setOwners(["bob"], { keep: ["carol"] });
    const aliceAgain = await members.alice!.vault.openTeam("team-1");
    expect(aliceAgain.state).toBe("pending");
    expect(await aliceAgain.teamKey(1)).toHaveLength(32);
    const carol = await members.carol!.vault.openTeam("team-1");
    expect(carol.state).toBe("ready");
    expect(carol.currentVersion).toBe(3);
    expect(await carol.teamKey(1)).toEqual(await aliceAgain.teamKey(1));
  });
});
