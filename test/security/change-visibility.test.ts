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

describe("SP-15: owners see each member's access and what needs their action", () => {
  it("statuses follow a member from joining to approval, a re-key and a removal", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const carol = await w.account("carol");
    expect(await aliceTeam.memberStatuses(["carol"])).toEqual([{ accountId: "carol", status: "no-keys" }]);
    await carol.vault.joinTeam("team-1");
    expect(await aliceTeam.memberStatuses(["carol"])).toEqual([{ accountId: "carol", status: "awaiting-approval", continuity: "new" }]);
    await aliceTeam.grant("carol", 1);
    expect((await aliceTeam.memberStatuses(["carol"]))[0]!.status).toBe("approved");

    await members.bob!.vault.rekey("team-1");
    expect(await aliceTeam.memberStatuses(["bob"])).toEqual([{ accountId: "bob", status: "rekey-awaiting-approval", continuity: "routine" }]);
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: [{ accountId: "bob", memberKeysVersion: 2 }] });
    expect(await aliceTeam.memberStatuses(["bob", "carol"])).toEqual([
      { accountId: "bob", status: "approved" },
      { accountId: "carol", status: "outdated", continuity: "new" },
    ]);
  });

  it("warnings: single owner, members awaiting approval, rotation needed, rotation interrupted", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const codes = async (active: string[]) => (await aliceTeam.warnings(active)).map((x) => [x.code, x.accountIds, x.action]);
    expect(await codes(["alice", "bob"])).toEqual([["single-owner", ["alice"], "setOwners"]]);

    const carol = await w.account("carol");
    await carol.vault.joinTeam("team-1");
    expect(await codes(["alice", "bob", "carol"])).toContainEqual(["members-awaiting-approval", ["carol"], "grant"]);

    // bob leaves the product: still granted at the current version.
    expect(await codes(["alice"])).toContainEqual(["rotation-needed", ["bob"], "rotate"]);

    // A rotation interrupted after its first batch: bob, kept, misses the new version.

    members.alice!.store.onCommit((ops) => {
      if (ops.every((op) => op.op === "create" && op.key.type === "grant") && ops.some((op) => op.op === "create" && "accountId" in op.key && op.key.accountId === "bob")) {
        throw new Error("network");
      }
    });
    await expect(aliceTeam.rotate({ keep: ["bob"] })).rejects.toEqual(expect.objectContaining({ code: "STORE_ERROR" }));
    members.alice!.store.reset();
    const reopened = await members.alice!.vault.openTeam("team-1");
    expect((await reopened.warnings(["alice", "bob"])).map((x) => x.code)).toContain("rotation-interrupted");
    await reopened.completeRotation({ keep: ["bob"] });
    expect((await reopened.warnings(["alice", "bob"])).map((x) => x.code)).not.toContain("rotation-interrupted");
  });
});
