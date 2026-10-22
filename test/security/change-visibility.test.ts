/**
 * SP-15: Owner and membership changes are visible.
 * Threats: TH-17, TH-41.
 */
import { describe, expect, it } from "vitest";
import { team } from "../support/teams.js";

describe("SP-15: owner and membership changes are visible", () => {
  it("each owner change is reported once, with its signer, on every member's client", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    const carol = members.carol!;
    expect((await carol.vault.openTeam("team-1")).ownerChanges).toEqual([]);

    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob", "carol"] });
    const bobTeam = await members.bob!.vault.openTeam("team-1");
    await bobTeam.owner().setOwners(["bob"], { keep: ["alice", "carol"] });

    const seen = await carol.vault.openTeam("team-1");
    expect(seen.ownerChanges).toEqual([
      { version: 3, signer: "alice", added: ["bob"], removed: [], rekeyed: [] },
      { version: 4, signer: "bob", added: [], removed: ["alice"], rekeyed: [] },
    ]);
    // Already seen: not reported again.
    expect((await carol.vault.openTeam("team-1")).ownerChanges).toEqual([]);
  });

  it("a rotation without an owner change reports nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    expect((await members.bob!.vault.openTeam("team-1")).ownerChanges).toEqual([]);
  });

  it("every member sees who approved each member", async () => {
    const { members, aliceTeam, w } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob"] });
    const dave = await w.account("dave");
    await dave.vault.joinTeam("team-1");
    const bobTeam = await members.bob!.vault.openTeam("team-1");
    await bobTeam.owner().approve([{ accountId: "dave", memberKeysVersion: 1 }]);
    const view = await members.alice!.vault.openTeam("team-1");
    expect(await view.members()).toContainEqual({ accountId: "dave", memberKeysVersion: 1, grantedBy: "bob" });
  });

  it("Limit: members granted by a removed owner are a warning list, hidden once re-granted by another", async () => {
    const { members, aliceTeam } = await team("bob", "carol");
    await aliceTeam.owner().setOwners(["alice", "bob"], { keep: ["bob", "carol"] });
    const bobTeam = await members.bob!.vault.openTeam("team-1");
    expect(await bobTeam.owner().grantedBy(["alice"])).toEqual(["alice", "bob", "carol"]);
    await bobTeam.owner().setOwners(["bob"], { keep: ["alice", "carol"] });
    expect(await bobTeam.owner().grantedBy(["alice"])).toEqual([]);
  });
});

describe("SP-15: owners see each member's access and what needs their action", () => {
  it("statuses follow a member from joining to approval, a re-key and a removal", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const owner = aliceTeam.owner();
    const carol = await w.account("carol");
    const view = async (...ids: string[]) =>
      (await owner.overview(ids)).accounts.filter((a) => ids.includes(a.accountId)).map(({ accountId, status, proof }) => ({ accountId, status, proof }));
    expect(await view("carol")).toEqual([{ accountId: "carol", status: "no-keys", proof: undefined }]);
    await carol.vault.joinTeam("team-1");
    expect(await view("carol")).toEqual([{ accountId: "carol", status: "awaiting-approval", proof: "none" }]);
    await owner.approve([{ accountId: "carol", memberKeysVersion: 1 }]);
    expect(await view("carol")).toEqual([{ accountId: "carol", status: "approved", proof: "none" }]);

    await members.bob!.vault.rekey("team-1");
    expect(await view("bob")).toEqual([{ accountId: "bob", status: "rekey-awaiting-approval", proof: "none" }]);
    expect(await owner.approve([{ accountId: "bob", memberKeysVersion: 2 }])).toEqual({ rotatedTo: 4, approved: ["bob"] });
    expect(await view("bob", "carol")).toEqual([
      { accountId: "bob", status: "approved", proof: "none" },
      // approve() kept every holder: carol holds version 4 too.
      { accountId: "carol", status: "approved", proof: "none" },
    ]);
    await owner.remove(["carol"]);
    expect(await view("carol")).toEqual([{ accountId: "carol", status: "outdated", proof: "none" }]);
  });

  it("warnings: single owner, members awaiting approval, rotation needed; a failed rotation changes nothing", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const codes = async (active: string[]) => (await aliceTeam.owner().overview(active)).warnings.map((x) => [x.code, x.accountIds, x.action]);
    expect(await codes(["alice", "bob"])).toEqual([["single-owner", ["alice"], "setOwners"]]);

    const carol = await w.account("carol");
    await carol.vault.joinTeam("team-1");
    expect(await codes(["alice", "bob", "carol"])).toContainEqual(["members-awaiting-approval", ["carol"], "approve"]);

    // bob leaves the product: still granted at the current version.
    expect(await codes(["alice"])).toContainEqual(["rotation-needed", ["bob"], "reconcile"]);

    // A rotation is one record: a failed write leaves nothing half done (D-34).
    members.alice!.store.onCommit(() => {
      throw new Error("network");
    });
    await expect(aliceTeam.owner().rotate({ keep: ["bob"] })).rejects.toEqual(expect.objectContaining({ code: "STORE_ERROR" }));
    members.alice!.store.reset();
    const reopened = await members.alice!.vault.openTeam("team-1");
    expect(reopened.currentVersion).toBe(2);
    expect((await reopened.members()).map((m) => m.accountId).sort()).toEqual(["alice", "bob"]);
  });

  it("D-44: a member admitted and removed again between two opens is reported, with each signer", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    const mallory = await w.account("mallory");
    await mallory.vault.joinTeam("team-1");
    await aliceTeam.owner().approve([{ accountId: "mallory", memberKeysVersion: 1 }]);
    await aliceTeam.owner().remove(["mallory"]);

    const seen = await bob.vault.openTeam("team-1");
    expect(seen.memberChanges.map(({ signer, added, removed, rekeyed }) => ({ signer, added, removed, rekeyed }))).toEqual([
      { signer: "alice", added: ["mallory"], removed: [], rekeyed: [] },
      { signer: "alice", added: [], removed: ["mallory"], rekeyed: [] },
    ]);
    expect(seen.memberChanges[1]!.version).toBe(seen.currentVersion);
    // Already seen: not reported again.
    expect((await bob.vault.openTeam("team-1")).memberChanges).toEqual([]);
  });

  it("D-44: an approved re-key is reported; a rotation that changes no keys reports nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    expect((await bob.vault.openTeam("team-1")).memberChanges).toEqual([]);
    await bob.vault.rekey("team-1");
    await aliceTeam.owner().approve([{ accountId: "bob", memberKeysVersion: 2 }]);
    const seen = await bob.vault.openTeam("team-1");
    expect(seen.memberChanges).toEqual([{ version: seen.currentVersion, signer: "alice", added: [], removed: [], rekeyed: ["bob"] }]);
  });
});
