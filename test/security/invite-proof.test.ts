/**
 * SP-24: An invite proof shows the joiner held the invite link.
 * Threats: TH-02, TH-04, TH-37, TH-43.
 */
import { describe, expect, it } from "vitest";
import { decodeInvite, encodeInvite } from "../../src/encoding/link.js";
import { createInvite, inviteToJson } from "../../src/records/invite.js";
import { sessionInternals } from "../../src/team/session.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { bundleOf } from "../support/forge.js";
import { team } from "../support/teams.js";

async function invited(...names: string[]) {
  const t = await team();
  const { invite } = await t.aliceTeam.owner().createInvite("invite-1", { inviteeRef: "ref-1" });
  for (const name of names) await (await t.w.account(name)).vault.joinTeam("team-1", { invite });
  return { ...t, invite };
}

const humans = (report: { needsHuman: readonly { accountId: string; reason: string }[] }) =>
  report.needsHuman.map(({ accountId, reason }) => [accountId, reason]);

describe("SP-24: invite proofs", () => {
  it("is a hint by default, and admits the joiner only with autoApproveInvites", async () => {
    const { aliceTeam } = await invited("dave");
    const owner = aliceTeam.owner();
    const dave = (await owner.overview(["alice", "dave"])).accounts.find((a) => a.accountId === "dave")!;
    expect(dave).toMatchObject({ status: "awaiting-approval", proof: "invite", inviteId: "invite-1", inviteeRef: "ref-1" });
    expect(humans(await owner.reconcile(["alice", "dave"]))).toEqual([["dave", "invite-not-accepted"]]);
    expect(humans(await owner.reconcile(["alice", "dave"], { autoApproveInvites: () => false }))).toEqual([["dave", "invite-not-accepted"]]);
    expect(await owner.reconcile(["alice", "dave"], { autoApproveInvites: true })).toMatchObject({ admitted: ["dave"], needsHuman: [] });
    expect((await owner.overview(["alice", "dave"])).accounts.find((a) => a.accountId === "dave")!.status).toBe("approved");
  });

  it("one invite admits one account: a second joiner with the same link waits for a human", async () => {
    const { aliceTeam } = await invited("dave", "erin");
    const report = await aliceTeam.owner().reconcile(["alice", "dave", "erin"], { autoApproveInvites: true });
    expect(report.admitted).toEqual(["dave"]);
    expect(humans(report)).toEqual([["erin", "invite-not-accepted"]]);
    // Still only one, on the next run too.
    expect(humans(await aliceTeam.owner().reconcile(["alice", "dave", "erin"], { autoApproveInvites: true }))).toEqual([["erin", "invite-not-accepted"]]);
  });

  it("a link with another secret proves nothing", async () => {
    const { aliceTeam, w, invite } = await invited();
    const forged = encodeInvite({ ...decodeInvite(invite), secret: cc1.randomBytes(32) });
    await (await w.account("dave")).vault.joinTeam("team-1", { invite: forged });
    const report = await aliceTeam.owner().reconcile(["alice", "dave"], { autoApproveInvites: true });
    expect(report).toMatchObject({ admitted: [], needsHuman: [{ accountId: "dave", reason: "awaiting-approval", proof: "none" }] });
  });

  it("an invite of an older version is a hint only", async () => {
    const { aliceTeam } = await invited("dave");
    await aliceTeam.owner().rotate({ keep: [] });
    expect(humans(await aliceTeam.owner().reconcile(["alice", "dave"], { autoApproveInvites: true }))).toEqual([["dave", "invite-not-accepted"]]);
  });

  it("an invite a member who isn't an owner wrote is ignored", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    const bobTeam = await bob.vault.openTeam("team-1");
    const keys = await bundleOf(bob.vault);
    const secret = cc1.randomBytes(32);
    const record = createInvite(cc1, {
      teamId: "team-1", inviteId: "rogue", teamKeyVersion: 1, teamKey: await sessionInternals(bobTeam).teamKey(1), secret,
      signer: { accountId: "bob", signingPublicKey: keys.pairs.signing.publicKey }, signerSecretKey: keys.pairs.signing.secretKey, createdAt: 1,
    });
    await bob.store.commit([{ op: "create", key: { type: "invite", teamId: "team-1", inviteId: "rogue" }, record: inviteToJson(record) }]);
    const link = encodeInvite({ anchor: decodeInvite((await aliceTeam.owner().createInvite("real")).invite).anchor, inviteId: "rogue", secret });
    await (await w.account("dave")).vault.joinTeam("team-1", { invite: link });
    const report = await aliceTeam.owner().reconcile(["alice", "bob", "dave"], { autoApproveInvites: true });
    expect(report).toMatchObject({ admitted: [], needsHuman: [{ accountId: "dave", reason: "awaiting-approval", proof: "none" }] });
  });

  it("the policy sees the invitee reference and decides per joiner", async () => {
    const { aliceTeam } = await invited("dave");
    const seen: unknown[] = [];
    await aliceTeam.owner().reconcile(["alice", "dave"], {
      autoApproveInvites: (candidate) => {
        seen.push(candidate);
        return candidate.inviteeRef === "ref-1";
      },
    });
    expect(seen).toEqual([{ accountId: "dave", inviteId: "invite-1", inviteeRef: "ref-1" }]);
  });

  it("the joiner starts from the invite's anchor: a forged team is refused (SP-07)", async () => {
    const { w, invite } = await invited();
    const dave = await w.account("dave");
    await dave.vault.joinTeam("team-1", { invite });
    dave.store.rollback("team-1", 0);
    expect((await dave.vault.openTeam("team-1", { invite })).failure).toEqual(expect.objectContaining({ code: "TRUST_FAILURE" }));
  });
});
