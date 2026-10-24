/**
 * The library through its public entry points only, shaped like a product's pipelines:
 * a value encrypted before the server assigns an id, files uploaded one by one, the key record
 * sealed at finalize; per-part reveal; an intake from outside; a vault and a page in separate
 * contexts; approvals as rotations, writes retried across them, the owner's reconcile and securing
 * an account. Doubles as executable documentation. Covers SP-02, SP-06, SP-12, SP-14, SP-15, SP-22, SP-23 end to end.
 */
import { keysHandle } from "../support/teams.js";
import { describe, expect, it } from "vitest";
import { createLinkClient, createTeamKeyReceiver, createVault, isConvoyError, type Settings } from "../../src/index.js";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore, fixedClock } from "../../src/testing/index.js";

const settings: Settings = { argon2: { write: { opslimit: 2, memlimit: 64 * 1024 * 1024 } } };
const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);

/** The product's own content backend: it assigns ids and stores ciphertext. */
class ProductServer {
  #next = 1;
  readonly files = new Map<string, Uint8Array>();
  readonly submissions = new Map<string, unknown>();
  createResource(firstPart: Uint8Array): string {
    const id = `res-${this.#next++}`;
    this.files.set(`${id}/0`, firstPart);
    return id;
  }
  upload(id: string, index: number, bytes: Uint8Array) {
    this.files.set(`${id}/${index}`, bytes);
  }
  download = (id: string, index: number) => async () => this.files.get(`${id}/${index}`)!;
}

async function* chunks(bytes: Uint8Array, size = 1 << 20) {
  for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
}

async function collect(stream: AsyncIterable<Uint8Array>) {
  const out: Uint8Array[] = [];
  for await (const c of stream) out.push(c);
  return new Uint8Array(Buffer.concat(out));
}

describe("scenario", () => {
  it("runs a team's life the way a product would", async () => {
    const keyStore = new MemoryRecordStore();
    const product = new ProductServer();
    const oprf = new FakeOprfServer();
    const clock = fixedClock();
    const local = () => new MemoryLocalKeyStore();
    // The OPRF public keys ship in the product's client code (D-53).
    const clientSettings: Settings = { ...settings, oprf: await oprf.clientSettings() };
    const vault = (accountId: string, keys = local()) =>
      createVault({ store: keyStore.as(accountId), oprf, deviceKeys: keys, anchors: keys, clock, settings: clientSettings }, accountId);

    // 1. Encryption setup: recovery first; the owner creates the team and invites a member with
    //    the team's anchor; the member joins, and the owner approves after checking the request.
    const alice = await vault("alice");
    expect((await alice.status()).account).toBe("not-set-up");
    await alice.setup("1234");
    expect(await alice.status()).toEqual({ account: "unlocked", deviceRegistered: true, deviceId: expect.any(String), recovery: "not-set-up", pin: "set-up" });
    await expect(alice.createTeam("team-1")).rejects.toSatisfy((e) => isConvoyError(e, "RECOVERY_NOT_SET_UP"));
    const { recoveryPhrase } = alice.beginRecoverySetup(); // shown to the user, then typed back
    await alice.confirmRecoveryPhrase(recoveryPhrase);
    expect((await alice.status()).recovery).toBe("set-up");
    await alice.createTeam("team-1");
    const team = await alice.openTeam("team-1");
    const owner = team.owner();
    expect((await owner.overview(["alice"])).warnings.map((w) => w.code)).toEqual(["single-owner"]);
    const anchor = team.inviteAnchor(); // in the invite link's fragment

    const bob = await vault("bob");
    await bob.setup("5678");
    await bob.confirmRecoveryPhrase(bob.beginRecoverySetup().recoveryPhrase);
    expect((await owner.overview(["alice", "bob"])).accounts.find((a) => a.accountId === "bob")!.status).toBe("no-keys");
    await bob.joinTeam("team-1", { anchor });
    expect((await bob.openTeam("team-1")).state).toBe("pending");
    const bobView = (await owner.overview(["alice", "bob"])).accounts.find((a) => a.accountId === "bob")!;
    expect(bobView).toMatchObject({ status: "awaiting-approval", proof: "none" });
    // A first join is never automatic: a human approves.
    expect((await owner.reconcile(["alice", "bob"])).needsHuman).toEqual([
      { accountId: "bob", reason: "awaiting-approval", keys: bobView.keys, proof: "none" },
    ]);
    expect(await owner.approve([bobView.keys!])).toEqual({ rotatedTo: 2, approved: ["bob"] });
    expect((await owner.overview(["alice", "bob"])).accounts.find((a) => a.accountId === "bob")!.status).toBe("approved");

    // 2. Secret creation: the value is encrypted before the server assigns the id, files are
    //    uploaded one by one (streamed), and the key record is sealed at finalize.
    const bobTeam = await bob.openTeam("team-1");
    const draft = bobTeam.beginItem();
    const id = product.createResource(draft.addPart(text("the secret value"), { meta: text('{"kind":"text"}') }));
    const file = Uint8Array.from({ length: 5 * 1024 * 1024 + 7 }, (_, i) => i % 251);
    const ref = draft.partRef(file); // safe to send the server, e.g. for deduplication
    product.upload(id, 1, await collect(draft.addPartStream(chunks(file), { meta: text("report.pdf") })));
    await owner.rotate({ keep: ["bob"] }); // an owner rotates while bob uploads (D-37)
    await draft.seal(id); // refused at the old version, sealed again at the new one
    expect(bobTeam.currentVersion).toBe(3);
    expect(ref).toHaveLength(43);

    // 3. Reveal per attachment: a member, then a link holder given the record by the product.
    const opened = await team.openItem(id);
    expect(opened.parts.map((p) => read(p.meta))).toEqual(['{"kind":"text"}', "report.pdf"]);
    expect(read(await opened.part(0, product.download(id, 0)))).toBe("the secret value");
    expect((await collect(opened.partStream(1, product.download(id, 1)))).length).toBe(file.length);
    const outsider = await createLinkClient({ clock });
    const shared = outsider.openSharedItem(await team.shareLinkKey(id), "team-1", id, await keyStore.anonymous().get({ type: "item", teamId: "team-1", itemId: id }));
    expect(read(await shared.part(0, product.download(id, 0)))).toBe("the secret value");

    // 4. Intake: an inbox, an anonymous sender, the envelope sent at finalize with the server's id.
    const { linkKey } = await team.createInbox("request-1");
    const intake = outsider.beginSubmission(linkKey, "team-1", "request-1");
    const submissionId = product.createResource(intake.addPart(text("filled form")));
    product.submissions.set(submissionId, await intake.seal(submissionId));
    const submission = await bobTeam.openSubmission("request-1", submissionId, product.submissions.get(submissionId));
    expect(read(await submission.part(0, product.download(submissionId, 0)))).toBe("filled form");

    // 5. Bob becomes an owner; then bob removes alice's access and ownership.
    await owner.setOwners(["alice", "bob"]);
    const bobOwner = await bob.openTeam("team-1");
    expect(bobOwner.ownerChanges.map((c) => c.added)).toEqual([["bob"]]);
    // Removing an owner is never automatic: reconcile leaves it to a human.
    const plan = await bobOwner.owner().reconcile(["bob"], { dryRun: true });
    expect(plan.needsHuman).toContainEqual(expect.objectContaining({ accountId: "alice", reason: "inactive-owner" }));
    await bobOwner.owner().setOwners(["bob"], { keep: [] });
    const later = bobOwner.beginItem();
    later.addPart(text("alice can't read this"));
    await later.seal("after-removal");
    const aliceView = await alice.openTeam("team-1");
    expect(aliceView.state).toBe("pending");
    await expect(aliceView.openItem("after-removal")).rejects.toSatisfy((e) => isConvoyError(e, "NOT_GRANTED"));

    // 6. Alice re-keys; bob sees the continuity hint and grants her new keys (never the replaced ones).
    await alice.rekey("team-1");
    const aliceView2 = (await bobOwner.owner().overview(["alice", "bob"])).accounts.find((a) => a.accountId === "alice")!;
    expect(aliceView2).toMatchObject({ status: "outdated", proof: "none", keys: { accountId: "alice", memberKeysVersion: 2 } });
    await expect(bobOwner.owner().approve([await keysHandle(bobOwner, "alice", 1)])).rejects.toSatisfy((e) => isConvoyError(e, "STALE_VERSION"));
    await bobOwner.owner().approve([aliceView2.keys!]);
    expect((await alice.openTeam("team-1")).state).toBe("ready");

    // 7. Separate contexts: the vault on one origin, team work on the product's page.
    const page = local();
    const receiver = await createTeamKeyReceiver("alice", "team-1");
    const transfer = await alice.exportTeamKeys("team-1", receiver.request); // carried by the product's bridge
    const pageTeam = await receiver.openTeam({ store: keyStore.as("alice"), anchors: page, clock, settings }, transfer);
    expect(pageTeam.state).toBe("ready");
    expect(read(await (await pageTeam.openItem(id)).part(0, product.download(id, 0)))).toBe("the secret value");

    // 8. Alice rotates her account key: her team still opens, her phrase still works.
    await alice.rotate({ phrase: recoveryPhrase, newPin: "1234" });
    expect((await alice.openTeam("team-1")).state).toBe("ready");
    const newDevice = await vault("alice");
    await newDevice.recover(recoveryPhrase, "4321");
    expect((await newDevice.openTeam("team-1")).state).toBe("ready");

    // 9. A device of alice's may have been misused: one call from a clean device secures the
    //    account; bob's routine reconcile approves her proven re-key and rotates.
    const secured = await newDevice.secureAccount({ phrase: recoveryPhrase, newPin: "8642" });
    expect(secured).toEqual({ rekeyed: ["team-1"], failed: [] });
    const routine = await (await bob.openTeam("team-1")).owner().reconcile(["alice", "bob"]);
    expect(routine).toMatchObject({ approvedRekeys: ["alice"], needsHuman: [] });
    expect((await newDevice.openTeam("team-1")).state).toBe("ready");
    await expect(alice.unlock()).rejects.toSatisfy((e) => isConvoyError(e, "DEVICE_NOT_REGISTERED"));
  });
});
