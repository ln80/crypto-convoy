/**
 * The library through its public entry points only, shaped like a product's pipelines:
 * a value encrypted before the server assigns an id, files uploaded one by one, the key record
 * sealed at finalize; per-part reveal; an intake from outside; a vault and a page in separate
 * contexts. Doubles as executable documentation. Covers SP-02, SP-06, SP-12, SP-14, SP-15 end to end.
 */
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
    const vault = (accountId: string, keys = local()) =>
      createVault({ store: keyStore.as(accountId), oprf, deviceKeys: keys, anchors: keys, clock, settings }, accountId);

    // 1. Encryption setup: the owner creates the team; a member joins and waits for approval.
    const alice = await vault("alice");
    expect((await alice.status()).account).toBe("not-set-up");
    const { recoveryPhrase } = await alice.setup("1234");
    expect(await alice.status()).toEqual({ account: "unlocked", deviceRegistered: true });
    await alice.createTeam("team-1");
    const team = await alice.openTeam("team-1");
    expect((await team.warnings(["alice"])).map((w) => w.code)).toEqual(["single-owner"]);

    const bob = await vault("bob");
    await bob.setup("5678");
    expect((await team.memberStatuses(["bob"]))[0]!.status).toBe("no-keys");
    await bob.joinTeam("team-1");
    expect((await bob.openTeam("team-1", { anchor: team.inviteAnchor() })).state).toBe("pending");
    expect(await team.memberStatuses(["bob"])).toEqual([{ accountId: "bob", status: "awaiting-approval", continuity: "new" }]);
    expect((await team.warnings(["alice", "bob"])).find((w) => w.code === "members-awaiting-approval")?.accountIds).toEqual(["bob"]);
    await team.grant("bob", (await team.memberRequest("bob")).memberKeysVersion);
    expect((await team.memberStatuses(["bob"]))[0]!.status).toBe("approved");

    // 2. Secret creation: the value is encrypted before the server assigns the id, files are
    //    uploaded one by one (streamed), and the key record is sealed at finalize.
    const bobTeam = await bob.openTeam("team-1");
    const draft = bobTeam.beginItem();
    const id = product.createResource(draft.addPart(text("the secret value"), { meta: text('{"kind":"text"}') }));
    const file = Uint8Array.from({ length: 5 * 1024 * 1024 + 7 }, (_, i) => i % 251);
    const ref = draft.partRef(file); // safe to send the server, e.g. for deduplication
    product.upload(id, 1, await collect(draft.addPartStream(chunks(file), { meta: text("report.pdf") })));
    await draft.seal(id);
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
    await team.setOwners(["alice", "bob"], { keep: ["bob"] });
    const bobOwner = await bob.openTeam("team-1");
    expect(bobOwner.ownerChanges.map((c) => c.added)).toEqual([["bob"]]);
    expect((await bobOwner.warnings(["bob"])).map((w) => w.code)).toContain("rotation-needed");
    await bobOwner.setOwners(["bob"], { keep: [] });
    const later = bobOwner.beginItem();
    later.addPart(text("alice can't read this"));
    await later.seal("after-removal");
    const aliceView = await alice.openTeam("team-1");
    expect(aliceView.state).toBe("pending");
    await expect(aliceView.openItem("after-removal")).rejects.toSatisfy((e) => isConvoyError(e, "NOT_GRANTED"));

    // 6. Alice re-keys; bob sees the continuity hint and grants her new keys (never the replaced ones).
    await alice.rekey("team-1");
    expect(await bobOwner.memberStatuses(["alice"])).toEqual([{ accountId: "alice", status: "outdated", continuity: "routine" }]);
    await expect(bobOwner.grant("alice", 1)).rejects.toSatisfy((e) => isConvoyError(e, "STALE_VERSION"));
    await bobOwner.grant("alice", 2);
    expect((await alice.openTeam("team-1")).state).toBe("ready");

    // 7. Separate contexts: the vault on one origin, team work on the product's page.
    const page = local();
    const receiver = await createTeamKeyReceiver("alice", "team-1");
    const transfer = await alice.exportTeamKeys("team-1", receiver.request); // carried by the product's bridge
    const pageTeam = await receiver.openTeam({ store: keyStore.as("alice"), anchors: page, clock, settings }, transfer);
    expect(pageTeam.state).toBe("ready");
    expect(read(await (await pageTeam.openItem(id)).part(0, product.download(id, 0)))).toBe("the secret value");

    // 8. Alice rotates her account key: her team still opens, her phrase still works.
    await alice.rotate({ pin: "1234", phrase: recoveryPhrase });
    expect((await alice.openTeam("team-1")).state).toBe("ready");
    const newDevice = await vault("alice");
    await newDevice.recover(recoveryPhrase, "4321");
    expect((await newDevice.openTeam("team-1")).state).toBe("ready");
  });
});
