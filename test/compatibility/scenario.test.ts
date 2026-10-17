/**
 * The whole library through its public entry points only, as an integration would use it.
 * Doubles as executable documentation. Covers SP-06, SP-11, SP-12, SP-14 end to end.
 */
import { describe, expect, it } from "vitest";
import { createLinkClient, createVault, isConvoyError, type OpenedPart, type Settings } from "../../src/index.js";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore, fixedClock } from "../../src/testing/index.js";

const settings: Settings = { argon2: { write: { opslimit: 2, memlimit: 64 * 1024 * 1024 } } };
const text = (s: string) => new TextEncoder().encode(s);
const read = (parts: OpenedPart[]) => parts.map((p) => new TextDecoder().decode(p.content));

describe("scenario", () => {
  it("runs a team's life: setup, join, share, inbox, removal, re-key, owners, account rotation", async () => {
    const server = new MemoryRecordStore();
    const oprf = new FakeOprfServer();
    const clock = fixedClock();
    const vault = (accountId: string) =>
      createVault({ store: server.as(accountId), oprf, localKeys: new MemoryLocalKeyStore(), clock, settings }, accountId);

    // 1. Two accounts; alice creates the team, bob joins with the invite anchor, alice grants him.
    const alice = await vault("alice");
    const { recoveryPhrase } = await alice.setup("1234");
    const bob = await vault("bob");
    await bob.setup("5678");
    const team = await alice.createTeam("team-1");
    const bobPending = await bob.joinTeam("team-1", { anchor: team.inviteAnchor() });
    expect(bobPending.state).toBe("pending");
    const request = await team.memberRequest("bob");
    expect(request.continuity).toBe("new");
    await team.grant("bob", request.memberKeysVersion);
    const bobTeam = await bob.openTeam("team-1");
    expect(bobTeam.state).toBe("ready");

    // 2. Items, a share link, an inbox and a submission.
    await bobTeam.createItem("note", [{ content: text("hello team"), meta: text('{"type":"text"}') }]);
    expect(read(await team.openItem("note"))).toEqual(["hello team"]);
    const outsider = await createLinkClient({ store: server.anonymous(), clock });
    expect(read(await outsider.openSharedItem(await team.shareLinkKey("note"), "team-1", "note"))).toEqual(["hello team"]);
    const { linkKey } = await team.createInbox("requests");
    const { submissionId } = await outsider.submitToInbox(linkKey, "team-1", "requests", [{ content: text("a document") }]);
    expect(read((await bobTeam.openSubmission("requests", submissionId)).parts)).toEqual(["a document"]);

    // 3. Bob becomes an owner; then bob removes alice's access, alice is no longer an owner.
    await team.setOwners(["alice", "bob"], { keep: ["bob"] });
    const bobOwner = await bob.openTeam("team-1");
    expect(bobOwner.ownerChanges.map((c) => c.added)).toEqual([["bob"]]);
    await bobOwner.setOwners(["bob"], { keep: [] });
    await bobOwner.createItem("after-removal", [{ content: text("alice can't read this") }]);
    const aliceView = await alice.openTeam("team-1");
    expect(aliceView.state).toBe("pending");
    await expect(aliceView.openItem("after-removal")).rejects.toSatisfy((e) => isConvoyError(e, "NOT_GRANTED"));
    expect(read(await aliceView.openItem("note"))).toEqual(["hello team"]);

    // 4. Alice re-keys; bob checks the continuity hint and approves her keys back by rotating.
    await alice.rekey("team-1");
    expect((await bobOwner.memberRequest("alice")).continuity).toBe("routine");
    await bobOwner.grant("alice", 1);
    await bobOwner.rotate({ keep: ["alice"], approveRekeys: ["alice"] });
    expect((await alice.openTeam("team-1")).state).toBe("ready");

    // 5. Alice rotates her account key: her team still opens, her phrase still works.
    await alice.rotate({ pin: "1234", phrase: recoveryPhrase });
    expect(read(await (await alice.openTeam("team-1")).openItem("after-removal"))).toEqual(["alice can't read this"]);
    const newDevice = await vault("alice");
    await newDevice.recover(recoveryPhrase, "4321");
    expect((await newDevice.openTeam("team-1")).state).toBe("ready");
  });
});
