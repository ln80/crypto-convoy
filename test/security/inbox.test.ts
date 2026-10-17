/**
 * SP-14: Only the team can open inbox submissions.
 * Threats: TH-21, TH-22, TH-30.
 */
import { describe, expect, it } from "vitest";
import { submit } from "../../src/content/inbox.js";
import { encodeLinkKey } from "../../src/encoding/link.js";
import { openEnvelope, parseSubmission } from "../../src/records/submission.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { TamperingStore } from "../support/fake-store.js";
import { outsider } from "../support/link-client.js";
import { team } from "../support/teams.js";

const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);

describe("SP-14: only the team opens inbox submissions", () => {
  it("a member opens what an outside sender submitted", async () => {
    const { aliceTeam, members, w } = await team("bob");
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const { submissionId } = await submit(outsider(w.server.anonymous()), linkKey, "team-1", "inbox-1", [{ content: text("hello"), meta: text("m") }]);
    const opened = await (await members.bob!.vault.openTeam("team-1")).openSubmission("inbox-1", submissionId);
    expect(opened.parts.map((p) => read(p.content))).toEqual(["hello"]);
    expect(read(opened.parts[0]!.meta)).toBe("m");
  });

  it("a sender can't open another sender's submission", async () => {
    const { aliceTeam, w } = await team();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const sender = outsider(w.server.anonymous());
    const { submissionId } = await submit(sender, linkKey, "team-1", "inbox-1", [{ content: text("secret") }]);
    const record = parseSubmission(await w.server.anonymous().get({ type: "submission", teamId: "team-1", inboxId: "inbox-1", submissionId }), {
      teamId: "team-1",
      inboxId: "inbox-1",
      submissionId,
    });
    // What a sender holds: the public key from the link, and any key pair of their own.
    const own = cc1.generateEncryptionKeyPair();
    expect(() => openEnvelope(record, own)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });

  it("another team's keys can't open the submission", async () => {
    const { aliceTeam, members, w } = await team();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const { submissionId } = await submit(outsider(w.server.anonymous()), linkKey, "team-1", "inbox-1", [{ content: text("x") }]);
    const other = await members.alice!.vault.createTeam("team-2");
    await other.createInbox("inbox-1");
    const alice = members.alice!;
    const team2Inbox = await alice.store.get({ type: "inbox", teamId: "team-2", inboxId: "inbox-1" });
    alice.store.replace({ type: "inbox", teamId: "team-1", inboxId: "inbox-1" }, { ...(team2Inbox as object), teamId: "team-1" });
    const session = await alice.vault.openTeam("team-1");
    await expect(session.openSubmission("inbox-1", submissionId)).rejects.toEqual(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });

  it("the sender seals to the key in the link, whatever the server offers (TH-21)", async () => {
    const { aliceTeam, members, w } = await team();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const attacker = cc1.generateEncryptionKeyPair();
    const store = new TamperingStore(w.server.anonymous());
    store.replace({ type: "inbox", inboxId: "inbox-1" }, { publicKey: Buffer.from(attacker.publicKey).toString("base64url") });
    const { submissionId } = await submit(outsider(store), linkKey, "team-1", "inbox-1", [{ content: text("to the team") }]);
    const record = parseSubmission(await store.get({ type: "submission", teamId: "team-1", inboxId: "inbox-1", submissionId }), {
      teamId: "team-1",
      inboxId: "inbox-1",
      submissionId,
    });
    expect(() => openEnvelope(record, attacker)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
    expect((await (await members.alice!.vault.openTeam("team-1")).openSubmission("inbox-1", submissionId)).parts).toHaveLength(1);
  });

  it("refuses a low-order inbox key in a link", async () => {
    const { w } = await team();
    await expect(submit(outsider(w.server.anonymous()), encodeLinkKey(new Uint8Array(32)), "team-1", "inbox-1", [{ content: text("x") }])).rejects.toEqual(
      expect.objectContaining({ code: "MALFORMED_RECORD" }),
    );
  });

  it("Limit: a member removed after the inbox was created can still open new submissions (TH-30)", async () => {
    const { aliceTeam, members, w } = await team("bob");
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const bobSession = await members.bob!.vault.openTeam("team-1");
    await aliceTeam.rotate({ keep: [] });
    const { submissionId } = await submit(outsider(w.server.anonymous()), linkKey, "team-1", "inbox-1", [{ content: text("later") }]);
    expect(read((await bobSession.openSubmission("inbox-1", submissionId)).parts[0]!.content)).toBe("later");

    // Replacing the inbox ends it: the new key pair is under a version bob never received.
    const { linkKey: replaced } = await aliceTeam.replaceInbox("inbox-1", "inbox-2");
    const { submissionId: next } = await submit(outsider(w.server.anonymous()), replaced, "team-1", "inbox-2", [{ content: text("new") }]);
    await expect(bobSession.openSubmission("inbox-2", next)).rejects.toEqual(expect.objectContaining({ code: "NOT_GRANTED" }));
  });
});
