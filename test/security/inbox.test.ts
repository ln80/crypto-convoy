/**
 * SP-14: Only the team can open inbox submissions.
 * Threats: TH-21, TH-22, TH-30.
 */
import { describe, expect, it } from "vitest";
import { encodeLinkKey } from "../../src/encoding/link.js";
import { openEnvelope, parseSubmission } from "../../src/records/submission.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { ContentStore, addParts, read } from "../support/content-store.js";
import { outsider } from "../support/link-client.js";
import { team } from "../support/teams.js";

/** An outside sender's submission: parts uploaded, then sealed with the id the integration chose. */
async function send(linkKey: string, content: ContentStore, submissionId: string, values: string[], inboxId = "inbox-1") {
  const draft = (await outsider()).beginSubmission(linkKey, "team-1", inboxId);
  addParts(draft, content, submissionId, values);
  const record = await draft.seal(submissionId);
  content.putRecord(submissionId, record);
  return record;
}

describe("SP-14: only the team opens inbox submissions", () => {
  it("a member opens what an outside sender submitted, part by part", async () => {
    const { aliceTeam, members } = await team("bob");
    const content = new ContentStore();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    await send(linkKey, content, "sub-1", ["hello", "file"]);
    const opened = await (await members.bob!.vault.openTeam("team-1")).openSubmission("inbox-1", "sub-1", content.record("sub-1"));
    expect(opened.parts).toHaveLength(2);
    expect(read(await opened.part(1, content.get("sub-1", 1)))).toBe("file");
  });

  it("a sender can't open another sender's submission", async () => {
    const { aliceTeam } = await team();
    const content = new ContentStore();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const record = parseSubmission(await send(linkKey, content, "sub-1", ["secret"]), { teamId: "team-1", inboxId: "inbox-1", submissionId: "sub-1" });
    // What a sender holds: the public key from the link, and any key pair of their own.
    expect(() => openEnvelope(record, cc1.generateEncryptionKeyPair())).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });

  it("refuses an envelope under another id or for another inbox", async () => {
    const { aliceTeam } = await team();
    const content = new ContentStore();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    await aliceTeam.createInbox("inbox-2");
    await send(linkKey, content, "sub-1", ["x"]);
    await expect(aliceTeam.openSubmission("inbox-1", "sub-2", { ...(content.record("sub-1") as object), submissionId: "sub-2" })).rejects.toEqual(
      expect.objectContaining({ code: "DECRYPTION_FAILED" }),
    );
    await expect(aliceTeam.openSubmission("inbox-2", "sub-1", { ...(content.record("sub-1") as object), inboxId: "inbox-2" })).rejects.toEqual(
      expect.objectContaining({ code: "DECRYPTION_FAILED" }),
    );
  });

  it("another team's inbox key can't open the submission", async () => {
    const { aliceTeam, members } = await team();
    const content = new ContentStore();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    await send(linkKey, content, "sub-1", ["x"]);
    const alice = members.alice!;
    await alice.vault.createTeam("team-2");
    await (await alice.vault.openTeam("team-2")).createInbox("inbox-1");
    const other = await alice.store.get({ type: "inbox", teamId: "team-2", inboxId: "inbox-1" });
    alice.store.replace({ type: "inbox", teamId: "team-1", inboxId: "inbox-1" }, { ...(other as object), teamId: "team-1" });
    const session = await alice.vault.openTeam("team-1");
    await expect(session.openSubmission("inbox-1", "sub-1", content.record("sub-1"))).rejects.toEqual(
      expect.objectContaining({ code: "DECRYPTION_FAILED" }),
    );
  });

  it("the sender seals to the key in the link: no server is consulted (TH-21)", async () => {
    const { aliceTeam } = await team();
    const content = new ContentStore();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const attacker = cc1.generateEncryptionKeyPair();
    const record = parseSubmission(await send(linkKey, content, "sub-1", ["to the team"]), { teamId: "team-1", inboxId: "inbox-1", submissionId: "sub-1" });
    expect(() => openEnvelope(record, attacker)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
    expect((await aliceTeam.openSubmission("inbox-1", "sub-1", content.record("sub-1"))).parts).toHaveLength(1);
  });

  it("refuses a low-order inbox key in a link", async () => {
    await expect((async () => (await outsider()).beginSubmission(encodeLinkKey(new Uint8Array(32)), "team-1", "inbox-1"))()).rejects.toEqual(
      expect.objectContaining({ code: "MALFORMED_RECORD" }),
    );
  });

  it("Limit: a member removed after the inbox was created can still open new submissions (TH-30)", async () => {
    const { aliceTeam, members } = await team("bob");
    const content = new ContentStore();
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const bobSession = await members.bob!.vault.openTeam("team-1");
    await aliceTeam.owner().rotate({ keep: [] });
    await send(linkKey, content, "sub-1", ["later"]);
    const opened = await bobSession.openSubmission("inbox-1", "sub-1", content.record("sub-1"));
    expect(read(await opened.part(0, content.get("sub-1", 0)))).toBe("later");

    // Replacing the inbox ends it: the new key pair is under a version bob never received.
    const { linkKey: replaced } = await aliceTeam.replaceInbox("inbox-1", "inbox-2");
    await send(replaced, content, "sub-2", ["new"], "inbox-2");
    await expect(bobSession.openSubmission("inbox-2", "sub-2", content.record("sub-2"))).rejects.toEqual(
      expect.objectContaining({ code: "NOT_GRANTED" }),
    );
  });
});
