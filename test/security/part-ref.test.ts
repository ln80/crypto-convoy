/**
 * SP-21: A part reference reveals nothing without the item key.
 * Threats: TH-40.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { cc1 } from "../../src/suites/cc1/index.js";
import { outsider } from "../support/link-client.js";
import { team } from "../support/teams.js";

const file = new TextEncoder().encode("the same file, attached twice");

describe("SP-21: part references are keyed per item", () => {
  it("the same content gives different references in two items, and in an item and a submission", async () => {
    const { aliceTeam } = await team();
    const a = aliceTeam.beginItem();
    const b = aliceTeam.beginItem();
    expect(a.partRef(file)).not.toBe(b.partRef(file));
    const { linkKey } = await aliceTeam.createInbox("inbox-1");
    const submission = (await outsider()).beginSubmission(linkKey, "team-1", "inbox-1");
    expect(submission.partRef(file)).not.toBe(a.partRef(file));
  });

  it("equal content within an item gives equal references, for deduplication", async () => {
    const { aliceTeam } = await team();
    const draft = aliceTeam.beginItem();
    expect(draft.partRef(file)).toBe(draft.partRef(file.slice()));
    expect(draft.partRef(file)).not.toBe(draft.partRef(new TextEncoder().encode("another file")));
  });

  it("matches no unkeyed hash of the content", async () => {
    const { aliceTeam } = await team();
    const ref = aliceTeam.beginItem().partRef(file);
    const plain = [cc1.hash(file), createHash("sha256").update(file).digest()];
    for (const hash of plain) expect(ref).not.toBe(Buffer.from(hash).toString("base64url"));
  });

  it("a streamed reference equals the buffered one", async () => {
    const { aliceTeam } = await team();
    const draft = aliceTeam.beginItem();
    async function* chunks() {
      yield file.subarray(0, 7);
      yield file.subarray(7);
    }
    expect(await draft.partRefStream(chunks())).toBe(draft.partRef(file));
  });
});
