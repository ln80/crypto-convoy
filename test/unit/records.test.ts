/** Every record type round-trips through its JSON form, and is refused in another context (§4, §8). */
import { describe, expect, it } from "vitest";
import { openAccountKeyWrap, parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { openInboxKey, parseInbox } from "../../src/records/inbox.js";
import { openItemKey, openManifest, openPart, parseItem } from "../../src/records/item.js";
import { parseMemberKeys } from "../../src/records/member-keys.js";
import { openMemberKeysWrap, parseMemberKeysWrap } from "../../src/records/member-keys-wrap.js";
import { openEnvelope, openSubmissionPart, parseSubmission } from "../../src/records/submission.js";
import { openTeamState, parseTeamState } from "../../src/records/team-state.js";
import { parsers } from "../support/parsers.js";
import { sampleRecords } from "../support/records.js";

const sample = sampleRecords();
const { records, secrets } = sample;
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("records round-trip", () => {
  it.each(Object.entries(parsers(sample.submissionId)))("%s parses its own JSON", (_, parse) => {
    expect(() => parse(JSON.parse(JSON.stringify(records[_ as keyof typeof records])))).not.toThrow();
  });

  it("opens every secret it wrapped", () => {
    const wrap = parseAccountKeyWrap(records["account-key-wrap"], { accountId: "alice", accountKeyVersion: 1, method: "recovery" });
    expect([...openAccountKeyWrap(wrap, secrets.methodKey)]).toEqual([...secrets.accountKey]);

    const published = parseMemberKeys(records["member-keys"], { teamId: "team-1", accountId: "alice" });
    const keysWrap = parseMemberKeysWrap(records["member-keys-wrap"], { accountId: "alice", teamId: "team-1", accountKeyVersion: 1 });
    expect([...openMemberKeysWrap(keysWrap, secrets.accountKey, published).teamStateKey]).toEqual([...secrets.bundle.teamStateKey]);

    const state = parseTeamState(records["team-state"], { accountId: "alice", teamId: "team-1" });
    expect(openTeamState(state, secrets.bundle.teamStateKey).version).toBe(1);

    const grant = parseGrant(records.grant, { teamId: "team-1" });
    expect([...openGrant(grant, secrets.pairs.encryption)]).toEqual([...secrets.teamKey]);

    const item = parseItem(records.item, { teamId: "team-1", itemId: "item-1" });
    const itemKey = openItemKey(item, secrets.teamKey);
    const [entry] = openManifest(item, itemKey);
    expect([...entry!.meta]).toEqual([1]);
    expect(text(openPart(item, itemKey, entry!, sample.parts.item[0]!))).toBe("hi");

    const inbox = parseInbox(records.inbox, { teamId: "team-1", inboxId: "inbox-1" });
    const submission = parseSubmission(records.submission, { teamId: "team-1", inboxId: "inbox-1", submissionId: sample.submissionId });
    const envelope = openEnvelope(submission, openInboxKey(inbox, secrets.teamKey));
    expect(text(openSubmissionPart(submission, envelope, envelope.manifest[0]!, sample.parts.submission[0]!))).toBe("hello");
  });
});

describe("§8 step 3: context", () => {
  it.each([
    ["item of another team", () => parseItem(records.item, { teamId: "team-2", itemId: "item-1" })],
    ["item under another id", () => parseItem(records.item, { teamId: "team-1", itemId: "item-2" })],
    ["account wrap of another version", () => parseAccountKeyWrap(records["account-key-wrap"], { accountId: "alice", accountKeyVersion: 2, method: "recovery" })],
    ["account wrap of another method", () => parseAccountKeyWrap({ ...records["account-key-wrap"] }, { accountId: "alice", accountKeyVersion: 1, method: "recovery", deviceId: "x" })],
    ["team state of another account", () => parseTeamState(records["team-state"], { accountId: "bob", teamId: "team-1" })],
    ["grant of another version", () => parseGrant(records.grant, { teamId: "team-1", teamKeyVersion: 2 })],
  ])("refuses the %s", (_, run) => {
    expect(run).toThrow(expect.objectContaining({ code: "TRUST_FAILURE", reason: "context_mismatch" }));
  });

  it("refuses a state opened with another key as state_unreadable", () => {
    const state = parseTeamState(records["team-state"], { accountId: "alice", teamId: "team-1" });
    expect(() => openTeamState(state, secrets.teamKey)).toThrow(expect.objectContaining({ reason: "state_unreadable" }));
  });

  it("refuses member keys that don't match the published record", () => {
    const keysWrap = parseMemberKeysWrap(records["member-keys-wrap"], { accountId: "alice", teamId: "team-1", accountKeyVersion: 1 });
    const other = sampleRecords();
    const published = parseMemberKeys(other.records["member-keys"], { teamId: "team-1", accountId: "alice" });
    expect(() => openMemberKeysWrap(keysWrap, secrets.accountKey, published)).toThrow(
      expect.objectContaining({ code: "TRUST_FAILURE", reason: "key_mismatch" }),
    );
  });
});
