/**
 * Replay of team-key.v1.json (record level), item.v1.json and submission.v1.json (§4).
 * SP-03: moved or tampered records fail. SP-05: version records verify strictly.
 * Chain and owner-rule cases are replayed in team-chain.vectors.test.ts.
 */
import { describe, expect, it } from "vitest";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { openItemKey, openManifest, openPart, parseItem } from "../../src/records/item.js";
import { parseMemberKeys } from "../../src/records/member-keys.js";
import { openEnvelope, openSubmissionPart, parseSubmission } from "../../src/records/submission.js";
import { parseTeamKeyVersion, recordHash, teamKeyVersionPayload } from "../../src/records/team-key-version.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { loadVectors, tohex, unhex } from "../support/vectors.js";

type Json = Record<string, unknown>;
interface TeamKeys {
  teamId: string;
  accounts: Record<string, { signingSeed: string; encryptionSecretKey: string }>;
  teamKeys: Record<string, string>;
  memberKeys: Json[];
  versions: Record<string, { record: Json; payload: string; recordHash: string }>;
  grantCases: { name: string; grant: Json; member: string; expect: { teamKey?: string; error?: string } }[];
  recordCases: { name: string; record: Json; expect: { error: string; reason?: string } }[];
}
interface Items {
  teamKey: string;
  itemKey: string;
  record: Json;
  manifest: string;
  parts: { ciphertext: string; plaintext: string; meta: string }[];
  tampered: { name: string; record: Json; expectedItemId?: string; error: string; reason?: string }[];
  swappedParts: { name: string; order: number[]; error: string }[];
}
interface Submissions {
  inbox: { secretKey: string; publicKey: string };
  contentKey: string;
  createdAt: number;
  record: Json;
  parts: { ciphertext: string; plaintext: string }[];
  tampered: { name: string; record: Json; error: string }[];
}

const team = loadVectors<TeamKeys>("team-key.v1.json");
const items = loadVectors<Items>("item.v1.json");
const submissions = loadVectors<Submissions>("submission.v1.json");
const failure = (e: { error: string; reason?: string }) =>
  expect.objectContaining(e.reason ? { code: e.error, reason: e.reason } : { code: e.error });

describe("team-key.v1: records", () => {
  it.each(team.memberKeys)("member keys of $accountId verify", (record) => {
    expect(() => parseMemberKeys(record, { teamId: team.teamId, accountId: record["accountId"] as string })).not.toThrow();
  });

  it.each(Object.entries(team.versions))("version %s: payload, record hash and signature", (_, vector) => {
    const record = parseTeamKeyVersion(vector.record, { teamId: team.teamId });
    expect(tohex(teamKeyVersionPayload(cc1, record))).toBe(vector.payload);
    expect(tohex(recordHash(record))).toBe(vector.recordHash);
  });

  it.each(team.recordCases)("refuses $name", ({ record, expect: e }) => {
    expect(() => parseTeamKeyVersion(record, { teamId: team.teamId })).toThrow(failure(e));
  });

  it.each(team.grantCases.filter((c) => c.expect.teamKey))("$name opens the team key", ({ grant, member, expect: e }) => {
    const encryptionSecretKey = unhex(team.accounts[member]!.encryptionSecretKey);
    const record = parseGrant(grant, { teamId: team.teamId, accountId: member });
    const teamKey = openGrant(record, { publicKey: cc1.encryptionPublicKey(encryptionSecretKey), secretKey: encryptionSecretKey });
    expect(tohex(teamKey)).toBe(e.teamKey);
  });
});

describe("item.v1", () => {
  const expected = { teamId: "team-1", itemId: "item-1" };

  it("opens the item key, manifest and parts", () => {
    const record = parseItem(items.record, expected);
    const itemKey = openItemKey(record, unhex(items.teamKey));
    expect(tohex(itemKey)).toBe(items.itemKey);
    const manifest = openManifest(record, itemKey);
    manifest.forEach((entry, i) => {
      expect(tohex(entry.meta)).toBe(items.parts[i]!.meta);
      expect(tohex(openPart(record, itemKey, entry, unhex(items.parts[i]!.ciphertext)))).toBe(items.parts[i]!.plaintext);
    });
  });

  it.each(items.tampered)("SP-03: refuses $name", ({ record, expectedItemId, error, reason }) => {
    const run = () => {
      const parsed = parseItem(record, { ...expected, itemId: expectedItemId ?? (record["itemId"] as string) });
      openManifest(parsed, openItemKey(parsed, unhex(items.teamKey)));
    };
    expect(run).toThrow(failure({ error, reason }));
  });

  it.each(items.swappedParts.filter((s) => s.order.length === items.parts.length))("SP-03: refuses $name", ({ order, error }) => {
    const record = parseItem(items.record, expected);
    const itemKey = unhex(items.itemKey);
    const manifest = openManifest(record, itemKey);
    expect(() => manifest.forEach((entry, i) => openPart(record, itemKey, entry, unhex(items.parts[order[i]!]!.ciphertext)))).toThrow(
      failure({ error }),
    );
  });
});

describe("submission.v1", () => {
  const inboxKey = { publicKey: unhex(submissions.inbox.publicKey), secretKey: unhex(submissions.inbox.secretKey) };
  const expected = { teamId: "team-1", inboxId: "inbox-1", submissionId: submissions.record["submissionId"] as string };

  it("opens the envelope and parts", () => {
    const record = parseSubmission(submissions.record, expected);
    const envelope = openEnvelope(record, inboxKey);
    expect(tohex(envelope.contentKey)).toBe(submissions.contentKey);
    expect(envelope.createdAt).toBe(submissions.createdAt);
    envelope.manifest.forEach((entry, i) => {
      expect(tohex(openSubmissionPart(record, envelope, entry, unhex(submissions.parts[i]!.ciphertext)))).toBe(submissions.parts[i]!.plaintext);
    });
  });

  it.each(submissions.tampered)("SP-03: refuses $name", ({ record, error }) => {
    expect(() => openEnvelope(parseSubmission(record, { ...expected, submissionId: record["submissionId"] as string }), inboxKey)).toThrow(
      failure({ error }),
    );
  });
});
