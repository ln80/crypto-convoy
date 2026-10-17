/**
 * Replay of invite.v1.json (§4.2, §4.11).
 * SP-24: an invite proof verifies only with the invite's join secret, over exactly the joiner's keys.
 */
import { describe, expect, it } from "vitest";
import { openInviteSecret, parseInvite } from "../../src/records/invite.js";
import { hasValidInviteProof, type MemberKeys } from "../../src/records/member-keys.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { loadVectors, tohex, unhex } from "../support/vectors.js";

type Json = Record<string, unknown>;
interface Invites {
  teamId: string;
  teamKey: string;
  joinSecret: string;
  owner: { accountId: string; signingPublicKey: string };
  joiner: { accountId: string; memberKeysVersion: number; signingPublicKey: string; encryptionPublicKey: string; recoveryPublicKey: string };
  invites: Record<string, Json>;
  proofCases: { name: string; inviteId: string; mac: string; expect: boolean }[];
  refused: { name: string; record: Json; error: string; reason?: string }[];
}

const v = loadVectors<Invites>("invite.v1.json");

describe("invite.v1: records", () => {
  it.each(Object.entries(v.invites))("opens the join secret of %s", (_, json) => {
    const record = parseInvite(json, { teamId: v.teamId, inviteId: json["inviteId"] as string });
    expect(tohex(record.signer.signingPublicKey)).toBe(v.owner.signingPublicKey);
    expect(tohex(openInviteSecret(record, unhex(v.teamKey)))).toBe(v.joinSecret);
  });

  it.each(v.refused)("refuses $name", ({ record, error, reason }) => {
    const run = () => {
      const parsed = parseInvite(record, { teamId: v.teamId, inviteId: "invite-1" });
      return openInviteSecret(parsed, unhex(v.teamKey));
    };
    expect(run).toThrow(expect.objectContaining({ code: error, ...(reason ? { reason } : {}) }));
  });
});

describe("invite.v1: proofs", () => {
  const joiner = {
    suite: cc1,
    teamId: v.teamId,
    accountId: v.joiner.accountId,
    memberKeysVersion: v.joiner.memberKeysVersion,
    signingPublicKey: unhex(v.joiner.signingPublicKey),
    encryptionPublicKey: unhex(v.joiner.encryptionPublicKey),
    recoveryPublicKey: unhex(v.joiner.recoveryPublicKey),
  };
  it.each(v.proofCases)("$name", ({ inviteId, mac, expect: valid }) => {
    const record = { ...joiner, inviteProof: { inviteId, mac: unhex(mac) } } as unknown as MemberKeys;
    expect(hasValidInviteProof(record, "invite-1", unhex(v.joinSecret))).toBe(valid);
  });
});
