/**
 * Replay of the chain, roster and grant cases of team-key.v1.json (§4.2, §4.5, §4.6).
 * SP-05: only a current owner changes the chain. SP-07: anchors refuse rollback and forks.
 * SP-04: a grant opens only for the member's own keys, signed by an owner of its version.
 */
import { describe, expect, it } from "vitest";
import { trustFailure } from "../../src/errors.js";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { keysHash, parseMemberKeys } from "../../src/records/member-keys.js";
import { openRosterEntry, parseTeamKeyVersion, rosterEntryOf } from "../../src/records/team-key-version.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { verifyChain } from "../../src/team/chain.js";
import { checkOwnerRule } from "../../src/team/grants.js";
import { loadVectors, tohex, unhex } from "../support/vectors.js";

type Json = Record<string, unknown>;
interface TeamKeys {
  teamId: string;
  accounts: Record<string, { signingSeed: string; encryptionSecretKey: string; recoverySeed: string }>;
  keysHashes: Record<string, string>;
  memberKeys: Json[];
  versions: Record<string, { record: Json; recordHash: string }>;
  variants: Record<string, Json>;
  chainCases: { name: string; chain: (number | string)[]; anchors: [number, string][]; expect: { current?: number; error?: string; reason?: string } }[];
  grantCases: { name: string; grant: Json; member: string; expect: { teamKey?: string; error?: string; reason?: string } }[];
  rosterCases: { name: string; version: number; member: string; expect: { teamKey?: string; error?: string } }[];
}

const v = loadVectors<TeamKeys>("team-key.v1.json");
const memberKeys = v.memberKeys.map((m) => parseMemberKeys(m, { teamId: v.teamId, accountId: m["accountId"] as string }));
const recordOf = (ref: number | string) => (typeof ref === "number" ? v.versions[ref]!.record : v.variants[ref]!);
const pairOf = (member: string) => {
  const secret = unhex(v.accounts[member]!.encryptionSecretKey);
  return { publicKey: cc1.encryptionPublicKey(secret), secretKey: secret };
};
const ownHash = (member: string) => keysHash(cc1, memberKeys.find((m) => m.accountId === member)!);
const honest = verifyChain({ records: [1, 2, 3].map((n) => parseTeamKeyVersion(recordOf(n), { teamId: v.teamId })), anchors: [], memberKeys });

describe("team-key.v1: chain", () => {
  it.each(v.chainCases)("$name", ({ chain, anchors, expect: e }) => {
    const run = () =>
      verifyChain({
        records: chain.map((ref) => parseTeamKeyVersion(recordOf(ref), { teamId: v.teamId })),
        anchors: anchors.map(([version, hash]) => ({ version, hash: unhex(hash) })),
        memberKeys,
      });
    if (e.error) expect(run).toThrow(expect.objectContaining({ code: e.error, reason: e.reason }));
    else expect(run().records.at(-1)!.version).toBe(e.current);
  });
});

describe("team-key.v1: member keys", () => {
  it("recomputes each keys hash", () => {
    for (const m of memberKeys) expect(tohex(keysHash(cc1, m))).toBe(v.keysHashes[m.accountId]);
    for (const m of memberKeys) {
      expect(tohex(m.recoveryPublicKey)).toBe(tohex(cc1.signingKeyPair(unhex(v.accounts[m.accountId]!.recoverySeed)).publicKey));
    }
  });
});

describe("team-key.v1: rosters", () => {
  it.each(v.rosterCases)("$name", ({ version, member, expect: e }) => {
    const record = honest.records.find((r) => r.version === version)!;
    const run = () => {
      const entry = rosterEntryOf(record, member);
      if (!entry) throw new Error("NOT_GRANTED");
      if (!cc1.equal(entry.keysHash, ownHash(member))) throw trustFailure("key_mismatch");
      return openRosterEntry(record, entry, pairOf(member));
    };
    if (e.error) expect(run).toThrow(e.error);
    else expect(tohex(run())).toBe(e.teamKey);
  });
});

describe("team-key.v1: grants", () => {
  it.each(v.grantCases)("$name", ({ grant, member, expect: e }) => {
    const run = () => {
      const parsed = parseGrant(grant, { teamId: v.teamId, accountId: member });
      checkOwnerRule(parsed, honest);
      if (!cc1.equal(parsed.keysHash, ownHash(member))) throw trustFailure("key_mismatch");
      return openGrant(parsed, pairOf(member));
    };
    if (e.error) expect(run).toThrow(expect.objectContaining({ code: e.error, reason: e.reason }));
    else expect(tohex(run())).toBe(e.teamKey);
  });
});
