/**
 * Replay of the chain and grant cases of team-key.v1.json (§4.5, §4.6).
 * SP-05: only a current owner changes the chain. SP-07: anchors refuse rollback and forks.
 * SP-04: a grant opens only for the member's own keys, signed by an owner of its version.
 */
import { describe, expect, it } from "vitest";
import { trustFailure } from "../../src/errors.js";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { parseMemberKeys } from "../../src/records/member-keys.js";
import { parseTeamKeyVersion } from "../../src/records/team-key-version.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { verifyChain } from "../../src/team/chain.js";
import { checkOwnerRule } from "../../src/team/grants.js";
import { loadVectors, tohex, unhex } from "../support/vectors.js";

type Json = Record<string, unknown>;
interface TeamKeys {
  teamId: string;
  accounts: Record<string, { signingSeed: string; encryptionSecretKey: string }>;
  memberKeys: Json[];
  versions: Record<string, { record: Json; recordHash: string }>;
  variants: Record<string, Json>;
  chainCases: { name: string; chain: (number | string)[]; anchors: [number, string][]; expect: { current?: number; error?: string; reason?: string } }[];
  grantCases: { name: string; grant: Json; member: string; expect: { teamKey?: string; error?: string; reason?: string } }[];
}

const v = loadVectors<TeamKeys>("team-key.v1.json");
const memberKeys = v.memberKeys.map((m) => parseMemberKeys(m, { teamId: v.teamId, accountId: m["accountId"] as string }));
const recordOf = (ref: number | string) => (typeof ref === "number" ? v.versions[ref]!.record : v.variants[ref]!);
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

describe("team-key.v1: grants", () => {
  it.each(v.grantCases)("$name", ({ grant, member, expect: e }) => {
    const secret = unhex(v.accounts[member]!.encryptionSecretKey);
    const pair = { publicKey: cc1.encryptionPublicKey(secret), secretKey: secret };
    const signingKey = cc1.signingKeyPair(unhex(v.accounts[member]!.signingSeed)).publicKey;
    const run = () => {
      const parsed = parseGrant(grant, { teamId: v.teamId, accountId: member });
      checkOwnerRule(parsed, honest);
      const own = cc1.equal(parsed.memberEncryptionPublicKey, pair.publicKey) && cc1.equal(parsed.memberSigningPublicKey, signingKey);
      if (!own) throw trustFailure("key_mismatch");
      return openGrant(parsed, pair);
    };
    if (e.error) expect(run).toThrow(expect.objectContaining({ code: e.error, reason: e.reason }));
    else expect(tohex(run())).toBe(e.teamKey);
  });
});
