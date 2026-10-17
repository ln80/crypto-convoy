/**
 * SP-22: for any team snapshot, the reconcile plan gives the new version to no account outside
 * the rule: a current holder with the same keys, a recovery-proven re-key of a non-owner, or an
 * opted-in, invite-proven first joiner of the current version. It never removes an owner or the caller.
 */
import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { createMemberKeys, keysHash, type MemberKeys } from "../../src/records/member-keys.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import type { Holder } from "../../src/team/grants.js";
import { planReconcile, type MembershipSnapshot, type OpenedInvite } from "../../src/team/membership.js";

const VERSION = 5;
type Newest = "none" | "same" | "continuity" | "recovery" | "foreign-recovery" | "invite-current" | "invite-old" | "invite-forged";
interface Case {
  holds: boolean;
  heldBefore: boolean;
  active: boolean;
  owner: boolean;
  newest: Newest;
}

const caseArb: fc.Arbitrary<Case> = fc.record({
  holds: fc.boolean(),
  heldBefore: fc.boolean(),
  active: fc.boolean(),
  owner: fc.boolean(),
  newest: fc.constantFrom<Newest>("none", "same", "continuity", "recovery", "foreign-recovery", "invite-current", "invite-old", "invite-forged"),
});

const secretOf = (version: number) => new Uint8Array(32).fill(version);

/** Builds real records for one account: version 1 keys (held or not), then its newest keys. */
function account(accountId: string, c: Case) {
  const recovery = cc1.signingKeyPair(cc1.randomBytes(32));
  const make = (version: number, proofs: Parameters<typeof createMemberKeys>[3] = {}) => {
    const signing = cc1.signingKeyPair(cc1.randomBytes(32));
    const encryption = cc1.generateEncryptionKeyPair();
    return {
      signing,
      record: createMemberKeys(
        cc1,
        {
          teamId: "team-1", accountId, memberKeysVersion: version, signingPublicKey: signing.publicKey,
          encryptionPublicKey: encryption.publicKey, recoveryPublicKey: recovery.publicKey, createdAt: 1,
        },
        signing.secretKey,
        proofs,
      ),
    };
  };
  const first = make(1, c.newest.startsWith("invite") && !c.holds && !c.heldBefore
    ? { invite: { inviteId: `invite-${accountId}`, secret: c.newest === "invite-forged" ? cc1.randomBytes(32) : secretOf(c.newest === "invite-old" ? VERSION - 1 : VERSION) } }
    : {});
  const keys: MemberKeys[] = [first.record];
  if (c.holds && c.newest !== "none" && c.newest !== "same" && !c.newest.startsWith("invite")) {
    const proofs =
      c.newest === "continuity" ? { previousSigningSecretKey: first.signing.secretKey }
      : c.newest === "recovery" ? { recoverySigningSecretKey: recovery.secretKey }
      : { recoverySigningSecretKey: cc1.signingKeyPair(cc1.randomBytes(32)).secretKey };
    keys.push(make(2, proofs).record);
  }
  return keys;
}

describe("SP-22: the reconcile plan never widens access outside its rule", () => {
  test.prop([fc.array(caseArb, { minLength: 1, maxLength: 6 }), fc.boolean()], { numRuns: 60 })("for any snapshot", (cases, optIn) => {
    const ids = cases.map((_, i) => `acct-${i}`);
    const self = "self";
    const keys = new Map<string, readonly MemberKeys[]>();
    const holders: Holder[] = [];
    const invites = new Map<string, OpenedInvite>();
    const signer = { accountId: self, signingPublicKey: cc1.signingKeyPair(cc1.randomBytes(32)).publicKey };
    cases.forEach((c, i) => {
      const id = ids[i]!;
      const list = account(id, c);
      keys.set(id, list);
      if (c.holds) holders.push({ accountId: id, memberKeysVersion: 1, keysHash: keysHash(cc1, list[0]!), teamKeyVersion: VERSION, signer });
      const version = c.newest === "invite-old" ? VERSION - 1 : VERSION;
      invites.set(`invite-${id}`, { inviteId: `invite-${id}`, teamKeyVersion: version, secret: secretOf(version) });
    });
    const snapshot: MembershipSnapshot = {
      version: VERSION,
      owners: [self, ...ids.filter((_, i) => cases[i]!.owner)],
      self,
      holders,
      keys,
      heldBefore: new Set(ids.filter((_, i) => cases[i]!.heldBefore && !cases[i]!.holds)),
      invites,
      active: new Set([self, ...ids.filter((_, i) => cases[i]!.active)]),
    };
    const plan = planReconcile(snapshot, optIn);

    for (const id of plan.remove) {
      const c = cases[ids.indexOf(id)]!;
      expect(c.holds && !c.active && !c.owner).toBe(true);
    }
    expect(plan.remove).not.toContain(self);
    for (const { accountId } of plan.approveRekeys) {
      const c = cases[ids.indexOf(accountId)]!;
      expect(c.holds && c.active && !c.owner && c.newest === "recovery").toBe(true);
    }
    for (const { keys: handle } of plan.admit) {
      const c = cases[ids.indexOf(handle.accountId)]!;
      expect(optIn && c.active && !c.holds && !c.heldBefore && c.newest === "invite-current").toBe(true);
    }
    // Everything else an active account needs is left to a human, never silently dropped.
    const acted = new Set([...plan.approveRekeys.map((h) => h.accountId), ...plan.admit.map((a) => a.keys.accountId)]);
    cases.forEach((c, i) => {
      const id = ids[i]!;
      const waiting = c.active && ((!c.holds) || (c.holds && keys.get(id)!.length > 1));
      if (waiting && !acted.has(id)) expect(plan.needsHuman.map((n) => n.accountId)).toContain(id);
    });
  });
});
