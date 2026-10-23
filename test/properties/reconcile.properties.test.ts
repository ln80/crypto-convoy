/**
 * SP-22: for any team snapshot, the reconcile plan gives the new version to no account outside
 * the rule: a current holder with the same keys, a recovery-proven re-key of a non-owner, or the
 * caller's own re-key to keys its session holds (D-47). It never removes an owner or the caller,
 * and leaves every other pending account to a human.
 */
import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { createMemberKeys, keysHash, type MemberKeys } from "../../src/records/member-keys.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import type { Holder } from "../../src/team/access.js";
import { planReconcile, type MembershipSnapshot } from "../../src/team/membership.js";

const VERSION = 5;
type Newest = "same" | "unproven" | "recovery" | "foreign-recovery";
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
  newest: fc.constantFrom<Newest>("same", "unproven", "recovery", "foreign-recovery"),
});

/** Builds real records for one account: version 1 keys, then, for a holder, its newest keys. */
function account(accountId: string, c: Case): MemberKeys[] {
  const recovery = cc1.signingKeyPair(cc1.randomBytes(32));
  const make = (version: number, recoverySigningSecretKey?: Uint8Array) => {
    const signing = cc1.signingKeyPair(cc1.randomBytes(32));
    return createMemberKeys(
      cc1,
      {
        teamId: "team-1", accountId, memberKeysVersion: version, signingPublicKey: signing.publicKey,
        encryptionPublicKey: cc1.generateEncryptionKeyPair().publicKey, recoveryPublicKey: recovery.publicKey, createdAt: 1,
      },
      signing.secretKey,
      recoverySigningSecretKey ? { recoverySigningSecretKey } : {},
    );
  };
  const keys = [make(1)];
  if (c.holds && c.newest !== "same") {
    const signer = c.newest === "recovery" ? recovery.secretKey : c.newest === "foreign-recovery" ? cc1.signingKeyPair(cc1.randomBytes(32)).secretKey : undefined;
    keys.push(make(2, signer));
  }
  return keys;
}

describe("SP-22: the reconcile plan never widens access outside its rule", () => {
  const selfArb = fc.constantFrom<"none" | "held" | "foreign">("none", "held", "foreign");
  test.prop([fc.array(caseArb, { minLength: 1, maxLength: 6 }), selfArb], { numRuns: 60 })("for any snapshot", (cases, selfRekey) => {
    const ids = cases.map((_, i) => `acct-${i}`);
    const self = "self";
    const keys = new Map<string, readonly MemberKeys[]>();
    const holders: Holder[] = [];
    const signer = { accountId: self, signingPublicKey: cc1.signingKeyPair(cc1.randomBytes(32)).publicKey };
    // The caller holds the current version; "held" keys are in its session, "foreign" ones someone published.
    const selfKeys = account(self, { holds: selfRekey !== "none", heldBefore: false, active: true, owner: true, newest: selfRekey === "none" ? "same" : "unproven" });
    keys.set(self, selfKeys);
    holders.push({ accountId: self, memberKeysVersion: 1, keysHash: keysHash(cc1, selfKeys[0]!), teamKeyVersion: VERSION, signer });
    cases.forEach((c, i) => {
      const id = ids[i]!;
      const list = account(id, c);
      keys.set(id, list);
      if (c.holds) holders.push({ accountId: id, memberKeysVersion: 1, keysHash: keysHash(cc1, list[0]!), teamKeyVersion: VERSION, signer });
    });
    const snapshot: MembershipSnapshot = {
      version: VERSION,
      owners: [self, ...ids.filter((_, i) => cases[i]!.owner)],
      self,
      holders,
      keys,
      heldBefore: new Set(ids.filter((_, i) => cases[i]!.heldBefore && !cases[i]!.holds)),
      selfHeld: new Set(selfRekey === "held" ? [1, 2] : [1]),
      active: new Set([self, ...ids.filter((_, i) => cases[i]!.active)]),
    };
    const plan = planReconcile(snapshot);

    for (const id of plan.remove) {
      const c = cases[ids.indexOf(id)]!;
      expect(c.holds && !c.active && !c.owner).toBe(true);
    }
    expect(plan.remove).not.toContain(self);
    // The caller's own re-key: approved exactly when its session holds the keys (D-47).
    expect(plan.approveRekeys.some((h) => h.accountId === self)).toBe(selfRekey === "held");
    if (selfRekey === "foreign") expect(plan.needsHuman).toContainEqual(expect.objectContaining({ accountId: self, reason: "owner-rekey" }));
    for (const { accountId } of plan.approveRekeys.filter((h) => h.accountId !== self)) {
      const c = cases[ids.indexOf(accountId)]!;
      expect(c.holds && c.active && !c.owner && c.newest === "recovery").toBe(true);
    }
    // Everything else an active account needs is left to a human, never silently dropped.
    const acted = new Set(plan.approveRekeys.map((h) => h.accountId));
    cases.forEach((c, i) => {
      const id = ids[i]!;
      const waiting = c.active && (!c.holds || keys.get(id)!.length > 1);
      if (waiting && !acted.has(id)) expect(plan.needsHuman.map((n) => n.accountId)).toContain(id);
    });
  });
});
