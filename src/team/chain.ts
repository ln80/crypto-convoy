// Verifying the team key chain (§4.5 reader checks, §6.1 steps 2–3).
import type { Anchor } from "../encoding/link.js";
import { trustFailure } from "../errors.js";
import type { SignerRef } from "../records/common.js";
import { keysHash, type MemberKeys } from "../records/member-keys.js";
import { recordHash, type TeamKeyVersion } from "../records/team-key-version.js";

/** One accepted change of the owner list, for the integration to show (SP-15). */
export interface OwnerChange {
  readonly version: number;
  readonly signer: string;
  readonly added: readonly string[];
  readonly removed: readonly string[];
  /** Owners whose signing key changed (an approved re-key, §6.8). */
  readonly rekeyed: readonly string[];
}

/** One accepted change of the roster, for the integration to show (SP-15, D-44). */
export interface MemberChange {
  readonly version: number;
  readonly signer: string;
  /** Accounts receiving this version that didn't hold the previous one. */
  readonly added: readonly string[];
  /** Accounts that held the previous version and don't receive this one. */
  readonly removed: readonly string[];
  /** Accounts receiving this version with other keys than the previous one (an approved re-key, §6.8). */
  readonly rekeyed: readonly string[];
}

export interface VerifiedChain {
  /** Consecutive records, from the first one fetched to the newest. */
  readonly records: readonly TeamKeyVersion[];
  readonly hashes: ReadonlyMap<number, Uint8Array>;
  readonly ownerChanges: readonly OwnerChange[];
  readonly memberChanges: readonly MemberChange[];
}

export const sameSigner = (a: SignerRef, b: SignerRef, equal: (x: Uint8Array, y: Uint8Array) => boolean) =>
  a.accountId === b.accountId && equal(a.signingPublicKey, b.signingPublicKey);

export function isOwner(record: TeamKeyVersion, signer: SignerRef): boolean {
  return record.owners.some((owner) => sameSigner(owner, signer, record.suite.equal));
}

/**
 * `records` is the chain as served, from version 1 or from an anchored version, to the newest.
 * Nothing in it is adopted unless every check passes, anchors included (SP-05, SP-07).
 * Throws `TRUST_FAILURE`.
 */
export function verifyChain(input: {
  records: readonly TeamKeyVersion[];
  anchors: readonly Anchor[];
  memberKeys: readonly MemberKeys[];
}): VerifiedChain {
  const { records, anchors, memberKeys } = input;
  if (records.length === 0) throw trustFailure("rollback");
  // Above version 1, the first record is trusted only through an anchor (§6.1 step 2).
  const first = records[0]!;
  if (first.version !== 1 && !anchors.some((a) => a.version === first.version)) {
    throw trustFailure(anchors.some((a) => a.version < first.version) ? "rollback" : "chain_conflict");
  }

  const hashes = new Map<number, Uint8Array>();
  records.forEach((record, i) => {
    // Consecutive versions, no gap, no second record for a version.
    if (record.version !== records[0]!.version + i) throw trustFailure("chain_conflict");
    const hash = recordHash(record);
    const previous = records[i - 1];
    const equal = record.suite.equal;
    if (record.version === 1) {
      if (!record.prevHash.every((byte) => byte === 0)) throw trustFailure("chain_conflict");
      if (!isOwner(record, record.signer)) throw trustFailure("not_an_owner");
    } else if (previous) {
      if (!equal(record.prevHash, hashes.get(previous.version)!)) throw trustFailure("chain_conflict");
      if (!isOwner(previous, record.signer)) throw trustFailure("not_an_owner");
    }
    for (const owner of record.owners) {
      const published = memberKeys.find((m) => m.accountId === owner.accountId && equal(m.signingPublicKey, owner.signingPublicKey));
      if (!published) throw trustFailure("key_mismatch");
      // Owners hold the version they own, with these keys (§4.5 rule 5).
      const entry = record.roster.find((e) => e.accountId === owner.accountId);
      if (!entry || entry.memberKeysVersion !== published.memberKeysVersion || !equal(entry.keysHash, keysHash(record.suite, published))) {
        throw trustFailure("key_mismatch");
      }
    }
    if (!record.roster.some((e) => e.accountId === record.signer.accountId)) throw trustFailure("key_mismatch");
    hashes.set(record.version, hash);
  });

  const newest = records[records.length - 1]!.version;
  for (const anchor of anchors) {
    if (anchor.version > newest) throw trustFailure("rollback");
    // A chain must be fetched from the lowest anchor: one it can't show is refused.
    if (anchor.version < first.version) throw trustFailure("chain_conflict");
    if (!records[0]!.suite.equal(hashes.get(anchor.version)!, anchor.hash)) throw trustFailure("chain_conflict");
  }

  const highestAnchor = anchors.length > 0 ? Math.max(...anchors.map((a) => a.version)) : 0;
  const ownerChanges: OwnerChange[] = [];
  const memberChanges: MemberChange[] = [];
  records.forEach((record, i) => {
    if (record.version <= highestAnchor) return;
    const previous = new Map((records[i - 1]?.roster ?? []).map((e) => [e.accountId, e.keysHash]));
    const current = new Map(record.roster.map((e) => [e.accountId, e.keysHash]));
    const joined = [...current.keys()].filter((id) => !previous.has(id));
    const left = [...previous.keys()].filter((id) => !current.has(id));
    const newKeys = [...current].filter(([id, hash]) => previous.has(id) && !record.suite.equal(previous.get(id)!, hash)).map(([id]) => id);
    if (joined.length > 0 || left.length > 0 || newKeys.length > 0) {
      memberChanges.push({ version: record.version, signer: record.signer.accountId, added: joined, removed: left, rekeyed: newKeys });
    }
    const before = new Set((records[i - 1]?.owners ?? []).map((o) => o.accountId));
    const after = new Set(record.owners.map((o) => o.accountId));
    const added = [...after].filter((id) => !before.has(id));
    const removed = [...before].filter((id) => !after.has(id));
    const rekeyed = record.owners
      .filter((o) => {
        const old = records[i - 1]?.owners.find((p) => p.accountId === o.accountId);
        return old !== undefined && !record.suite.equal(old.signingPublicKey, o.signingPublicKey);
      })
      .map((o) => o.accountId);
    if (added.length > 0 || removed.length > 0 || rekeyed.length > 0) {
      ownerChanges.push({ version: record.version, signer: record.signer.accountId, added, removed, rekeyed });
    }
  });
  return { records, hashes, ownerChanges, memberChanges };
}

/**
 * Prepends `older` records (consecutive, ending just below the chain's first record) to a verified
 * chain. They are trusted through the hash links back from a record already verified, so nothing
 * else needs checking: a different record can't have the same hash (§6.1 step 2). Throws `TRUST_FAILURE`.
 */
export function extendChain(chain: VerifiedChain, older: readonly TeamKeyVersion[]): VerifiedChain {
  const first = chain.records[0]!;
  if (older.length === 0 || older.at(-1)!.version !== first.version - 1) throw trustFailure("rollback");
  const hashes = new Map(chain.hashes);
  let next = first;
  for (let i = older.length - 1; i >= 0; i--) {
    const record = older[i]!;
    if (record.version !== next.version - 1) throw trustFailure("chain_conflict");
    const hash = recordHash(record);
    if (!record.suite.equal(hash, next.prevHash)) throw trustFailure("chain_conflict");
    hashes.set(record.version, hash);
    next = record;
  }
  if (next.version === 1 && !next.prevHash.every((byte) => byte === 0)) throw trustFailure("chain_conflict");
  return { records: [...older, ...chain.records], hashes, ownerChanges: chain.ownerChanges, memberChanges: chain.memberChanges };
}
