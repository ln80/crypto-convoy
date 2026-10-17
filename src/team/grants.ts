// Who holds a version (roster ∪ grants, §6.5), the owner rule, and opening one's own access (§6.1 step 5).
import { trustFailure } from "../errors.js";
import { callPort } from "../ports.js";
import type { SignerRef } from "../records/common.js";
import { openGrant, parseGrant, type Grant } from "../records/grant.js";
import { keysHash } from "../records/member-keys.js";
import { openPreviousKey, openRosterEntry, type TeamKeyVersion } from "../records/team-key-version.js";
import { isOwner, type VerifiedChain } from "./chain.js";
import type { MemberBundle, TeamPorts } from "./context.js";

/** A grant for version n counts only if its signer is an owner of version n (§4.5 owner rule). */
export function checkOwnerRule(grant: { teamKeyVersion: number; signer: SignerRef }, chain: VerifiedChain): void {
  const record = chain.records.find((r) => r.version === grant.teamKeyVersion);
  if (!record) throw trustFailure("rollback");
  if (!isOwner(record, grant.signer)) throw trustFailure("not_an_owner");
}

export async function listGrants(ports: TeamPorts, teamId: string, query: { teamKeyVersion?: number; accountId?: string; memberKeysVersion?: number }) {
  const jsons = await callPort(() => ports.store.list({ type: "grant", teamId, ...query }));
  return jsons.map((json) => parseGrant(json, { teamId, ...query }));
}

/** One account holding a version with one set of keys: through the version's roster, or a grant (§6.5). */
export interface Holder {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly keysHash: Uint8Array;
  readonly teamKeyVersion: number;
  /** Who gave it: the version record's signer, or the grant's. */
  readonly signer: SignerRef;
  readonly grant?: Grant;
}

/** The roster of `record` and the grants of its version, owner rule checked. Throws `TRUST_FAILURE`. */
export function holdersOf(record: TeamKeyVersion, grants: readonly Grant[], chain: VerifiedChain): Holder[] {
  const holders: Holder[] = record.roster.map((e) => ({
    accountId: e.accountId,
    memberKeysVersion: e.memberKeysVersion,
    keysHash: e.keysHash,
    teamKeyVersion: record.version,
    signer: record.signer,
  }));
  for (const grant of grants) {
    checkOwnerRule(grant, chain);
    holders.push({
      accountId: grant.accountId,
      memberKeysVersion: grant.memberKeysVersion,
      keysHash: grant.keysHash,
      teamKeyVersion: grant.teamKeyVersion,
      signer: grant.signer,
      grant,
    });
  }
  return holders;
}

export interface OwnAccess {
  readonly teamKeyVersion: number;
  readonly bundle: MemberBundle;
  readonly teamKey: Uint8Array;
  /** The chain, reaching down to the access's version. */
  readonly chain: VerifiedChain;
}

/**
 * This account's newest access: the newest roster entry for one of its keys, or a newer grant
 * (§6.1 step 5). `chainFrom` reaches older records when the access is below the loaded chain.
 */
export async function openOwnAccess(
  ports: TeamPorts,
  teamId: string,
  accountId: string,
  loaded: VerifiedChain,
  chainFrom: (version: number) => Promise<VerifiedChain>,
  bundles: readonly MemberBundle[],
): Promise<OwnAccess | null> {
  let bestGrant: { grant: Grant; bundle: MemberBundle } | null = null;
  for (const bundle of bundles) {
    const grants = await listGrants(ports, teamId, { accountId, memberKeysVersion: bundle.memberKeysVersion });
    for (const grant of grants) if (!bestGrant || grant.teamKeyVersion > bestGrant.grant.teamKeyVersion) bestGrant = { grant, bundle };
  }
  const floor = bestGrant?.grant.teamKeyVersion ?? 0;
  const fromRoster = (chain: VerifiedChain) => {
    for (let i = chain.records.length - 1; i >= 0 && chain.records[i]!.version > floor; i--) {
      const record = chain.records[i]!;
      const entry = record.roster.find((e) => e.accountId === accountId && bundles.some((b) => b.memberKeysVersion === e.memberKeysVersion));
      if (entry) return { record, entry, bundle: bundles.find((b) => b.memberKeysVersion === entry.memberKeysVersion)! };
    }
    return null;
  };
  let chain = loaded;
  let roster = fromRoster(chain);
  // A member who held nothing recent (pending, removed) may hold an entry below the loaded chain.
  if (!roster && !bestGrant && chain.records[0]!.version > 1) {
    chain = await chainFrom(1);
    roster = fromRoster(chain);
  }

  const { suite } = ports;
  let teamKey: Uint8Array;
  let version: number;
  let bundle: MemberBundle;
  if (roster) {
    ({ bundle } = roster);
    if (!suite.equal(roster.entry.keysHash, keysHash(suite, bundle.published))) throw trustFailure("key_mismatch");
    teamKey = openRosterEntry(roster.record, roster.entry, bundle.pairs.encryption);
    version = roster.record.version;
  } else if (bestGrant) {
    ({ bundle } = bestGrant);
    const { grant } = bestGrant;
    chain = await chainFrom(grant.teamKeyVersion);
    checkOwnerRule(grant, chain);
    if (!suite.equal(grant.keysHash, keysHash(suite, bundle.published))) throw trustFailure("key_mismatch");
    teamKey = openGrant(grant, bundle.pairs.encryption);
    version = grant.teamKeyVersion;
  } else {
    return null;
  }
  // Opening the link with the opened key confirms it is the key that record was made with (§4.5).
  const record = chain.records.find((r) => r.version === version)!;
  if (record.version > 1) suite.wipe(openPreviousKey(record, teamKey));
  return { teamKeyVersion: version, bundle, teamKey, chain };
}
