// Who holds a version (its roster, §4.5, D-37) and opening one's own access (§6.1 step 5).
import { trustFailure } from "../errors.js";
import type { SignerRef } from "../records/common.js";
import { keysHash } from "../records/member-keys.js";
import { openPreviousKey, openRosterEntry, type TeamKeyVersion } from "../records/team-key-version.js";
import type { VerifiedChain } from "./chain.js";
import type { MemberBundle, TeamPorts } from "./context.js";

/** One account holding a version with one set of keys: an entry of that version's roster. */
export interface Holder {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly keysHash: Uint8Array;
  readonly teamKeyVersion: number;
  /** The version record's signer, who gave it. */
  readonly signer: SignerRef;
}

/** The roster of `record`: the only way to hold its version (D-37). */
export function holdersOf(record: TeamKeyVersion): Holder[] {
  return record.roster.map((e) => ({
    accountId: e.accountId,
    memberKeysVersion: e.memberKeysVersion,
    keysHash: e.keysHash,
    teamKeyVersion: record.version,
    signer: record.signer,
  }));
}

export interface OwnAccess {
  readonly teamKeyVersion: number;
  readonly bundle: MemberBundle;
  readonly teamKey: Uint8Array;
  /** The chain, reaching down to the access's version. */
  readonly chain: VerifiedChain;
}

/**
 * This account's newest access: the newest roster entry for one of its keys (§6.1 step 5).
 * `chainFrom` reaches older records when the access is below the loaded chain.
 */
export async function openOwnAccess(
  ports: TeamPorts,
  accountId: string,
  loaded: VerifiedChain,
  chainFrom: (version: number) => Promise<VerifiedChain>,
  bundles: readonly MemberBundle[],
): Promise<OwnAccess | null> {
  const fromRoster = (chain: VerifiedChain) => {
    for (let i = chain.records.length - 1; i >= 0; i--) {
      const record = chain.records[i]!;
      const entry = record.roster.find((e) => e.accountId === accountId && bundles.some((b) => b.memberKeysVersion === e.memberKeysVersion));
      if (entry) return { record, entry, bundle: bundles.find((b) => b.memberKeysVersion === entry.memberKeysVersion)! };
    }
    return null;
  };
  let chain = loaded;
  let found = fromRoster(chain);
  // A member who held nothing recent (pending, removed) may hold an entry below the loaded chain.
  if (!found && chain.records[0]!.version > 1) {
    chain = await chainFrom(1);
    found = fromRoster(chain);
  }
  if (!found) return null;

  const { suite } = ports;
  const { record, entry, bundle } = found;
  if (!suite.equal(entry.keysHash, keysHash(suite, bundle.published))) throw trustFailure("key_mismatch");
  const teamKey = openRosterEntry(record, entry, bundle.pairs.encryption);
  // Opening the link with the opened key confirms it is the key that record was made with (§4.5).
  if (record.version > 1) suite.wipe(openPreviousKey(record, teamKey));
  return { teamKeyVersion: record.version, bundle, teamKey, chain };
}
