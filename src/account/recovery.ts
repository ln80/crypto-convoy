// The recovery phrase as the account's root: setting it up, proving re-keys, securing the account (§5.6, §5.10, §5.11).
import type { Anchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError } from "../errors.js";
import { checkId } from "../encoding/json.js";
import { verifiedChain } from "../team/load.js";
import { callPort } from "../ports.js";
import { openAccountKeyWrap, openRecoveryPublicKey } from "../records/account-key-wrap.js";
import { parseMemberKeysWrap } from "../records/member-keys-wrap.js";
import type { KeyPair } from "../suites/suite.js";
import type { MemberBundle } from "../team/context.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { newMemberKeys, nextMemberKeysVersion, openBundles, openedWraps, recordVaultAnchor, vaultAnchorOf } from "./member-custody.js";
import { deriveRecoveryKeys } from "./recovery-key.js";
import { commit, fetchWrap } from "./unlock-methods.js";

/** Teams re-keyed by an account-wide operation, and those to retry with `rekey` (§5.6, §5.11). */
export interface RekeyReport {
  readonly rekeyed: readonly string[];
  readonly failed: readonly string[];
}

/** Same words, whatever the spacing and case: the user types the phrase back (§5.10). */
export function samePhrase(a: string, b: string): boolean {
  const words = (p: string) => p.normalize("NFKD").trim().toLowerCase().split(/\s+/).join(" ");
  return words(a) === words(b);
}

/**
 * The recovery wrap at the account's current version: absent (recovery not set up, D-35), or present
 * with its public key, `null` when the record doesn't parse or its key can't be read, which a session
 * can cause: a mismatch, never a failure (D-56).
 */
export async function storedRecoveryKey(ports: AccountPorts, account: OpenAccount): Promise<{ present: boolean; key: Uint8Array | null }> {
  try {
    const wrap = await fetchWrap(ports, { accountId: account.accountId, accountKeyVersion: account.version, method: "recovery" });
    return wrap ? { present: true, key: openRecoveryPublicKey(wrap, account.key) } : { present: false, key: null };
  } catch (error) {
    if (unreadable(error)) return { present: true, key: null };
    throw error;
  }
}

/** A record's own failure, as opposed to the store's: a record someone else wrote may cause it (D-56, D-58). */
const unreadable = (error: unknown) => isConvoyError(error) && !isConvoyError(error, "STORE_ERROR");

/**
 * The current phrase, checked by opening the recovery wrap's account key, never against the public
 * key the wrap names, which an account-key holder can rewrite (D-56): its recovery signing key, and
 * whether the wrap names another public key. Throws `RECOVERY_NOT_SET_UP`, `WRONG_CREDENTIAL`.
 * The caller wipes the secret key.
 */
export async function typedPhrase(ports: AccountPorts, account: OpenAccount, phrase: string): Promise<{ signing: KeyPair; mismatch: boolean }> {
  const { suite } = ports;
  const wrap = await fetchWrap(ports, { accountId: account.accountId, accountKeyVersion: account.version, method: "recovery" });
  if (!wrap) throw new ConvoyError("RECOVERY_NOT_SET_UP");
  const { recoveryKey, signing } = deriveRecoveryKeys(suite, account.accountId, phrase);
  try {
    let key: Uint8Array;
    try {
      key = openAccountKeyWrap(wrap, recoveryKey);
    } finally {
      suite.wipe(recoveryKey);
    }
    try {
      if (!suite.equal(key, account.key)) throw new ConvoyError("WRONG_CREDENTIAL");
    } finally {
      suite.wipe(key);
    }
    // A stored key that can't be read differs too: reported, never refused (D-56).
    let stored: Uint8Array | null = null;
    try {
      stored = openRecoveryPublicKey(wrap, account.key);
    } catch (error) {
      if (!unreadable(error)) throw error;
    }
    return { signing, mismatch: stored === null || !suite.equal(stored, signing.publicKey) };
  } catch (error) {
    suite.wipe(signing.secretKey);
    throw error;
  }
}

/** The recovery public key of a phrase the user typed, for keys a new phrase will prove (D-56). */
export function phrasePublicKey(ports: AccountPorts, accountId: string, phrase: string): Uint8Array {
  const { recoveryKey, signing } = deriveRecoveryKeys(ports.suite, accountId, phrase);
  ports.suite.wipe(recoveryKey, signing.secretKey);
  return signing.publicKey;
}

/** The recovery signing key of a phrase, unchecked: for a repair with no bundle to check it against (D-60). The caller wipes it. */
export function recoverySigningKey(ports: AccountPorts, accountId: string, phrase: string): KeyPair {
  const { recoveryKey, signing } = deriveRecoveryKeys(ports.suite, accountId, phrase);
  ports.suite.wipe(recoveryKey);
  return signing;
}

/** The teams the integration's product lists for the user, checked as ids, once each (D-60). Throws `MALFORMED_RECORD`. */
export function productTeams(teamIds: readonly string[] | undefined): string[] {
  if (teamIds === undefined) return [];
  if (!Array.isArray(teamIds)) throw new ConvoyError("MALFORMED_RECORD");
  return [...new Set(teamIds.map((teamId) => checkId(teamId)))];
}

/**
 * The recovery signing key of an old phrase a retry signs with, checked against the recovery keys
 * the team's bundles carry, against a typing mistake (D-49): another phrase is `WRONG_CREDENTIAL`.
 * The caller wipes the secret key.
 */
export function oldPhraseSigner(ports: AccountPorts, accountId: string, phrase: string, carried: readonly Uint8Array[]): KeyPair {
  const { recoveryKey, signing } = deriveRecoveryKeys(ports.suite, accountId, phrase);
  ports.suite.wipe(recoveryKey);
  if (!carried.some((key) => ports.suite.equal(signing.publicKey, key))) {
    ports.suite.wipe(signing.secretKey);
    throw new ConvoyError("WRONG_CREDENTIAL");
  }
  return signing;
}

/** The teams this account holds member keys for, at its current account key version. */
export async function accountTeams(ports: AccountPorts, account: OpenAccount): Promise<string[]> {
  // Only teams with a wrap that opens: a garbage wrap names no team of the account's (D-58).
  const teams = (await openedWraps(ports, account)).map(({ wrap }) => wrap.teamId);
  return [...new Set(teams)];
}

/**
 * New member keys in one team (§6.8), with a recovery signature when `signer` is given. Their floor
 * is the tip of a chain that contains every root the vault holds (the newest bundle's floor and its
 * own anchor), or, given `ownerAnchor`, that anchor alone (D-54); the tip becomes the vault's anchor.
 * Throws `NOT_GRANTED` without keys for the team, `TRUST_FAILURE` when the roots conflict or the
 * chain doesn't verify: nothing is written then.
 */
export async function rekeyTeam(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  recoveryPublicKey: Uint8Array,
  signer?: KeyPair,
  ownerAnchor?: Anchor,
): Promise<void> {
  const bundles = await openBundles(ports, account, teamId);
  const [newest] = bundles;
  // With an owner's anchor, a team whose wraps are gone is re-keyed too: that anchor is the only root (D-59).
  if (!newest && !ownerAnchor) throw new ConvoyError("NOT_GRANTED");
  const vault = ownerAnchor ? null : await vaultAnchorOf(ports, account.accountId, teamId);
  const roots = ownerAnchor ? [ownerAnchor] : [newest!.floor, vault].filter((a): a is Anchor => a !== null && a !== undefined);
  const chain = await verifiedChain(ports, teamId, roots);
  const tip = chain.records.at(-1)!;
  const floor = { version: tip.version, hash: chain.hashes.get(tip.version)! };
  const options = { recoveryPublicKey, floor, ...(signer ? { recoverySigningSecretKey: signer.secretKey } : {}) };
  await commit(ports, newMemberKeys(ports, account, teamId, await nextMemberKeysVersion(ports, account, teamId), options).ops);
  await recordVaultAnchor(ports, account.accountId, teamId, floor, ownerAnchor !== undefined);
}

/**
 * Re-keys every team in its own write, reporting failures instead of stopping (§5.6, §5.11); `anchors`
 * from owners, by team (D-54). `missing` are teams the product lists with no wrap that opens: reported failed (D-60).
 */
export async function rekeyTeams(
  ports: AccountPorts,
  account: OpenAccount,
  teamIds: readonly string[],
  recoveryPublicKey: Uint8Array,
  signer?: KeyPair,
  anchors: ReadonlyMap<string, Anchor> = new Map(),
  missing: readonly string[] = [],
): Promise<RekeyReport> {
  const rekeyed: string[] = [];
  const failed: string[] = [...missing];
  for (const teamId of teamIds) {
    try {
      await rekeyTeam(ports, account, teamId, recoveryPublicKey, signer, anchors.get(teamId));
      rekeyed.push(teamId);
    } catch {
      // Reported by id only: the error may concern any record of that team (§9).
      failed.push(teamId);
    }
  }
  return { rekeyed, failed };
}

/**
 * Teams where the account has a published member keys version newer than every bundle the vault
 * holds: keys this vault didn't make, a sign that someone holds the session (D-43, TH-37).
 */
export async function teamsWithForeignKeys(ports: AccountPorts, account: OpenAccount): Promise<string[]> {
  const foreign: string[] = [];
  for (const teamId of await accountTeams(ports, account)) {
    const bundles = await teamBundles(ports, account, teamId);
    // Keys or a wrap this vault didn't make, or a withheld record: that team alone is reported (D-58).
    if (!bundles) {
      foreign.push(teamId);
      continue;
    }
    const [newest] = bundles;
    const published = await callPort(() => ports.store.list({ type: "member-keys", teamId, accountId: account.accountId }));
    const newer = published.some((json) => {
      const version = (json as { memberKeysVersion?: unknown }).memberKeysVersion;
      return typeof version === "number" && newest !== undefined && version > newest.memberKeysVersion;
    });
    if (newer) foreign.push(teamId);
  }
  return foreign;
}

/** Teams whose newest member keys don't carry the current recovery key: they need a re-key (§5.6). */
export async function teamsWithOldRecoveryKey(ports: AccountPorts, account: OpenAccount, recoveryPublicKey: Uint8Array): Promise<string[]> {
  const stale: string[] = [];
  for (const teamId of await accountTeams(ports, account)) {
    const bundles = await teamBundles(ports, account, teamId);
    // A team whose bundles fail is listed, so its re-key is tried and reported failed (D-58).
    const newest = bundles?.[0];
    if (!bundles || (newest && !ports.suite.equal(newest.published.recoveryPublicKey, recoveryPublicKey))) stale.push(teamId);
  }
  return stale;
}

/** A team's bundles, or null when they fail their checks: across the account's teams, that team alone fails (D-58). */
async function teamBundles(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<MemberBundle[] | null> {
  try {
    return await openBundles(ports, account, teamId);
  } catch (error) {
    if (unreadable(error)) return null;
    throw error;
  }
}
