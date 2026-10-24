// The recovery phrase as the account's root: setting it up, proving re-keys, securing the account (§5.6, §5.10, §5.11).
import type { Anchor } from "../encoding/link.js";
import { ConvoyError } from "../errors.js";
import { verifiedChain } from "../team/load.js";
import { callPort } from "../ports.js";
import { openAccountKeyWrap, openRecoveryPublicKey } from "../records/account-key-wrap.js";
import { parseMemberKeysWrap } from "../records/member-keys-wrap.js";
import type { KeyPair } from "../suites/suite.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { newMemberKeys, nextMemberKeysVersion, openBundles, recordVaultAnchor, vaultAnchorOf } from "./member-custody.js";
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

/** The recovery public key at the account's current version, or `null` when recovery isn't set up (D-35). */
export async function currentRecoveryKey(ports: AccountPorts, account: OpenAccount): Promise<Uint8Array | null> {
  const wrap = await fetchWrap(ports, { accountId: account.accountId, accountKeyVersion: account.version, method: "recovery" });
  return wrap ? openRecoveryPublicKey(wrap, account.key) : null;
}

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
    return { signing, mismatch: !suite.equal(openRecoveryPublicKey(wrap, account.key), signing.publicKey) };
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
  const wraps = await callPort(() => ports.store.list({ type: "member-keys-wrap", accountId: account.accountId, accountKeyVersion: account.version }));
  const teams = wraps.map((json) => parseMemberKeysWrap(json, { accountId: account.accountId, accountKeyVersion: account.version }).teamId);
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
  if (!newest) throw new ConvoyError("NOT_GRANTED");
  const vault = ownerAnchor ? null : await vaultAnchorOf(ports, account.accountId, teamId);
  const roots = ownerAnchor ? [ownerAnchor] : [newest.floor, vault].filter((a): a is Anchor => a !== null && a !== undefined);
  const chain = await verifiedChain(ports, teamId, roots);
  const tip = chain.records.at(-1)!;
  const floor = { version: tip.version, hash: chain.hashes.get(tip.version)! };
  const options = { recoveryPublicKey, floor, ...(signer ? { recoverySigningSecretKey: signer.secretKey } : {}) };
  await commit(ports, newMemberKeys(ports, account, teamId, await nextMemberKeysVersion(ports, account, teamId), options).ops);
  await recordVaultAnchor(ports, account.accountId, teamId, floor, ownerAnchor !== undefined);
}

/** Re-keys every team in its own write, reporting failures instead of stopping (§5.6, §5.11); `anchors` from owners, by team (D-54). */
export async function rekeyTeams(
  ports: AccountPorts,
  account: OpenAccount,
  teamIds: readonly string[],
  recoveryPublicKey: Uint8Array,
  signer?: KeyPair,
  anchors: ReadonlyMap<string, Anchor> = new Map(),
): Promise<RekeyReport> {
  const rekeyed: string[] = [];
  const failed: string[] = [];
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
    const [newest] = await openBundles(ports, account, teamId);
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
    const [newest] = await openBundles(ports, account, teamId);
    if (newest && !ports.suite.equal(newest.published.recoveryPublicKey, recoveryPublicKey)) stale.push(teamId);
  }
  return stale;
}
