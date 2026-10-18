// The recovery phrase as the account's root: setting it up, proving re-keys, securing the account (§5.6, §5.10, §5.11).
import { ConvoyError } from "../errors.js";
import { callPort } from "../ports.js";
import { openRecoveryPublicKey } from "../records/account-key-wrap.js";
import { parseMemberKeysWrap } from "../records/member-keys-wrap.js";
import type { KeyPair } from "../suites/suite.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { newMemberKeys, openBundles } from "./member-custody.js";
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
 * The recovery signing key of `phrase`, checked against `expected`: a phrase that isn't the
 * account's current one is `WRONG_CREDENTIAL`. The caller wipes the secret key.
 */
export function recoverySigner(ports: AccountPorts, accountId: string, phrase: string, expected: Uint8Array): KeyPair {
  const { recoveryKey, signing } = deriveRecoveryKeys(ports.suite, accountId, phrase);
  ports.suite.wipe(recoveryKey);
  if (!ports.suite.equal(signing.publicKey, expected)) {
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
 * New member keys in one team (§6.8), with a recovery signature when `signer` is given. Throws
 * `NOT_GRANTED` without keys for the team.
 */
export async function rekeyTeam(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  recoveryPublicKey: Uint8Array,
  signer?: KeyPair,
): Promise<void> {
  const [newest] = await openBundles(ports, account, teamId);
  if (!newest) throw new ConvoyError("NOT_GRANTED");
  const options = { recoveryPublicKey, ...(signer ? { recoverySigningSecretKey: signer.secretKey } : {}) };
  await commit(ports, newMemberKeys(ports, account, teamId, newest.memberKeysVersion + 1, options).ops);
}

/** Re-keys every team in its own write, reporting failures instead of stopping (§5.6, §5.11). */
export async function rekeyTeams(
  ports: AccountPorts,
  account: OpenAccount,
  teamIds: readonly string[],
  recoveryPublicKey: Uint8Array,
  signer?: KeyPair,
): Promise<RekeyReport> {
  const rekeyed: string[] = [];
  const failed: string[] = [];
  for (const teamId of teamIds) {
    try {
      await rekeyTeam(ports, account, teamId, recoveryPublicKey, signer);
      rekeyed.push(teamId);
    } catch {
      // Reported by id only: the error may concern any record of that team (§9).
      failed.push(teamId);
    }
  }
  return { rekeyed, failed };
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
