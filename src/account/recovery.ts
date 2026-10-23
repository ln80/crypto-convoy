// The recovery phrase as the account's root: setting it up, proving re-keys, securing the account (§5.6, §5.10, §5.11).
import type { Anchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError } from "../errors.js";
import { readServerState } from "../team/anchors.js";
import type { MemberBundle } from "../team/context.js";
import { callPort } from "../ports.js";
import { openRecoveryPublicKey } from "../records/account-key-wrap.js";
import { parseMemberKeysWrap } from "../records/member-keys-wrap.js";
import type { KeyPair } from "../suites/suite.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { newMemberKeys, nextMemberKeysVersion, openBundles } from "./member-custody.js";
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
 * The recovery signing key of `phrase`, checked against `expected` (one key, or any of several:
 * the current one and those a team's keys carry, D-49): another phrase is `WRONG_CREDENTIAL`.
 * The caller wipes the secret key.
 */
export function recoverySigner(ports: AccountPorts, accountId: string, phrase: string, expected: Uint8Array | readonly Uint8Array[]): KeyPair {
  const { recoveryKey, signing } = deriveRecoveryKeys(ports.suite, accountId, phrase);
  ports.suite.wipe(recoveryKey);
  const keys = expected instanceof Uint8Array ? [expected] : expected;
  if (!keys.some((key) => ports.suite.equal(signing.publicKey, key))) {
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
 * New member keys in one team (§6.8), with a recovery signature when `signer` is given, and the
 * newest trusted anchor as floor (D-50). Throws `NOT_GRANTED` without keys for the team.
 */
export async function rekeyTeam(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  recoveryPublicKey: Uint8Array,
  signer?: KeyPair,
): Promise<void> {
  const bundles = await openBundles(ports, account, teamId);
  const [newest] = bundles;
  if (!newest) throw new ConvoyError("NOT_GRANTED");
  const floor = await newestTrustedAnchor(ports, account, teamId, bundles);
  const options = { recoveryPublicKey, ...(signer ? { recoverySigningSecretKey: signer.secretKey } : {}), ...(floor ? { floor } : {}) };
  await commit(ports, newMemberKeys(ports, account, teamId, await nextMemberKeysVersion(ports, account, teamId), options).ops);
}

/**
 * The floor for new or re-wrapped keys: the highest of the bundles' floors and the `team-state`
 * anchor (§5.9, D-50). Never the local anchor, which a script or a thief on the device can change
 * (D-51). A garbage `team-state` is skipped, so it never blocks a re-key (TH-46).
 */
export async function newestTrustedAnchor(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  bundles: readonly MemberBundle[],
): Promise<Anchor | undefined> {
  let server: Anchor | undefined;
  try {
    server = (await readServerState(ports, account.accountId, teamId, bundles))?.anchor;
  } catch (error) {
    if (!isConvoyError(error, "TRUST_FAILURE")) throw error;
  }
  const anchors = [...bundles.map((b) => b.floor), server].filter((a): a is Anchor => a !== undefined);
  return anchors.reduce<Anchor | undefined>((best, a) => (!best || a.version > best.version ? a : best), undefined);
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
