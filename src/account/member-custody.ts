// Member keys live under the account key, so creating and opening them runs in the vault (§5.8, §5.9).
import type { Anchor } from "../encoding/link.js";
import { ConvoyError, StoreConflictError, isConvoyError } from "../errors.js";
import { decodeRequest, sealTransfer } from "../records/transfer.js";
import { loadChain } from "../team/load.js";
import { callPort, type WriteOp } from "../ports.js";
import { createMemberKeys, keysHash, memberKeysToJson, parseMemberKeys, type MemberKeysProofs } from "../records/member-keys.js";
import {
  bundleKeyPairs,
  checkBundle,
  createMemberKeysWrap,
  generateBundle,
  memberKeysWrapToJson,
  parseMemberKeysWrap,
  unwrapMemberKeys,
  type MemberKeyBundle,
  type MemberKeysWrap,
} from "../records/member-keys-wrap.js";
import { createTeamKeyVersion, recordHash, teamKeyVersionToJson, type TeamKeyVersion } from "../records/team-key-version.js";
import type { MemberBundle, TeamPorts } from "../team/context.js";
import { TeamSession, sessionInternals } from "../team/session.js";
import type { AccountPorts, OpenAccount } from "./context.js";

/**
 * The account's wraps at its key version that parse and open under the account key. One that
 * doesn't was never the account's (only the account key makes one): it is absent, as if withheld (§4.3, D-58).
 */
export async function openedWraps(ports: AccountPorts, account: OpenAccount): Promise<{ wrap: MemberKeysWrap; bundle: MemberKeyBundle }[]> {
  const { accountId } = account;
  const jsons = await callPort(() => ports.store.list({ type: "member-keys-wrap", accountId, accountKeyVersion: account.version }));
  const opened: { wrap: MemberKeysWrap; bundle: MemberKeyBundle }[] = [];
  for (const json of jsons) {
    try {
      const wrap = parseMemberKeysWrap(json, { accountId, accountKeyVersion: account.version });
      opened.push({ wrap, bundle: unwrapMemberKeys(wrap, account.key) });
    } catch (error) {
      if (!isConvoyError(error)) throw error;
    }
  }
  return opened;
}

/** Every member key bundle of this account for the team, newest first, checked against the published keys. */
export async function openBundles(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<MemberBundle[]> {
  const { store, suite } = ports;
  const { accountId } = account;
  const opened = (await openedWraps(ports, account))
    .filter(({ wrap }) => wrap.teamId === teamId)
    .sort((a, b) => b.wrap.memberKeysVersion - a.wrap.memberKeysVersion);
  const bundles: MemberBundle[] = [];
  for (const { wrap, bundle } of opened) {
    const json = await callPort(() => store.get({ type: "member-keys", teamId, accountId, memberKeysVersion: wrap.memberKeysVersion }));
    const published = parseMemberKeys(json, { teamId, accountId, memberKeysVersion: wrap.memberKeysVersion });
    // A wrap that opens is the account's: one its published keys don't match is a trust failure, not absent.
    checkBundle(suite, bundle, published);
    bundles.push({ memberKeysVersion: wrap.memberKeysVersion, published, pairs: bundleKeyPairs(suite, bundle), floor: bundle.floor });
  }
  return bundles;
}

interface NewMemberKeysOptions {
  /** The account's recovery public key, read authenticated from its recovery wrap (§4.1). */
  readonly recoveryPublicKey: Uint8Array;
  /** On a re-key with the phrase: the recovery signing key proves the new keys (D-33). */
  readonly recoverySigningSecretKey?: MemberKeysProofs["recoverySigningSecretKey"];
  /** The anchor floor the bundle carries (§4.3, D-48, D-66). */
  readonly floor: Anchor;
}

/**
 * The version for new member keys: one above the account's newest published record for the team,
 * so keys someone else published never block it (§5.9, D-43). Every bundle is published with its
 * wrap, which the server creates only in that batch (D-58).
 */
export async function nextMemberKeysVersion(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<number> {
  const published = await callPort(() => ports.store.list({ type: "member-keys", teamId, accountId: account.accountId }));
  const versions = published.map((json) => (json as { memberKeysVersion?: unknown }).memberKeysVersion);
  for (const version of versions) {
    if (!Number.isSafeInteger(version) || (version as number) < 1 || (version as number) >= 2 ** 32 - 1) throw new ConvoyError("MALFORMED_RECORD");
  }
  return Math.max(0, ...(versions as number[])) + 1;
}

/** New member keys: the published record, with its proof, and its wrap with its anchor floor (§5.9). */
export function newMemberKeys(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  memberKeysVersion: number,
  options: NewMemberKeysOptions,
): { ops: WriteOp[]; bundle: MemberBundle } {
  const keys = generateMemberKeys(ports, account, teamId, memberKeysVersion, options);
  return { ops: memberKeysOps(ports, account, keys, options.floor), bundle: { ...keys.bundle, floor: options.floor } };
}

interface GeneratedKeys {
  readonly raw: Omit<MemberKeyBundle, "floor">;
  readonly bundle: Omit<MemberBundle, "floor">;
}

function generateMemberKeys(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  memberKeysVersion: number,
  options: Omit<NewMemberKeysOptions, "floor">,
): GeneratedKeys {
  const { suite, clock } = ports;
  const { accountId } = account;
  const raw = generateBundle(suite);
  const pairs = bundleKeyPairs(suite, raw);
  const published = createMemberKeys(
    suite,
    {
      teamId,
      accountId,
      memberKeysVersion,
      signingPublicKey: pairs.signing.publicKey,
      encryptionPublicKey: pairs.encryption.publicKey,
      recoveryPublicKey: options.recoveryPublicKey,
      createdAt: clock.now(),
    },
    pairs.signing.secretKey,
    options.recoverySigningSecretKey ? { recoverySigningSecretKey: options.recoverySigningSecretKey } : {},
  );
  return { raw, bundle: { memberKeysVersion, published, pairs } };
}

/** The published record and the wrap, with the floor inside the wrapped bundle (§4.3). */
function memberKeysOps(ports: AccountPorts, account: OpenAccount, keys: GeneratedKeys, floor: Anchor): WriteOp[] {
  const { published } = keys.bundle;
  const { accountId } = account;
  const { teamId, memberKeysVersion } = published;
  const context = { accountId, teamId, memberKeysVersion, accountKeyVersion: account.version };
  const wrap = createMemberKeysWrap(ports.suite, context, account.key, { ...keys.raw, floor });
  return [
    { op: "create", key: { type: "member-keys", teamId, accountId, memberKeysVersion }, record: memberKeysToJson(published) },
    { op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(wrap) },
  ];
}

/** Team creation (§6.3): member keys and version 1, owned by and rostered to the creator, in one batch; the bundle's floor is version 1 (D-48), returned too. */
export function newTeamOps(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  recoveryPublicKey: Uint8Array,
  memberKeysVersion: number,
): { ops: WriteOp[]; floor: Anchor } {
  const { suite, clock } = ports;
  const keys = generateMemberKeys(ports, account, teamId, memberKeysVersion, { recoveryPublicKey });
  const { bundle } = keys;
  const teamKey = suite.randomBytes(suite.sizes.key);
  const signer = { accountId: account.accountId, signingPublicKey: bundle.pairs.signing.publicKey };
  const version = createTeamKeyVersion(suite, {
    teamId,
    version: 1,
    prevHash: new Uint8Array(suite.sizes.hash),
    owners: [signer],
    roster: [
      {
        accountId: account.accountId,
        // The version the keys were numbered with: 1 unless keys were already published under the account (§6.3, §5.9).
        memberKeysVersion,
        keysHash: keysHash(suite, bundle.published),
        encryptionPublicKey: bundle.pairs.encryption.publicKey,
      },
    ],
    createdAt: clock.now(),
    signer,
    signerSecretKey: bundle.pairs.signing.secretKey,
    teamKey,
  });
  suite.wipe(teamKey);
  const floor = { version: 1, hash: recordHash(version) };
  return { ops: [...memberKeysOps(ports, account, keys, floor), { op: "create", key: { type: "team-key-version", teamId, version: 1 }, record: teamKeyVersionToJson(version) }], floor };
}

/** The vault's own anchor for a team, apart from the sessions' (D-54). */
export async function vaultAnchorOf(ports: AccountPorts, accountId: string, teamId: string): Promise<Anchor | null> {
  return callPort(() => ports.deviceKeys.getVaultAnchor(accountId, teamId));
}

/**
 * Records the tip of a chain the vault verified as its anchor, never moving it down; `replace`
 * when an owner's anchor rooted the chain, so a forged higher one is corrected (D-54).
 */
export async function recordVaultAnchor(ports: AccountPorts, accountId: string, teamId: string, anchor: Anchor, replace = false): Promise<void> {
  const known = await vaultAnchorOf(ports, accountId, teamId);
  if (replace || !known || known.version < anchor.version) await callPort(() => ports.deviceKeys.setVaultAnchor(accountId, teamId, anchor));
}

/**
 * Opens a session in the vault's own context (§5.8), with the vault's anchor as a root too. Any
 * trust failure, in this account's own keys or in the team's records, gives an `unverified` session
 * (§6.1). Then records the vault's anchor, moves the floor and cleans up from the chain the session
 * verified, with no second download.
 */
export async function openSession(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<TeamSession> {
  if (!ports.anchors) throw new Error("crypto-convoy: give the vault `anchors` to open teams in its context, or use exportTeamKeys");
  let bundles: MemberBundle[];
  try {
    bundles = await openBundles(ports, account, teamId);
  } catch (error) {
    if (isConvoyError(error, "TRUST_FAILURE")) return TeamSession.failed(teamPorts(ports), account.accountId, teamId, error);
    throw error;
  }
  const vault = await vaultAnchorOf(ports, account.accountId, teamId);
  const session = await TeamSession.open(teamPorts(ports), account.accountId, teamId, bundles, vault ? [vault] : []);
  if (bundles.length > 0 && session.state !== "unverified") {
    const internals = sessionInternals(session);
    const tip = internals.current();
    await recordVaultAnchor(ports, account.accountId, teamId, { version: tip.version, hash: internals.currentHash() });
    await maintainBundles(ports, account, teamId, bundles, tip, internals.currentHash());
  }
  return session;
}

/** Only what team work needs: no OPRF, no account key (D-03). */
function teamPorts({ suite, store, anchors, clock, settings }: AccountPorts): TeamPorts {
  return { suite, store, anchors: anchors!, clock, settings };
}

/**
 * One team's member keys sealed to a receiver in another context (§3.8, D-29), after the vault
 * verified the chain from its roots: a planted floor or a forged chain is refused, never sealed
 * (D-54). Throws `NOT_GRANTED` without keys, `TRUST_FAILURE`.
 */
export async function exportBundles(ports: AccountPorts, account: OpenAccount, teamId: string, request: string): Promise<string> {
  const { suite } = ports;
  const receiver = decodeRequest(suite, request);
  let bundles = await openBundles(ports, account, teamId);
  if (bundles.length === 0) throw new ConvoyError("NOT_GRANTED");
  const vault = await vaultAnchorOf(ports, account.accountId, teamId);
  const chain = await loadChain(ports, account.accountId, teamId, bundles, vault ? [vault] : []);
  const tip = chain.records.at(-1)!;
  const tipHash = chain.hashes.get(tip.version)!;
  await recordVaultAnchor(ports, account.accountId, teamId, { version: tip.version, hash: tipHash });
  bundles = await maintainBundles(ports, account, teamId, bundles, tip, tipHash);
  return sealTransfer(
    suite,
    receiver,
    { accountId: account.accountId, teamId },
    bundles.map((b) => ({
      memberKeysVersion: b.memberKeysVersion,
      // libsodium's Ed25519 secret key is seed ‖ public key.
      signingSeed: b.pairs.signing.secretKey.subarray(0, 32),
      encryptionSecretKey: b.pairs.encryption.secretKey,
      floor: b.floor,
    })),
  );
}

/** The owners of the newest verified version, read in the vault for the last-owner rule (§5.9). */
export async function currentOwners(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<string[]> {
  const bundles = await openBundles(ports, account, teamId);
  const vault = await vaultAnchorOf(ports, account.accountId, teamId);
  const chain = await loadChain(ports, account.accountId, teamId, bundles, vault ? [vault] : []);
  return chain.records.at(-1)!.owners.map((o) => o.accountId);
}

/**
 * Vault upkeep after the chain was verified up to `tip` (§5.8 step 3), in one batch. The floor
 * follows the chain verified from every root: the newest bundle's wrap is replaced with `tip` as its floor (D-52, D-54).
 * Once the tip's roster holds the newest keys, older bundles open nothing the chain doesn't
 * (§6.8 step 4): their wraps are deleted. Best effort: on any failure nothing is written.
 */
async function maintainBundles(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  bundles: MemberBundle[],
  tip: TeamKeyVersion,
  tipHash: Uint8Array,
): Promise<MemberBundle[]> {
  const [newest, ...older] = bundles;
  if (!newest) return bundles;
  const { suite } = ports;
  const { accountId } = account;
  try {
    const ops: WriteOp[] = [];
    let kept = newest;
    if (tip.version > newest.floor.version) {
      const floor = { version: tip.version, hash: tipHash };
      const context = { accountId, teamId, memberKeysVersion: newest.memberKeysVersion, accountKeyVersion: account.version };
      const raw = { signingSeed: newest.pairs.signing.secretKey.subarray(0, 32), encryptionSecretKey: newest.pairs.encryption.secretKey, floor };
      ops.push({ op: "replace", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(createMemberKeysWrap(suite, context, account.key, raw)) });
      kept = { ...newest, floor };
    }
    const hash = keysHash(suite, newest.published);
    const held = tip.roster.some(
      (e) => e.accountId === accountId && e.memberKeysVersion === newest.memberKeysVersion && suite.equal(e.keysHash, hash),
    );
    const cleanUp = older.length > 0 && held;
    if (cleanUp) {
      ops.push(
        ...older.map((b): WriteOp => ({
          op: "delete",
          key: { type: "member-keys-wrap", accountId, teamId, memberKeysVersion: b.memberKeysVersion, accountKeyVersion: account.version },
        })),
      );
    }
    if (ops.length === 0) return bundles;
    await callPort(() => ports.store.commit(ops));
    return cleanUp ? [kept] : [kept, ...older];
  } catch (error) {
    if (isConvoyError(error) || error instanceof StoreConflictError) return bundles;
    throw error;
  }
}
