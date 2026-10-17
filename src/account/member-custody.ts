// Member keys live under the account key, so creating and opening them runs in the vault (§5.8, §5.9).
import type { Anchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError } from "../errors.js";
import { decodeRequest, sealTransfer } from "../records/transfer.js";
import { loadChain } from "../team/load.js";
import { callPort, type WriteOp } from "../ports.js";
import { createMemberKeys, keysHash, memberKeysToJson, parseMemberKeys, type MemberKeysProofs } from "../records/member-keys.js";
import {
  bundleKeyPairs,
  createMemberKeysWrap,
  generateBundle,
  memberKeysWrapToJson,
  openMemberKeysWrap,
  parseMemberKeysWrap,
} from "../records/member-keys-wrap.js";
import { createTeamKeyVersion, teamKeyVersionToJson } from "../records/team-key-version.js";
import type { MemberBundle, TeamPorts } from "../team/context.js";
import { TeamSession } from "../team/session.js";
import type { AccountPorts, OpenAccount } from "./context.js";

/** Every member key bundle of this account for the team, newest first, checked against the published keys. */
export async function openBundles(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<MemberBundle[]> {
  const { store, suite } = ports;
  const { accountId } = account;
  const wraps = (await callPort(() => store.list({ type: "member-keys-wrap", accountId, accountKeyVersion: account.version })))
    .map((json) => parseMemberKeysWrap(json, { accountId, accountKeyVersion: account.version }))
    .filter((wrap) => wrap.teamId === teamId)
    .sort((a, b) => b.memberKeysVersion - a.memberKeysVersion);
  const bundles: MemberBundle[] = [];
  for (const wrap of wraps) {
    const json = await callPort(() => store.get({ type: "member-keys", teamId, accountId, memberKeysVersion: wrap.memberKeysVersion }));
    const published = parseMemberKeys(json, { teamId, accountId, memberKeysVersion: wrap.memberKeysVersion });
    const bundle = openMemberKeysWrap(wrap, account.key, published);
    bundles.push({ memberKeysVersion: wrap.memberKeysVersion, published, pairs: bundleKeyPairs(suite, bundle) });
  }
  return bundles;
}

export interface NewMemberKeysOptions {
  /** The account's recovery public key, read authenticated from its recovery wrap (§4.1). */
  readonly recoveryPublicKey: Uint8Array;
  /** On a re-key: the previous keys sign for continuity (a hint). */
  readonly previous?: MemberBundle;
  readonly recoverySigningSecretKey?: Uint8Array;
  readonly invite?: MemberKeysProofs["invite"];
}

/** New member keys: the published record, with its proofs, and its wrap (§5.9). */
export function newMemberKeys(
  ports: AccountPorts,
  account: OpenAccount,
  teamId: string,
  memberKeysVersion: number,
  options: NewMemberKeysOptions,
): { ops: WriteOp[]; bundle: MemberBundle } {
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
    {
      ...(options.previous ? { previousSigningSecretKey: options.previous.pairs.signing.secretKey } : {}),
      ...(options.recoverySigningSecretKey ? { recoverySigningSecretKey: options.recoverySigningSecretKey } : {}),
      ...(options.invite ? { invite: options.invite } : {}),
    },
  );
  const context = { accountId, teamId, memberKeysVersion, accountKeyVersion: account.version };
  const wrap = createMemberKeysWrap(suite, context, account.key, raw);
  return {
    ops: [
      { op: "create", key: { type: "member-keys", teamId, accountId, memberKeysVersion }, record: memberKeysToJson(published) },
      { op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(wrap) },
    ],
    bundle: { memberKeysVersion, published, pairs },
  };
}

/** Team creation (§6.3): member keys and version 1, owned by and rostered to the creator, in one batch. */
export function newTeamOps(ports: AccountPorts, account: OpenAccount, teamId: string, recoveryPublicKey: Uint8Array): WriteOp[] {
  const { suite, clock } = ports;
  const { ops, bundle } = newMemberKeys(ports, account, teamId, 1, { recoveryPublicKey });
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
        memberKeysVersion: 1,
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
  return [...ops, { op: "create", key: { type: "team-key-version", teamId, version: 1 }, record: teamKeyVersionToJson(version) }];
}

/**
 * Opens a session in the vault's own context (§5.8). Any trust failure, in this account's own
 * keys or in the team's records, gives an `unverified` session (§6.1).
 */
export async function openSession(ports: AccountPorts, account: OpenAccount, teamId: string, invite?: Anchor): Promise<TeamSession> {
  if (!ports.anchors) throw new Error("crypto-convoy: give the vault `anchors` to open teams in its context, or use exportTeamKeys");
  let bundles: MemberBundle[];
  try {
    bundles = await openBundles(ports, account, teamId);
  } catch (error) {
    if (isConvoyError(error, "TRUST_FAILURE")) return TeamSession.failed(teamPorts(ports), account.accountId, teamId, error);
    throw error;
  }
  return TeamSession.open(teamPorts(ports), account.accountId, teamId, bundles, invite);
}

/** Only what team work needs: no OPRF, no account key (D-03). */
function teamPorts({ suite, store, anchors, clock, settings }: AccountPorts): TeamPorts {
  return { suite, store, anchors: anchors!, clock, settings };
}

/** One team's member keys sealed to a receiver in another context (§3.8, D-29). Throws `NOT_GRANTED` without keys. */
export async function exportBundles(ports: AccountPorts, account: OpenAccount, teamId: string, request: string): Promise<string> {
  const { suite } = ports;
  const receiver = decodeRequest(suite, request);
  const bundles = await openBundles(ports, account, teamId);
  if (bundles.length === 0) throw new ConvoyError("NOT_GRANTED");
  return sealTransfer(
    suite,
    receiver,
    { accountId: account.accountId, teamId },
    bundles.map((b) => ({
      memberKeysVersion: b.memberKeysVersion,
      // libsodium's Ed25519 secret key is seed ‖ public key.
      signingSeed: b.pairs.signing.secretKey.subarray(0, 32),
      encryptionSecretKey: b.pairs.encryption.secretKey,
      teamStateKey: b.pairs.teamStateKey,
    })),
  );
}

/** The owners of the newest verified version, read in the vault for the last-owner rule (§5.9). */
export async function currentOwners(ports: AccountPorts, account: OpenAccount, teamId: string): Promise<string[]> {
  const bundles = await openBundles(ports, account, teamId);
  const { chain } = await loadChain(ports, account.accountId, teamId, bundles);
  return chain.records.at(-1)!.owners.map((o) => o.accountId);
}
