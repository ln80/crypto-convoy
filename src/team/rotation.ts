// Rotating the team key and changing the owner list (§6.6, §6.7, §6.8): one record with its roster (D-34).
import { trustFailure } from "../errors.js";
import type { WriteOp } from "../ports.js";
import type { SignerRef } from "../records/common.js";
import { keysHash, type MemberKeys } from "../records/member-keys.js";
import { createTeamKeyVersion, teamKeyVersionToJson, type TeamKeyVersion } from "../records/team-key-version.js";
import type { Suite } from "../suites/suite.js";
import type { TeamPorts } from "./context.js";

/** One set of keys an account receives a version with: its published `member-keys` record, pinned by hash. */
export interface Recipient {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly keysHash: Uint8Array;
  readonly signingPublicKey: Uint8Array;
  readonly encryptionPublicKey: Uint8Array;
}

export function recipientFromKeys(suite: Suite, keys: MemberKeys): Recipient {
  return {
    accountId: keys.accountId,
    memberKeysVersion: keys.memberKeysVersion,
    keysHash: keysHash(suite, keys),
    signingPublicKey: keys.signingPublicKey,
    encryptionPublicKey: keys.encryptionPublicKey,
  };
}

export interface Signer {
  readonly ref: SignerRef;
  readonly secretKey: Uint8Array;
}

/**
 * The new version record (§4.5) with its roster, owners taken from the recipients' keys so a
 * re-keyed owner's signing key is replaced too (§6.8 step 3). Throws `MALFORMED_RECORD` past
 * the §2 bounds, `TRUST_FAILURE` (`not_an_owner`) for an owner who isn't a recipient.
 */
export function versionOp(
  ports: TeamPorts,
  current: TeamKeyVersion,
  currentHash: Uint8Array,
  currentKey: Uint8Array,
  nextKey: Uint8Array,
  ownerIds: readonly string[],
  recipients: readonly Recipient[],
  signer: Signer,
): WriteOp {
  const owners = ownerIds.map((accountId) => {
    const recipient = recipients.find((r) => r.accountId === accountId);
    // New owners must be members holding the current version (§6.7 step 1).
    if (!recipient) throw trustFailure("not_an_owner");
    return { accountId, signingPublicKey: recipient.signingPublicKey };
  });
  const record = createTeamKeyVersion(ports.suite, {
    teamId: current.teamId,
    version: current.version + 1,
    prevHash: currentHash,
    owners,
    roster: recipients,
    createdAt: ports.clock.now(),
    signer: signer.ref,
    signerSecretKey: signer.secretKey,
    teamKey: nextKey,
    previousKey: currentKey,
  });
  return { op: "create", key: { type: "team-key-version", teamId: current.teamId, version: record.version }, record: teamKeyVersionToJson(record) };
}
