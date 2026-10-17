// Rotating the team key and changing the owner list (§6.6, §6.7, §6.8).
import { trustFailure } from "../errors.js";
import type { WriteOp } from "../ports.js";
import type { SignerRef } from "../records/common.js";
import { createGrant, grantToJson, type Grant } from "../records/grant.js";
import type { MemberKeys } from "../records/member-keys.js";
import { createTeamKeyVersion, teamKeyVersionToJson, type TeamKeyVersion } from "../records/team-key-version.js";
import type { TeamPorts } from "./context.js";

/** One set of keys per kept account: the approved re-key, or the keys in its current grant (§6.6 step 2). */
export interface Recipient {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly signingPublicKey: Uint8Array;
  readonly encryptionPublicKey: Uint8Array;
}

export function recipientFromGrant(grant: Grant): Recipient {
  return {
    accountId: grant.accountId,
    memberKeysVersion: grant.memberKeysVersion,
    signingPublicKey: grant.memberSigningPublicKey,
    encryptionPublicKey: grant.memberEncryptionPublicKey,
  };
}

export function recipientFromKeys(keys: MemberKeys): Recipient {
  return {
    accountId: keys.accountId,
    memberKeysVersion: keys.memberKeysVersion,
    signingPublicKey: keys.signingPublicKey,
    encryptionPublicKey: keys.encryptionPublicKey,
  };
}

export interface Signer {
  readonly ref: SignerRef;
  readonly secretKey: Uint8Array;
}

export function grantOp(ports: TeamPorts, teamId: string, version: number, teamKey: Uint8Array, to: Recipient, signer: Signer): WriteOp {
  const grant = createGrant(ports.suite, {
    teamId,
    accountId: to.accountId,
    memberKeysVersion: to.memberKeysVersion,
    teamKeyVersion: version,
    memberSigningPublicKey: to.signingPublicKey,
    memberEncryptionPublicKey: to.encryptionPublicKey,
    teamKey,
    signer: signer.ref,
    signerSecretKey: signer.secretKey,
    createdAt: ports.clock.now(),
  });
  const key = { type: "grant", teamId, accountId: to.accountId, memberKeysVersion: to.memberKeysVersion, teamKeyVersion: version } as const;
  return { op: "create", key, record: grantToJson(grant) };
}

/**
 * The new version record (§4.5), with owners taken from the recipients' keys so a
 * re-keyed owner's signing key is replaced too (§6.8 step 3).
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
    // New owners must be members with a valid grant for the current version (§6.7 step 1).
    if (!recipient) throw trustFailure("not_an_owner");
    return { accountId, signingPublicKey: recipient.signingPublicKey };
  });
  const record = createTeamKeyVersion(ports.suite, {
    teamId: current.teamId,
    version: current.version + 1,
    prevHash: currentHash,
    owners,
    createdAt: ports.clock.now(),
    signer: signer.ref,
    signerSecretKey: signer.secretKey,
    teamKey: nextKey,
    previousKey: currentKey,
  });
  return { op: "create", key: { type: "team-key-version", teamId: current.teamId, version: record.version }, record: teamKeyVersionToJson(record) };
}
