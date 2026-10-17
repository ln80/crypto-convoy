// member-keys (§4.2): a member's public keys for one team, self-signed, with optional proofs. Public.
import { sign, verify } from "../blocks/sign.js";
import { bytes, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
import { labelled } from "../encoding/labels.js";
import type { Suite } from "../suites/suite.js";
import { expectContext, readEncryptionKey, readRecord, readSigningKey, writeHeader, type RecordHeader } from "./common.js";

export const MEMBER_KEYS = "member-keys";

export interface MemberKeysContext {
  readonly teamId: string;
  readonly accountId: string;
  readonly memberKeysVersion: number;
}

/** A join proof made with an invite link's secret (§4.2, D-32). */
export interface InviteProof {
  readonly inviteId: string;
  readonly mac: Uint8Array;
}

export interface MemberKeys extends RecordHeader, MemberKeysContext {
  readonly signingPublicKey: Uint8Array;
  readonly encryptionPublicKey: Uint8Array;
  /** The account's recovery signing key (§5.2, D-33). */
  readonly recoveryPublicKey: Uint8Array;
  readonly createdAt: number;
  readonly signature: Uint8Array;
  /** Signed by the previous keys on a re-key: a hint, never an approval (§6.8, SP-12). */
  readonly continuitySignature?: Uint8Array;
  /** Signed by a recovery signing key: a proof when it is the held keys' one (§6.8, SP-23). */
  readonly recoverySignature?: Uint8Array;
  readonly inviteProof?: InviteProof;
}

type Keys = Omit<MemberKeys, "v" | "suite" | "signature" | "continuitySignature" | "recoverySignature" | "inviteProof">;
type PublicKeys = Omit<Keys, "createdAt">;

/** `keysPayload` of §4.2: what every proof covers. */
const keysFields = (r: PublicKeys): Field[] => [
  string(r.teamId),
  string(r.accountId),
  u32(r.memberKeysVersion),
  bytes(r.signingPublicKey),
  bytes(r.encryptionPublicKey),
  bytes(r.recoveryPublicKey),
];

const signedFields = (r: Keys): Field[] => [...keysFields(r), u64(r.createdAt)];

/** The hash grants and rosters pin (§4.2). */
export function keysHash(suite: Suite, keys: PublicKeys): Uint8Array {
  return suite.hash(labelled("member-keys-hash", ...keysFields(keys)));
}

export function inviteMac(suite: Suite, secret: Uint8Array, inviteId: string, keys: PublicKeys): Uint8Array {
  return suite.keyedHash(secret, labelled("invite-proof", string(inviteId), ...keysFields(keys)));
}

export interface MemberKeysProofs {
  /** The member's previous signing key: a continuity hint. */
  readonly previousSigningSecretKey?: Uint8Array;
  /** The recovery signing key derived from the phrase: a proof. */
  readonly recoverySigningSecretKey?: Uint8Array;
  /** A first join with an invite link. */
  readonly invite?: { readonly inviteId: string; readonly secret: Uint8Array };
}

export function createMemberKeys(suite: Suite, keys: Keys, signingSecretKey: Uint8Array, proofs: MemberKeysProofs = {}): MemberKeys {
  return {
    v: 1,
    suite,
    ...keys,
    signature: sign(suite, signingSecretKey, "member-keys", signedFields(keys)),
    ...(proofs.previousSigningSecretKey
      ? { continuitySignature: sign(suite, proofs.previousSigningSecretKey, "member-keys-continuity", keysFields(keys)) }
      : {}),
    ...(proofs.recoverySigningSecretKey
      ? { recoverySignature: sign(suite, proofs.recoverySigningSecretKey, "member-keys-recovery", keysFields(keys)) }
      : {}),
    ...(proofs.invite
      ? { inviteProof: { inviteId: proofs.invite.inviteId, mac: inviteMac(suite, proofs.invite.secret, proofs.invite.inviteId, keys) } }
      : {}),
  };
}

/** §8 steps 1–4: shape, version, context, self-signature (§4.2). Proofs are checked by whoever needs them. */
export function parseMemberKeys(
  json: unknown,
  expected: Pick<MemberKeysContext, "teamId" | "accountId"> & Partial<MemberKeysContext>,
): MemberKeys {
  const { header, fields } = readRecord(
    json,
    MEMBER_KEYS,
    ["teamId", "accountId", "memberKeysVersion", "signingPublicKey", "encryptionPublicKey", "recoveryPublicKey", "createdAt", "signature"],
    ["continuitySignature", "recoverySignature", "inviteProof"],
  );
  const { suite } = header;
  let inviteProof: InviteProof | undefined;
  if (fields.has("inviteProof")) {
    const proof = fields.object("inviteProof", ["inviteId", "mac"]);
    inviteProof = { inviteId: proof.id("inviteId"), mac: proof.bytes("mac", suite.sizes.hash) };
  }
  const record: MemberKeys = {
    ...header,
    teamId: fields.id("teamId"),
    accountId: fields.id("accountId"),
    memberKeysVersion: fields.u32("memberKeysVersion", 1),
    signingPublicKey: readSigningKey(fields, "signingPublicKey", suite),
    encryptionPublicKey: readEncryptionKey(fields, "encryptionPublicKey", suite),
    recoveryPublicKey: readSigningKey(fields, "recoveryPublicKey", suite),
    createdAt: fields.int("createdAt"),
    signature: fields.bytes("signature", suite.sizes.signature),
    ...(fields.has("continuitySignature") ? { continuitySignature: fields.bytes("continuitySignature", suite.sizes.signature) } : {}),
    ...(fields.has("recoverySignature") ? { recoverySignature: fields.bytes("recoverySignature", suite.sizes.signature) } : {}),
    ...(inviteProof ? { inviteProof } : {}),
  };
  expectContext({ ...expected }, { ...record });
  verify(suite, record.signingPublicKey, "member-keys", signedFields(record), record.signature);
  return record;
}

function verifies(check: () => void): boolean {
  try {
    check();
    return true;
  } catch {
    return false;
  }
}

/** Whether the record's continuity signature verifies with the previous version's key (§4.2): a hint. */
export function hasValidContinuity(record: MemberKeys, previous: MemberKeys): boolean {
  if (!record.continuitySignature || previous.memberKeysVersion !== record.memberKeysVersion - 1) return false;
  const signature = record.continuitySignature;
  return verifies(() => verify(record.suite, previous.signingPublicKey, "member-keys-continuity", keysFields(record), signature));
}

/**
 * Whether the record's recovery signature verifies with `recoveryPublicKey`, which must be the
 * one of the keys the account holds (§4.2). Only then is the re-key proven (SP-23).
 */
export function hasValidRecoveryProof(record: MemberKeys, recoveryPublicKey: Uint8Array): boolean {
  const signature = record.recoverySignature;
  if (!signature) return false;
  return verifies(() => verify(record.suite, recoveryPublicKey, "member-keys-recovery", keysFields(record), signature));
}

/** Whether the record's invite proof verifies with the invite's join secret (§4.2, SP-24). */
export function hasValidInviteProof(record: MemberKeys, inviteId: string, secret: Uint8Array): boolean {
  const proof = record.inviteProof;
  if (!proof || proof.inviteId !== inviteId) return false;
  // Constant time: the MAC is a secret-keyed value (crypto rules).
  return record.suite.equal(proof.mac, inviteMac(record.suite, secret, inviteId, record));
}

export function memberKeysToJson(record: MemberKeys): JsonRecord {
  return {
    ...writeHeader(MEMBER_KEYS, record.suite),
    teamId: record.teamId,
    accountId: record.accountId,
    memberKeysVersion: record.memberKeysVersion,
    signingPublicKey: b64(record.signingPublicKey),
    encryptionPublicKey: b64(record.encryptionPublicKey),
    recoveryPublicKey: b64(record.recoveryPublicKey),
    createdAt: record.createdAt,
    signature: b64(record.signature),
    ...(record.continuitySignature ? { continuitySignature: b64(record.continuitySignature) } : {}),
    ...(record.recoverySignature ? { recoverySignature: b64(record.recoverySignature) } : {}),
    ...(record.inviteProof ? { inviteProof: { inviteId: record.inviteProof.inviteId, mac: b64(record.inviteProof.mac) } } : {}),
  };
}
