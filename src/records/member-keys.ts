// member-keys (§4.2): a member's public keys for one team, self-signed, with an optional recovery proof. Public.
import { sign, verify } from "../blocks/sign.js";
import { bytes, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
import { labelled } from "../encoding/labels.js";
import { isConvoyError } from "../errors.js";
import type { Suite } from "../suites/suite.js";
import { expectContext, readEncryptionKey, readRecord, readSigningKey, writeHeader, type RecordHeader } from "./common.js";

export const MEMBER_KEYS = "member-keys";

export interface MemberKeysContext {
  readonly teamId: string;
  readonly accountId: string;
  readonly memberKeysVersion: number;
}

export interface MemberKeys extends RecordHeader, MemberKeysContext {
  readonly signingPublicKey: Uint8Array;
  readonly encryptionPublicKey: Uint8Array;
  /** The account's recovery signing key (§5.2, D-33). */
  readonly recoveryPublicKey: Uint8Array;
  readonly createdAt: number;
  readonly signature: Uint8Array;
  /** Signed by a recovery signing key: a proof when it is the held keys' one (§6.8, SP-23). */
  readonly recoverySignature?: Uint8Array;
}

type Keys = Omit<MemberKeys, "v" | "suite" | "signature" | "recoverySignature">;
type PublicKeys = Omit<Keys, "createdAt">;

/** `keysPayload` of §4.2: what the recovery proof covers. */
const keysFields = (r: PublicKeys): Field[] => [
  string(r.teamId),
  string(r.accountId),
  u32(r.memberKeysVersion),
  bytes(r.signingPublicKey),
  bytes(r.encryptionPublicKey),
  bytes(r.recoveryPublicKey),
];

const signedFields = (r: Keys): Field[] => [...keysFields(r), u64(r.createdAt)];

/** The hash rosters pin (§4.2). */
export function keysHash(suite: Suite, keys: PublicKeys): Uint8Array {
  return suite.hash(labelled("member-keys-hash", ...keysFields(keys)));
}

export interface MemberKeysProofs {
  /** The recovery signing key derived from the phrase: a proof (D-33). */
  readonly recoverySigningSecretKey?: Uint8Array;
}

export function createMemberKeys(suite: Suite, keys: Keys, signingSecretKey: Uint8Array, proofs: MemberKeysProofs = {}): MemberKeys {
  return {
    v: 1,
    suite,
    ...keys,
    signature: sign(suite, signingSecretKey, "member-keys", signedFields(keys)),
    ...(proofs.recoverySigningSecretKey
      ? { recoverySignature: sign(suite, proofs.recoverySigningSecretKey, "member-keys-recovery", keysFields(keys)) }
      : {}),
  };
}

/** §8 steps 1–4: shape, version, context, self-signature (§4.2). The recovery proof is checked by whoever needs it. */
export function parseMemberKeys(
  json: unknown,
  expected: Pick<MemberKeysContext, "teamId" | "accountId"> & Partial<MemberKeysContext>,
): MemberKeys {
  const { header, fields } = readRecord(
    json,
    MEMBER_KEYS,
    ["teamId", "accountId", "memberKeysVersion", "signingPublicKey", "encryptionPublicKey", "recoveryPublicKey", "createdAt", "signature"],
    ["recoverySignature"],
  );
  const { suite } = header;
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
    ...(fields.has("recoverySignature") ? { recoverySignature: fields.bytes("recoverySignature", suite.sizes.signature) } : {}),
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

/**
 * Whether the record's recovery signature verifies with `recoveryPublicKey`, which must be the
 * one of the keys the account holds (§4.2). Only then is the re-key proven (SP-23).
 */
export function hasValidRecoveryProof(record: MemberKeys, recoveryPublicKey: Uint8Array): boolean {
  const signature = record.recoverySignature;
  if (!signature) return false;
  return verifies(() => verify(record.suite, recoveryPublicKey, "member-keys-recovery", keysFields(record), signature));
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
    ...(record.recoverySignature ? { recoverySignature: b64(record.recoverySignature) } : {}),
  };
}

/**
 * A team's published records, as a list: one that fails its checks is left out, as if unpublished,
 * so it stops nothing else (§4.2, D-58). Only for lists that verify, overview, reconcile or approve.
 */
export function parseListedMemberKeys(jsons: readonly unknown[], expected: Pick<MemberKeysContext, "teamId"> & Partial<MemberKeysContext>): MemberKeys[] {
  const listed: MemberKeys[] = [];
  for (const json of jsons) {
    try {
      listed.push(parseMemberKeys(json, { ...expected, accountId: expected.accountId ?? (json as { accountId?: string } | null)?.accountId ?? "" }));
    } catch (error) {
      if (!isConvoyError(error)) throw error;
    }
  }
  return listed;
}
