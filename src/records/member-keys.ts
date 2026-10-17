// member-keys (§4.2): a member's public keys for one team, self-signed. Public.
import { sign, verify } from "../blocks/sign.js";
import { bytes, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
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
  readonly createdAt: number;
  readonly signature: Uint8Array;
  /** Signed by the previous keys on a routine re-key: a hint, never an approval (§6.8, SP-12). */
  readonly continuitySignature?: Uint8Array;
}

type Unsigned = Omit<MemberKeys, "v" | "suite" | "signature" | "continuitySignature">;

const signedFields = (r: Unsigned): Field[] => [
  string(r.teamId),
  string(r.accountId),
  u32(r.memberKeysVersion),
  bytes(r.signingPublicKey),
  bytes(r.encryptionPublicKey),
  u64(r.createdAt),
];

const continuityFields = (r: Unsigned): Field[] => signedFields(r).slice(0, 5);

export function createMemberKeys(
  suite: Suite,
  keys: Unsigned,
  signingSecretKey: Uint8Array,
  previousSigningSecretKey?: Uint8Array,
): MemberKeys {
  return {
    v: 1,
    suite,
    ...keys,
    signature: sign(suite, signingSecretKey, "member-keys", signedFields(keys)),
    ...(previousSigningSecretKey
      ? { continuitySignature: sign(suite, previousSigningSecretKey, "member-keys-continuity", continuityFields(keys)) }
      : {}),
  };
}

/** §8 steps 1–4: shape, version, context, self-signature (§4.2). */
export function parseMemberKeys(
  json: unknown,
  expected: Pick<MemberKeysContext, "teamId" | "accountId"> & Partial<MemberKeysContext>,
): MemberKeys {
  const { header, fields } = readRecord(
    json,
    MEMBER_KEYS,
    ["teamId", "accountId", "memberKeysVersion", "signingPublicKey", "encryptionPublicKey", "createdAt", "signature"],
    ["continuitySignature"],
  );
  const { suite } = header;
  const record: MemberKeys = {
    ...header,
    teamId: fields.id("teamId"),
    accountId: fields.id("accountId"),
    memberKeysVersion: fields.u32("memberKeysVersion", 1),
    signingPublicKey: readSigningKey(fields, "signingPublicKey", suite),
    encryptionPublicKey: readEncryptionKey(fields, "encryptionPublicKey", suite),
    createdAt: fields.int("createdAt"),
    signature: fields.bytes("signature", suite.sizes.signature),
    ...(fields.has("continuitySignature")
      ? { continuitySignature: fields.bytes("continuitySignature", suite.sizes.signature) }
      : {}),
  };
  expectContext({ ...expected }, { ...record });
  verify(suite, record.signingPublicKey, "member-keys", signedFields(record), record.signature);
  return record;
}

/** Whether the record's continuity signature verifies with the previous version's key (§4.2). */
export function hasValidContinuity(record: MemberKeys, previous: MemberKeys): boolean {
  if (!record.continuitySignature || previous.memberKeysVersion !== record.memberKeysVersion - 1) return false;
  try {
    verify(record.suite, previous.signingPublicKey, "member-keys-continuity", continuityFields(record), record.continuitySignature);
    return true;
  } catch {
    return false;
  }
}

export function memberKeysToJson(record: MemberKeys): JsonRecord {
  return {
    ...writeHeader(MEMBER_KEYS, record.suite),
    teamId: record.teamId,
    accountId: record.accountId,
    memberKeysVersion: record.memberKeysVersion,
    signingPublicKey: b64(record.signingPublicKey),
    encryptionPublicKey: b64(record.encryptionPublicKey),
    createdAt: record.createdAt,
    signature: b64(record.signature),
    ...(record.continuitySignature ? { continuitySignature: b64(record.continuitySignature) } : {}),
  };
}
