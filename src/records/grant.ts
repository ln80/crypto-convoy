// grant (§4.6): one team key version for one member's keys, sealed and owner-signed.
import { open, seal } from "../blocks/seal.js";
import { sign, verify } from "../blocks/sign.js";
import { bytes, optional, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
import { decryptionFailed } from "../errors.js";
import type { KeyPair, Suite } from "../suites/suite.js";
import { expectContext, readRecord, readSigner, writeHeader, writeSigner, type RecordHeader, type SignerRef } from "./common.js";

export const GRANT = "grant";

export interface GrantContext {
  readonly teamId: string;
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly teamKeyVersion: number;
}

export interface Grant extends RecordHeader, GrantContext {
  /** The keys hash of the member's `member-keys` record (§4.2). */
  readonly keysHash: Uint8Array;
  readonly sealedTeamKey: Uint8Array;
  /** The invite whose proof this grant accepted (§6.9). */
  readonly inviteId?: string;
  readonly signer: SignerRef;
  readonly createdAt: number;
  readonly signature: Uint8Array;
}

const KEY = 32;
// Seal overhead 48, plus the label, two ids of at most 128 bytes, two u32 and the key (§3.2).
const SEALED_MAX = 48 + 4 + 64 + 2 * (4 + 128) + 8 + 4 + KEY;

const sealContext = (c: GrantContext): Field[] => [
  string(c.teamId),
  string(c.accountId),
  u32(c.memberKeysVersion),
  u32(c.teamKeyVersion),
];

const signedFields = (suite: Suite, g: Omit<Grant, "v" | "suite" | "signature">): Field[] => [
  string(g.teamId),
  string(g.accountId),
  u32(g.memberKeysVersion),
  bytes(g.keysHash),
  u32(g.teamKeyVersion),
  bytes(suite.hash(g.sealedTeamKey)),
  optional(g.inviteId, string),
  string(g.signer.accountId),
  bytes(g.signer.signingPublicKey),
  u64(g.createdAt),
];

export interface NewGrant extends GrantContext {
  readonly keysHash: Uint8Array;
  /** The member's encryption key, from the `member-keys` record `keysHash` names. */
  readonly encryptionPublicKey: Uint8Array;
  readonly inviteId?: string;
  readonly teamKey: Uint8Array;
  readonly signer: SignerRef;
  readonly signerSecretKey: Uint8Array;
  readonly createdAt: number;
}

/** Seals to the member's encryption key; throws `MALFORMED_RECORD` for a low-order key. */
export function createGrant(suite: Suite, input: NewGrant): Grant {
  const { teamKey, signerSecretKey, encryptionPublicKey, inviteId, ...rest } = input;
  const unsigned = {
    ...rest,
    ...(inviteId !== undefined ? { inviteId } : {}),
    sealedTeamKey: seal(suite, encryptionPublicKey, "grant-seal", sealContext(input), teamKey),
  };
  return { v: 1, suite, ...unsigned, signature: sign(suite, signerSecretKey, "grant", signedFields(suite, unsigned)) };
}

/**
 * §8 steps 1–4: shape, version, context, signature. The owner rule (signer in the owners
 * of `teamKeyVersion`) needs the chain and is checked by the team session.
 */
export function parseGrant(json: unknown, expected: { teamId: string } & Partial<GrantContext>): Grant {
  const { header, fields } = readRecord(
    json,
    GRANT,
    ["teamId", "accountId", "memberKeysVersion", "keysHash", "teamKeyVersion", "sealedTeamKey", "signer", "createdAt", "signature"],
    ["inviteId"],
  );
  const { suite } = header;
  const record: Grant = {
    ...header,
    teamId: fields.id("teamId"),
    accountId: fields.id("accountId"),
    memberKeysVersion: fields.u32("memberKeysVersion", 1),
    keysHash: fields.bytes("keysHash", suite.sizes.hash),
    teamKeyVersion: fields.u32("teamKeyVersion", 1),
    sealedTeamKey: fields.bytesUpTo("sealedTeamKey", 48, SEALED_MAX),
    ...(fields.has("inviteId") ? { inviteId: fields.id("inviteId") } : {}),
    signer: readSigner((json as JsonRecord)["signer"], suite),
    createdAt: fields.int("createdAt"),
    signature: fields.bytes("signature", suite.sizes.signature),
  };
  expectContext({ ...expected }, { ...record });
  verify(suite, record.signer.signingPublicKey, "grant", signedFields(suite, record), record.signature);
  return record;
}

/** Opens the team key with the member's own encryption keys. Throws `DECRYPTION_FAILED`. */
export function openGrant(record: Grant, encryption: KeyPair): Uint8Array {
  const teamKey = open(record.suite, encryption, "grant-seal", sealContext(record), record.sealedTeamKey);
  if (teamKey.length !== KEY) throw decryptionFailed();
  return teamKey;
}

export function grantToJson(record: Grant): JsonRecord {
  return {
    ...writeHeader(GRANT, record.suite),
    teamId: record.teamId,
    accountId: record.accountId,
    memberKeysVersion: record.memberKeysVersion,
    keysHash: b64(record.keysHash),
    teamKeyVersion: record.teamKeyVersion,
    sealedTeamKey: b64(record.sealedTeamKey),
    ...(record.inviteId !== undefined ? { inviteId: record.inviteId } : {}),
    signer: writeSigner(record.signer),
    createdAt: record.createdAt,
    signature: b64(record.signature),
  };
}
