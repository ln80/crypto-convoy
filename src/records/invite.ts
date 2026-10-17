// invite (§4.11): an owner's invitation, carrying a join secret wrapped under the team key (D-32).
import { sign, verify } from "../blocks/sign.js";
import { unwrap, wrap, wrappedHash, type Wrapped } from "../blocks/wrap.js";
import { bytes, optional, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
import { decryptionFailed } from "../errors.js";
import type { Suite } from "../suites/suite.js";
import {
  expectContext,
  readRecord,
  readSigner,
  readWrapped,
  writeHeader,
  writeSigner,
  writeWrapped,
  type RecordHeader,
  type SignerRef,
} from "./common.js";

export const INVITE = "invite";

const SECRET = 32;

export interface InviteContext {
  readonly teamId: string;
  readonly inviteId: string;
}

export interface Invite extends RecordHeader, InviteContext {
  readonly teamKeyVersion: number;
  /** Opaque to the library: the integration's reference to the invitee. */
  readonly inviteeRef?: string;
  readonly wrappedSecret: Wrapped;
  readonly signer: SignerRef;
  readonly createdAt: number;
  readonly signature: Uint8Array;
}

const wrapContext = (r: Pick<Invite, "teamId" | "inviteId" | "teamKeyVersion" | "inviteeRef">): Field[] => [
  string(r.teamId),
  string(r.inviteId),
  u32(r.teamKeyVersion),
  optional(r.inviteeRef, string),
];

const signedFields = (suite: Suite, r: Omit<Invite, "v" | "suite" | "signature">): Field[] => [
  ...wrapContext(r),
  bytes(wrappedHash(suite, r.wrappedSecret)),
  string(r.signer.accountId),
  bytes(r.signer.signingPublicKey),
  u64(r.createdAt),
];

export interface NewInvite extends InviteContext {
  readonly teamKeyVersion: number;
  readonly inviteeRef?: string;
  readonly teamKey: Uint8Array;
  readonly secret: Uint8Array;
  readonly signer: SignerRef;
  readonly signerSecretKey: Uint8Array;
  readonly createdAt: number;
}

export function createInvite(suite: Suite, input: NewInvite): Invite {
  const { teamKey, secret, signerSecretKey, inviteeRef, ...rest } = input;
  const base = { ...rest, ...(inviteeRef !== undefined ? { inviteeRef } : {}) };
  const unsigned = { ...base, wrappedSecret: wrap(suite, teamKey, "invite-secret", wrapContext(base), secret) };
  return { v: 1, suite, ...unsigned, signature: sign(suite, signerSecretKey, "invite", signedFields(suite, unsigned)) };
}

/** §8 steps 1–4. The owner rule (signer in the owners of `teamKeyVersion`) needs the chain: the team session checks it. */
export function parseInvite(json: unknown, expected: InviteContext): Invite {
  const { header, fields } = readRecord(
    json,
    INVITE,
    ["teamId", "inviteId", "teamKeyVersion", "wrappedSecret", "signer", "createdAt", "signature"],
    ["inviteeRef"],
  );
  const { suite } = header;
  const record: Invite = {
    ...header,
    teamId: fields.id("teamId"),
    inviteId: fields.id("inviteId"),
    teamKeyVersion: fields.u32("teamKeyVersion", 1),
    ...(fields.has("inviteeRef") ? { inviteeRef: fields.id("inviteeRef") } : {}),
    wrappedSecret: readWrapped(fields, "wrappedSecret", suite, SECRET + suite.sizes.tag),
    signer: readSigner((json as JsonRecord)["signer"], suite),
    createdAt: fields.int("createdAt"),
    signature: fields.bytes("signature", suite.sizes.signature),
  };
  expectContext({ ...expected }, { ...record });
  verify(suite, record.signer.signingPublicKey, "invite", signedFields(suite, record), record.signature);
  return record;
}

/** The join secret, with the team key of the invite's version. Throws `DECRYPTION_FAILED`. */
export function openInviteSecret(record: Invite, teamKey: Uint8Array): Uint8Array {
  const secret = unwrap(record.suite, teamKey, "invite-secret", wrapContext(record), record.wrappedSecret);
  if (secret.length !== SECRET) throw decryptionFailed();
  return secret;
}

export function inviteToJson(record: Invite): JsonRecord {
  return {
    ...writeHeader(INVITE, record.suite),
    teamId: record.teamId,
    inviteId: record.inviteId,
    teamKeyVersion: record.teamKeyVersion,
    ...(record.inviteeRef !== undefined ? { inviteeRef: record.inviteeRef } : {}),
    wrappedSecret: writeWrapped(record.wrappedSecret),
    signer: writeSigner(record.signer),
    createdAt: record.createdAt,
    signature: b64(record.signature),
  };
}
