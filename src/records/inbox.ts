// inbox (§4.9): public key in clear, secret key wrapped by the team key.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { bytes, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
import { decryptionFailed, trustFailure } from "../errors.js";
import type { KeyPair, Suite } from "../suites/suite.js";
import { expectContext, readEncryptionKey, readRecord, readWrapped, writeHeader, writeWrapped, type RecordHeader } from "./common.js";

export const INBOX = "inbox";

interface InboxContext {
  readonly teamId: string;
  readonly inboxId: string;
}

export interface Inbox extends RecordHeader, InboxContext {
  readonly teamKeyVersion: number;
  readonly publicKey: Uint8Array;
  readonly createdBy: string;
  readonly createdAt: number;
  readonly wrappedSecretKey: Wrapped;
}

const KEY = 32;

const adFields = (r: Omit<Inbox, "v" | "suite" | "wrappedSecretKey">): Field[] => [
  string(r.teamId),
  string(r.inboxId),
  u32(r.teamKeyVersion),
  bytes(r.publicKey),
  string(r.createdBy),
  u64(r.createdAt),
];

interface NewInbox extends InboxContext {
  readonly teamKeyVersion: number;
  readonly createdBy: string;
  readonly createdAt: number;
}

export function createInbox(suite: Suite, input: NewInbox, teamKey: Uint8Array): Inbox {
  const pair = suite.generateEncryptionKeyPair();
  try {
    const unwrapped = { ...input, publicKey: pair.publicKey };
    return { v: 1, suite, ...unwrapped, wrappedSecretKey: wrap(suite, teamKey, "inbox-key", adFields(unwrapped), pair.secretKey) };
  } finally {
    suite.wipe(pair.secretKey);
  }
}

export function parseInbox(json: unknown, expected: InboxContext): Inbox {
  const { header, fields } = readRecord(json, INBOX, [
    "teamId",
    "inboxId",
    "teamKeyVersion",
    "publicKey",
    "createdBy",
    "createdAt",
    "wrappedSecretKey",
  ]);
  const { suite } = header;
  const record: Inbox = {
    ...header,
    teamId: fields.id("teamId"),
    inboxId: fields.id("inboxId"),
    teamKeyVersion: fields.u32("teamKeyVersion", 1),
    publicKey: readEncryptionKey(fields, "publicKey", suite),
    createdBy: fields.id("createdBy"),
    createdAt: fields.int("createdAt"),
    wrappedSecretKey: readWrapped(fields, "wrappedSecretKey", suite, KEY + suite.sizes.tag),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/** The inbox key pair (§7.6 step 1). Throws `DECRYPTION_FAILED` or `TRUST_FAILURE` (`key_mismatch`). */
export function openInboxKey(record: Inbox, teamKey: Uint8Array): KeyPair {
  const { suite } = record;
  const secretKey = unwrap(suite, teamKey, "inbox-key", adFields(record), record.wrappedSecretKey);
  if (secretKey.length !== KEY) throw decryptionFailed();
  if (!suite.equal(suite.encryptionPublicKey(secretKey), record.publicKey)) throw trustFailure("key_mismatch");
  return { publicKey: record.publicKey, secretKey };
}

export function inboxToJson(record: Inbox): JsonRecord {
  return {
    ...writeHeader(INBOX, record.suite),
    teamId: record.teamId,
    inboxId: record.inboxId,
    teamKeyVersion: record.teamKeyVersion,
    publicKey: b64(record.publicKey),
    createdBy: record.createdBy,
    createdAt: record.createdAt,
    wrappedSecretKey: writeWrapped(record.wrappedSecretKey),
  };
}
