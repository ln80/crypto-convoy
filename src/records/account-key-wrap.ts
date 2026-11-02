// account-key-wrap (§4.1): the account key, wrapped for one unlock method.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { bytes, optional, string, u32, u64, type Field } from "../encoding/canonical.js";
import { b64, type JsonRecord } from "../encoding/json.js";
import { ConvoyError, decryptionFailed, malformed } from "../errors.js";
import { ARGON2_BOUNDS } from "../suites/cc1/index.js";
import type { Suite } from "../suites/suite.js";
import { expectContext, readRecord, readWrapped, writeHeader, writeWrapped, type RecordHeader } from "./common.js";

const ACCOUNT_KEY_WRAP = "account-key-wrap";

export type UnlockMethod = "pin" | "recovery" | "device";

/** Argon2id parameters and the server OPRF key a PIN wrap was made with. */
export interface Kdf {
  readonly salt: Uint8Array;
  readonly opslimit: number;
  readonly memlimit: number;
  readonly oprfKeyId: number;
}

interface AccountKeyWrapContext {
  readonly accountId: string;
  readonly accountKeyVersion: number;
  readonly method: UnlockMethod;
  /** Only for `device`. */
  readonly deviceId?: string;
  /** Only for `pin`. */
  readonly kdf?: Kdf;
}

export interface AccountKeyWrap extends RecordHeader, AccountKeyWrapContext {
  readonly wrappedAccountKey: Wrapped;
  /** Only for `recovery`: the recovery signing key's public half, under the account key (§4.1, D-33). */
  readonly wrappedRecoveryPublicKey?: Wrapped;
}

const KEY = 32;

function adFields(context: AccountKeyWrapContext): Field[] {
  const { kdf } = context;
  return [
    string(context.accountId),
    u32(context.accountKeyVersion),
    string(context.method),
    optional(context.deviceId, string),
    ...(kdf ? [bytes(kdf.salt), u64(kdf.opslimit), u64(kdf.memlimit), u32(kdf.oprfKeyId)] : []),
  ];
}

const recoveryContext = (c: Pick<AccountKeyWrapContext, "accountId" | "accountKeyVersion">): Field[] => [
  string(c.accountId),
  u32(c.accountKeyVersion),
];

function checkMethodFields(context: AccountKeyWrapContext) {
  if ((context.method === "device") !== (context.deviceId !== undefined)) throw malformed();
  if ((context.method === "pin") !== (context.kdf !== undefined)) throw malformed();
}

/** `recoveryPublicKey` is required for `recovery` and refused otherwise. */
export function createAccountKeyWrap(
  suite: Suite,
  context: AccountKeyWrapContext,
  methodKey: Uint8Array,
  accountKey: Uint8Array,
  recoveryPublicKey?: Uint8Array,
): AccountKeyWrap {
  checkMethodFields(context);
  if ((context.method === "recovery") !== (recoveryPublicKey !== undefined)) throw malformed();
  const wrappedAccountKey = wrap(suite, methodKey, "account-key-wrap", adFields(context), accountKey);
  return {
    v: 1,
    suite,
    ...context,
    wrappedAccountKey,
    ...(recoveryPublicKey
      ? { wrappedRecoveryPublicKey: wrap(suite, accountKey, "recovery-public-key", recoveryContext(context), recoveryPublicKey) }
      : {}),
  };
}

/** §8 steps 1–3. `expected` names the wrap the caller asked for; `kdf` comes from the record. */
export function parseAccountKeyWrap(json: unknown, expected: Omit<AccountKeyWrapContext, "kdf">): AccountKeyWrap {
  const method = (json as JsonRecord | null)?.["method"];
  const optional = method === "device" ? ["deviceId"] : method === "pin" ? ["kdf"] : ["wrappedRecoveryPublicKey"];
  const { header, fields } = readRecord(
    json,
    ACCOUNT_KEY_WRAP,
    ["accountId", "accountKeyVersion", "method", ...optional, "wrappedAccountKey"],
  );
  const { suite } = header;
  let kdf: Kdf | undefined;
  if (fields.has("kdf")) {
    const k = fields.object("kdf", ["salt", "opslimit", "memlimit", "oprfKeyId"]);
    kdf = {
      salt: k.bytes("salt", suite.sizes.salt),
      opslimit: k.int("opslimit", ARGON2_BOUNDS.minOpslimit, ARGON2_BOUNDS.maxOpslimit),
      memlimit: k.int("memlimit", ARGON2_BOUNDS.minMemlimit, ARGON2_BOUNDS.maxMemlimit),
      oprfKeyId: k.u32("oprfKeyId"),
    };
  }
  const record: AccountKeyWrap = {
    ...header,
    accountId: fields.id("accountId"),
    accountKeyVersion: fields.u32("accountKeyVersion", 1),
    method: fields.literal("method", ["pin", "recovery", "device"]),
    ...(fields.has("deviceId") ? { deviceId: fields.randomId("deviceId") } : {}),
    ...(kdf ? { kdf } : {}),
    wrappedAccountKey: readWrapped(fields, "wrappedAccountKey", suite, KEY + suite.sizes.tag),
    ...(fields.has("wrappedRecoveryPublicKey")
      ? { wrappedRecoveryPublicKey: readWrapped(fields, "wrappedRecoveryPublicKey", suite, KEY + suite.sizes.tag) }
      : {}),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/** Throws `WRONG_CREDENTIAL` for a PIN or phrase, `DECRYPTION_FAILED` for a device key (§4.1). */
export function openAccountKeyWrap(record: AccountKeyWrap, methodKey: Uint8Array): Uint8Array {
  let accountKey: Uint8Array;
  try {
    accountKey = unwrap(record.suite, methodKey, "account-key-wrap", adFields(record), record.wrappedAccountKey);
  } catch (error) {
    throw record.method === "device" ? error : new ConvoyError("WRONG_CREDENTIAL");
  }
  if (accountKey.length !== KEY) throw decryptionFailed();
  return accountKey;
}

/**
 * The recovery public key, authenticated by the account key (§4.1): a vault opened by the PIN or
 * a device reads it without the phrase. Throws `DECRYPTION_FAILED`, `MALFORMED_RECORD`.
 */
export function openRecoveryPublicKey(record: AccountKeyWrap, accountKey: Uint8Array): Uint8Array {
  if (!record.wrappedRecoveryPublicKey) throw malformed();
  const key = unwrap(record.suite, accountKey, "recovery-public-key", recoveryContext(record), record.wrappedRecoveryPublicKey);
  if (key.length !== KEY || !record.suite.isValidSigningPublicKey(key)) throw malformed();
  return key;
}

export function accountKeyWrapToJson(record: AccountKeyWrap): JsonRecord {
  const { kdf } = record;
  return {
    ...writeHeader(ACCOUNT_KEY_WRAP, record.suite),
    accountId: record.accountId,
    accountKeyVersion: record.accountKeyVersion,
    method: record.method,
    ...(record.deviceId !== undefined ? { deviceId: record.deviceId } : {}),
    ...(kdf
      ? { kdf: { salt: b64(kdf.salt), opslimit: kdf.opslimit, memlimit: kdf.memlimit, oprfKeyId: kdf.oprfKeyId } }
      : {}),
    wrappedAccountKey: writeWrapped(record.wrappedAccountKey),
    ...(record.wrappedRecoveryPublicKey ? { wrappedRecoveryPublicKey: writeWrapped(record.wrappedRecoveryPublicKey) } : {}),
  };
}
