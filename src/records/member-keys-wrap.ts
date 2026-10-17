// member-keys-wrap (§4.3): a member's private keys for one team, under the account key.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { string, u32, type Field } from "../encoding/canonical.js";
import type { JsonRecord } from "../encoding/json.js";
import { decryptionFailed, trustFailure } from "../errors.js";
import { concat } from "../internal/bytes.js";
import type { KeyPair, Suite } from "../suites/suite.js";
import { expectContext, readRecord, readWrapped, writeHeader, writeWrapped, type RecordHeader } from "./common.js";
import type { MemberKeys } from "./member-keys.js";

export const MEMBER_KEYS_WRAP = "member-keys-wrap";

export interface MemberKeysWrapContext {
  readonly accountId: string;
  readonly teamId: string;
  readonly memberKeysVersion: number;
  readonly accountKeyVersion: number;
}

export interface MemberKeysWrap extends RecordHeader, MemberKeysWrapContext {
  readonly wrappedKeys: Wrapped;
}

/** One team's member keys, opened. Held by a team session only (D-03). */
export interface MemberKeyBundle {
  readonly signingSeed: Uint8Array;
  readonly encryptionSecretKey: Uint8Array;
  readonly teamStateKey: Uint8Array;
}

/** The bundle's key pairs, computed from the seed and secret key. */
export interface MemberKeyPairs {
  readonly signing: KeyPair;
  readonly encryption: KeyPair;
  readonly teamStateKey: Uint8Array;
}

const PART = 32;

const adFields = (c: MemberKeysWrapContext): Field[] => [
  string(c.accountId),
  string(c.teamId),
  u32(c.memberKeysVersion),
  u32(c.accountKeyVersion),
];

export function generateBundle(suite: Suite): MemberKeyBundle {
  return {
    signingSeed: suite.generateSigningSeed(),
    encryptionSecretKey: suite.generateEncryptionKeyPair().secretKey,
    teamStateKey: suite.randomBytes(suite.sizes.key),
  };
}

export function bundleKeyPairs(suite: Suite, bundle: MemberKeyBundle): MemberKeyPairs {
  return {
    signing: suite.signingKeyPair(bundle.signingSeed),
    encryption: { publicKey: suite.encryptionPublicKey(bundle.encryptionSecretKey), secretKey: bundle.encryptionSecretKey },
    teamStateKey: bundle.teamStateKey,
  };
}

export function createMemberKeysWrap(
  suite: Suite,
  context: MemberKeysWrapContext,
  accountKey: Uint8Array,
  bundle: MemberKeyBundle,
): MemberKeysWrap {
  const plaintext = concat(bundle.signingSeed, bundle.encryptionSecretKey, bundle.teamStateKey);
  try {
    return { v: 1, suite, ...context, wrappedKeys: wrap(suite, accountKey, "member-keys-wrap", adFields(context), plaintext) };
  } finally {
    suite.wipe(plaintext);
  }
}

export function parseMemberKeysWrap(
  json: unknown,
  expected: Pick<MemberKeysWrapContext, "accountId" | "accountKeyVersion"> & Partial<MemberKeysWrapContext>,
): MemberKeysWrap {
  const { header, fields } = readRecord(json, MEMBER_KEYS_WRAP, [
    "accountId",
    "teamId",
    "memberKeysVersion",
    "accountKeyVersion",
    "wrappedKeys",
  ]);
  const record: MemberKeysWrap = {
    ...header,
    accountId: fields.id("accountId"),
    teamId: fields.id("teamId"),
    memberKeysVersion: fields.u32("memberKeysVersion", 1),
    accountKeyVersion: fields.u32("accountKeyVersion", 1),
    wrappedKeys: readWrapped(fields, "wrappedKeys", header.suite, 3 * PART + header.suite.sizes.tag),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/**
 * Opens the bundle and checks it against the published keys (§4.3).
 * Throws `DECRYPTION_FAILED`, or `TRUST_FAILURE` (`key_mismatch`).
 */
export function openMemberKeysWrap(record: MemberKeysWrap, accountKey: Uint8Array, published: MemberKeys): MemberKeyBundle {
  const { suite } = record;
  if (published.memberKeysVersion !== record.memberKeysVersion) throw trustFailure("key_mismatch");
  const plaintext = unwrap(suite, accountKey, "member-keys-wrap", adFields(record), record.wrappedKeys);
  if (plaintext.length !== 3 * PART) throw decryptionFailed();
  const bundle = {
    signingSeed: plaintext.slice(0, PART),
    encryptionSecretKey: plaintext.slice(PART, 2 * PART),
    teamStateKey: plaintext.slice(2 * PART),
  };
  suite.wipe(plaintext);
  const pairs = bundleKeyPairs(suite, bundle);
  const matches =
    suite.equal(pairs.signing.publicKey, published.signingPublicKey) &&
    suite.equal(pairs.encryption.publicKey, published.encryptionPublicKey);
  if (!matches) throw trustFailure("key_mismatch");
  return bundle;
}

export function memberKeysWrapToJson(record: MemberKeysWrap): JsonRecord {
  return {
    ...writeHeader(MEMBER_KEYS_WRAP, record.suite),
    accountId: record.accountId,
    teamId: record.teamId,
    memberKeysVersion: record.memberKeysVersion,
    accountKeyVersion: record.accountKeyVersion,
    wrappedKeys: writeWrapped(record.wrappedKeys),
  };
}
