// member-keys-wrap (§4.3): a member's private keys for one team, under the account key.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { Reader, bytes, optional, string, u32, type Field } from "../encoding/canonical.js";
import type { Anchor } from "../encoding/link.js";
import type { JsonRecord } from "../encoding/json.js";
import { decryptionFailed, malformed, trustFailure } from "../errors.js";
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
  /** The account's root of trust for the team: an anchor this vault built or verified (§4.3, D-52). */
  readonly floor?: Anchor;
}

/** The bundle's key pairs, computed from the seed and secret key. */
export interface MemberKeyPairs {
  readonly signing: KeyPair;
  readonly encryption: KeyPair;
  readonly teamStateKey: Uint8Array;
}

const PART = 32;
/** `optional<u32 version, bytes recordHash>`: absent, or present with a 32-byte hash. */
const SIZES = [3 * PART + 1, 3 * PART + 1 + 4 + 4 + PART];

/** The anchor floor's encoding, in a bundle and in a transfer entry (§3.8, §4.3). */
export function encodeFloor(floor: Anchor | undefined): Field {
  return optional(floor, (f) => new Uint8Array([...u32(f.version), ...bytes(f.hash)]));
}

/** Throws `MALFORMED_RECORD` for a version below 1 or a hash that isn't 32 bytes. */
export function readFloor(reader: Reader): Anchor | undefined {
  const floor = reader.optional((r) => ({ version: r.u32(), hash: r.bytes() }));
  if (floor === null) return undefined;
  if (floor.version < 1 || floor.hash.length !== PART) throw malformed();
  return floor;
}

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
  const plaintext = concat(bundle.signingSeed, bundle.encryptionSecretKey, bundle.teamStateKey, encodeFloor(bundle.floor));
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
    wrappedKeys: readWrapped(fields, "wrappedKeys", header.suite, SIZES[1]! + header.suite.sizes.tag),
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
  let bundle: MemberKeyBundle;
  try {
    if (!SIZES.includes(plaintext.length)) throw decryptionFailed();
    const reader = new Reader(plaintext.subarray(3 * PART));
    const floor = readFloor(reader);
    reader.end();
    bundle = {
      signingSeed: plaintext.slice(0, PART),
      encryptionSecretKey: plaintext.slice(PART, 2 * PART),
      teamStateKey: plaintext.slice(2 * PART, 3 * PART),
      ...(floor ? { floor } : {}),
    };
  } catch {
    // An authenticated plaintext of the wrong shape is a broken record, never a partial bundle (§4.3).
    throw decryptionFailed();
  } finally {
    suite.wipe(plaintext);
  }
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
