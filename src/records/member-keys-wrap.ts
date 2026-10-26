// member-keys-wrap (§4.3): a member's private keys for one team, under the account key.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { Reader, bytes, string, u32, type Field } from "../encoding/canonical.js";
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
  /** The account's root of trust for the team: an anchor this vault built or verified; every bundle holds one (§4.3, D-52, D-66). */
  readonly floor: Anchor;
}

/** The bundle's key pairs, computed from the seed and secret key. */
export interface MemberKeyPairs {
  readonly signing: KeyPair;
  readonly encryption: KeyPair;
}

const PART = 32;
/** `signingSeed ‖ encryptionSecretKey ‖ enc(u32 version, bytes recordHash)`: 104 bytes (§4.3, D-66). */
const SIZE = 2 * PART + 4 + 4 + PART;

/** The anchor floor's encoding, in a bundle and in a transfer entry (§3.8, §4.3). */
export function encodeFloor(floor: Anchor): Field {
  return concat(u32(floor.version), bytes(floor.hash));
}

/** Throws `MALFORMED_RECORD` for a version below 1 or a hash that isn't 32 bytes. */
export function readFloor(reader: Reader): Anchor {
  const floor = { version: reader.u32(), hash: reader.bytes() };
  if (floor.version < 1 || floor.hash.length !== PART) throw malformed();
  return floor;
}

const adFields = (c: MemberKeysWrapContext): Field[] => [
  string(c.accountId),
  string(c.teamId),
  u32(c.memberKeysVersion),
  u32(c.accountKeyVersion),
];

/** New keys; the floor is added when the wrap is written, since team creation hashes them into it (§6.3). */
export function generateBundle(suite: Suite): Omit<MemberKeyBundle, "floor"> {
  return { signingSeed: suite.generateSigningSeed(), encryptionSecretKey: suite.generateEncryptionKeyPair().secretKey };
}

export function bundleKeyPairs(suite: Suite, bundle: Pick<MemberKeyBundle, "signingSeed" | "encryptionSecretKey">): MemberKeyPairs {
  return {
    signing: suite.signingKeyPair(bundle.signingSeed),
    encryption: { publicKey: suite.encryptionPublicKey(bundle.encryptionSecretKey), secretKey: bundle.encryptionSecretKey },
  };
}

export function createMemberKeysWrap(
  suite: Suite,
  context: MemberKeysWrapContext,
  accountKey: Uint8Array,
  bundle: MemberKeyBundle,
): MemberKeysWrap {
  const plaintext = concat(bundle.signingSeed, bundle.encryptionSecretKey, encodeFloor(bundle.floor));
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
    wrappedKeys: readWrapped(fields, "wrappedKeys", header.suite, SIZE + header.suite.sizes.tag),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/**
 * Opens the bundle and checks it against the published keys (§4.3).
 * Throws `DECRYPTION_FAILED`, or `TRUST_FAILURE` (`key_mismatch`).
 */
export function openMemberKeysWrap(record: MemberKeysWrap, accountKey: Uint8Array, published: MemberKeys): MemberKeyBundle {
  if (published.memberKeysVersion !== record.memberKeysVersion) throw trustFailure("key_mismatch");
  const bundle = unwrapMemberKeys(record, accountKey);
  checkBundle(record.suite, bundle, published);
  return bundle;
}

/** Opens the bundle under the account key alone (§4.3). Throws `DECRYPTION_FAILED`. */
export function unwrapMemberKeys(record: MemberKeysWrap, accountKey: Uint8Array): MemberKeyBundle {
  const { suite } = record;
  const plaintext = unwrap(suite, accountKey, "member-keys-wrap", adFields(record), record.wrappedKeys);
  let bundle: MemberKeyBundle;
  try {
    // The layout without a floor, or any other length, doesn't open (D-66).
    if (plaintext.length !== SIZE) throw decryptionFailed();
    const reader = new Reader(plaintext.subarray(2 * PART));
    const floor = readFloor(reader);
    reader.end();
    bundle = { signingSeed: plaintext.slice(0, PART), encryptionSecretKey: plaintext.slice(PART, 2 * PART), floor };
  } catch {
    // An authenticated plaintext of the wrong shape is a broken record, never a partial bundle (§4.3).
    throw decryptionFailed();
  } finally {
    suite.wipe(plaintext);
  }
  return bundle;
}

/** The bundle's public keys must be the published record's (§4.3). Throws `TRUST_FAILURE` (`key_mismatch`). */
export function checkBundle(suite: Suite, bundle: MemberKeyBundle, published: MemberKeys): void {
  const pairs = bundleKeyPairs(suite, bundle);
  const matches =
    suite.equal(pairs.signing.publicKey, published.signingPublicKey) &&
    suite.equal(pairs.encryption.publicKey, published.encryptionPublicKey);
  if (!matches) throw trustFailure("key_mismatch");
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
