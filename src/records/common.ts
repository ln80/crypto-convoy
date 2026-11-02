import type { Wrapped } from "../blocks/wrap.js";
import { Fields, b64, readEnvelope, type JsonRecord } from "../encoding/json.js";
import { malformed, trustFailure } from "../errors.js";
import { suiteFor } from "../suites/registry.js";
import type { Suite } from "../suites/suite.js";

/** Record format versions this library reads; writers use the last (§10). */
const VERSIONS = [1] as const;
const WRITE_VERSION = 1;

export interface RecordHeader {
  readonly v: number;
  readonly suite: Suite;
}

/** §8 steps 1–2, then the body's shape for that version. */
export function readRecord(
  json: unknown,
  type: string,
  required: readonly string[],
  optional: readonly string[] = [],
): { header: RecordHeader; fields: Fields } {
  const { v, suite } = readEnvelope(json, type, VERSIONS);
  const header = { v, suite: suiteFor(suite) };
  // Only v1 exists: a later layout adds its own field list here, never edits this one (§10).
  const fields = Fields.of(json, ["v", "suite", "type", ...required], optional);
  return { header, fields };
}

export function writeHeader(type: string, suite: Suite): JsonRecord {
  return { v: WRITE_VERSION, suite: suite.id, type };
}

/** §8 step 3: ids and versions must be the ones the caller asked for. */
export function expectContext(expected: Record<string, unknown>, actual: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(expected)) {
    if (value !== undefined && actual[key] !== value) throw trustFailure("context_mismatch");
  }
}

export function readWrapped(fields: Fields, key: string, suite: Suite, maxCiphertext: number): Wrapped {
  const inner = fields.object(key, ["nonce", "ciphertext"]);
  return {
    nonce: inner.bytes("nonce", suite.sizes.nonce),
    ciphertext: inner.bytesUpTo("ciphertext", suite.sizes.tag, maxCiphertext),
  };
}

export function writeWrapped(wrapped: Wrapped): JsonRecord {
  return { nonce: b64(wrapped.nonce), ciphertext: b64(wrapped.ciphertext) };
}

/** An account and its signing key, as listed in owner lists and signers (§4.5, §4.6). */
export interface SignerRef {
  readonly accountId: string;
  readonly signingPublicKey: Uint8Array;
}

export function readSigner(value: unknown, suite: Suite): SignerRef {
  const fields = Fields.of(value, ["accountId", "signingPublicKey"]);
  return { accountId: fields.id("accountId"), signingPublicKey: readSigningKey(fields, "signingPublicKey", suite) };
}

export function writeSigner(signer: SignerRef): JsonRecord {
  return { accountId: signer.accountId, signingPublicKey: b64(signer.signingPublicKey) };
}

/** Every signing public key a record carries passes the §2 key check. */
export function readSigningKey(fields: Fields, key: string, suite: Suite): Uint8Array {
  const value = fields.bytes(key, suite.sizes.publicKey);
  if (!suite.isValidSigningPublicKey(value)) throw malformed();
  return value;
}

/** Encryption public keys are never low order (§2). */
export function readEncryptionKey(fields: Fields, key: string, suite: Suite): Uint8Array {
  const value = fields.bytes(key, suite.sizes.publicKey);
  if (suite.isLowOrder(value)) throw malformed();
  return value;
}
