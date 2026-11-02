// submission (§4.10): an envelope sealed to an inbox key, and its streamed parts.
import { open, seal } from "../blocks/seal.js";
import { streamDecrypt, streamDecryptChunks, streamEncrypt, streamEncryptChunks, type EncryptedStream } from "../blocks/stream.js";
import { Reader, bytes, enc, string, u32, u64, type Field } from "../encoding/canonical.js";
import { LIMITS, b64, type JsonRecord } from "../encoding/json.js";
import { decryptionFailed, malformed } from "../errors.js";
import type { KeyPair, Suite } from "../suites/suite.js";
import { expectContext, readRecord, writeHeader, type RecordHeader } from "./common.js";
import { checkPart, type Part } from "./item.js";
import { encodeManifest, readManifest, type ManifestEntry } from "./manifest.js";

export const SUBMISSION = "submission";

interface SubmissionContext {
  readonly teamId: string;
  readonly inboxId: string;
  readonly submissionId: string;
}

interface Submission extends RecordHeader, SubmissionContext {
  readonly sealedEnvelope: Uint8Array;
}

/** The opened envelope (§4.10). */
interface Envelope {
  readonly contentKey: Uint8Array;
  readonly createdAt: number;
  readonly manifest: ManifestEntry[];
}

const KEY = 32;
const ENVELOPE_MAX = 48 + 4 + 64 + 3 * (4 + LIMITS.idBytes) + 4 + KEY + 8 + 4 + LIMITS.parts * (4 + 8 + 4 + 32 + 4 + LIMITS.meta) + 4;

const envelopeContext = (c: SubmissionContext): Field[] => [string(c.teamId), string(c.inboxId), string(c.submissionId)];
// As for items, a part binds only its index; the envelope binds the ids and lists every part (D-26).
const partContext = (index: number): Field[] => [u32(index)];

export function encryptSubmissionPart(suite: Suite, contentKey: Uint8Array, index: number, content: Uint8Array): EncryptedStream {
  return streamEncrypt(suite, contentKey, "submission-part", partContext(index), content);
}

export function encryptSubmissionPartStream(
  suite: Suite,
  contentKey: Uint8Array,
  index: number,
  source: AsyncIterable<Uint8Array>,
  onComplete: (result: { size: number; hash: Uint8Array }) => void,
): AsyncGenerator<Uint8Array, void, undefined> {
  return streamEncryptChunks(suite, contentKey, "submission-part", partContext(index), source, onComplete);
}

/** Seals a draft (§7.5 step 4) to the public key the caller decoded from the link (SP-14). */
export function sealSubmission(
  suite: Suite,
  context: SubmissionContext,
  inboxPublicKey: Uint8Array,
  contentKey: Uint8Array,
  createdAt: number,
  manifest: readonly ManifestEntry[],
): Submission {
  if (suite.isLowOrder(inboxPublicKey)) throw malformed();
  const body = enc(bytes(contentKey), u64(createdAt), encodeManifest(manifest));
  try {
    return { v: 1, suite, ...context, sealedEnvelope: seal(suite, inboxPublicKey, "submission", envelopeContext(context), body) };
  } finally {
    suite.wipe(body);
  }
}

/** Everything at once, for small submissions and tests. */
export function createSubmission(
  suite: Suite,
  context: SubmissionContext,
  inboxPublicKey: Uint8Array,
  createdAt: number,
  parts: readonly Part[],
): { record: Submission; parts: Uint8Array[] } {
  const contentKey = suite.randomBytes(KEY);
  try {
    const encrypted = parts.map((part, index) => encryptSubmissionPart(suite, contentKey, index, part.content));
    const manifest = encrypted.map((part, index) => ({
      index,
      ciphertextSize: part.ciphertext.length,
      ciphertextHash: part.hash,
      meta: parts[index]!.meta ?? new Uint8Array(0),
    }));
    const record = sealSubmission(suite, context, inboxPublicKey, contentKey, createdAt, manifest);
    return { record, parts: encrypted.map((p) => p.ciphertext) };
  } finally {
    suite.wipe(contentKey);
  }
}

export function parseSubmission(json: unknown, expected: SubmissionContext): Submission {
  const { header, fields } = readRecord(json, SUBMISSION, ["teamId", "inboxId", "submissionId", "sealedEnvelope"]);
  const record: Submission = {
    ...header,
    teamId: fields.id("teamId"),
    inboxId: fields.id("inboxId"),
    submissionId: fields.id("submissionId"),
    sealedEnvelope: fields.bytesUpTo("sealedEnvelope", 48, ENVELOPE_MAX),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/** §7.6 step 2. Throws `DECRYPTION_FAILED` or `MALFORMED_RECORD`. */
export function openEnvelope(record: Submission, inboxKey: KeyPair): Envelope {
  const body = open(record.suite, inboxKey, "submission", envelopeContext(record), record.sealedEnvelope);
  try {
    const reader = new Reader(body);
    const contentKey = reader.bytes();
    const createdAt = reader.u64();
    const manifest = readManifest(reader);
    reader.end();
    if (contentKey.length !== KEY) throw decryptionFailed();
    return { contentKey, createdAt, manifest };
  } finally {
    record.suite.wipe(body);
  }
}

export function openSubmissionPart(record: Submission, envelope: Envelope, entry: ManifestEntry, ciphertext: Uint8Array): Uint8Array {
  checkPart(record.suite, entry, ciphertext);
  return streamDecrypt(record.suite, envelope.contentKey, "submission-part", partContext(entry.index), ciphertext);
}

export function openSubmissionPartStream(
  record: Submission,
  envelope: Envelope,
  entry: ManifestEntry,
  source: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array, void, undefined> {
  return streamDecryptChunks(record.suite, envelope.contentKey, "submission-part", partContext(entry.index), source, {
    size: entry.ciphertextSize,
    hash: entry.ciphertextHash,
  });
}

export function submissionToJson(record: Submission): JsonRecord {
  return {
    ...writeHeader(SUBMISSION, record.suite),
    teamId: record.teamId,
    inboxId: record.inboxId,
    submissionId: record.submissionId,
    sealedEnvelope: b64(record.sealedEnvelope),
  };
}
