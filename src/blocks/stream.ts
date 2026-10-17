// stream (§3.4): content of any size, in authenticated chunks bound to its context.
import type { Field } from "../encoding/canonical.js";
import { labelled, type Label } from "../encoding/labels.js";
import { decryptionFailed } from "../errors.js";
import { concat } from "../internal/bytes.js";
import type { Suite } from "../suites/suite.js";

export interface EncryptedStream {
  /** `header ‖ chunk₀ ‖ chunk₁ ‖ …` */
  readonly ciphertext: Uint8Array;
  /** BLAKE2b-256 of the whole ciphertext, header included. */
  readonly hash: Uint8Array;
}

/** What the manifest says a stream must be (§4.7, §4.10). */
export interface ExpectedStream {
  readonly size: number;
  readonly hash: Uint8Array;
}

export function streamEncrypt(
  suite: Suite,
  key: Uint8Array,
  name: Label,
  context: readonly Field[],
  plaintext: Uint8Array,
): EncryptedStream {
  const ad = labelled(name, ...context);
  const { streamChunk } = suite.sizes;
  const push = suite.streamPush(key);
  const parts = [push.header];
  const count = Math.max(1, Math.ceil(plaintext.length / streamChunk));
  for (let i = 0; i < count; i++) {
    const chunk = plaintext.subarray(i * streamChunk, (i + 1) * streamChunk);
    parts.push(push.push(chunk, ad, i === count - 1));
  }
  const ciphertext = concat(...parts);
  return { ciphertext, hash: suite.hash(ciphertext) };
}

/**
 * Streaming encryption (§3.4, D-27): yields the header, then each encrypted chunk, holding one
 * plaintext chunk back so the last one gets `FINAL`. Memory stays at about one chunk.
 * `onComplete` receives the ciphertext size and hash once the last chunk is out.
 */
export async function* streamEncryptChunks(
  suite: Suite,
  key: Uint8Array,
  name: Label,
  context: readonly Field[],
  source: AsyncIterable<Uint8Array>,
  onComplete: (result: { size: number; hash: Uint8Array }) => void,
): AsyncGenerator<Uint8Array, void, undefined> {
  const ad = labelled(name, ...context);
  const { streamChunk } = suite.sizes;
  const push = suite.streamPush(key);
  const hasher = suite.hasher();
  let size = 0;
  const emit = (bytes: Uint8Array) => {
    hasher.update(bytes);
    size += bytes.length;
    return bytes;
  };
  yield emit(push.header);
  const queue = new ByteQueue();
  for await (const data of source) {
    queue.push(data);
    // Only a chunk followed by more data is known not to be the last.
    while (queue.length > streamChunk) yield emit(push.push(queue.take(streamChunk), ad, false));
  }
  yield emit(push.push(queue.take(queue.length), ad, true));
  onComplete({ size, hash: hasher.digest() });
}

/** Pulls chunks in order and enforces the chunk rules of §3.4. */
class ChunkReader {
  readonly #ad: Uint8Array;
  readonly #suite: Suite;
  readonly #key: Uint8Array;
  #pull: ReturnType<Suite["streamPull"]> | undefined;
  #done = false;

  constructor(suite: Suite, key: Uint8Array, name: Label, context: readonly Field[]) {
    this.#suite = suite;
    this.#key = key;
    this.#ad = labelled(name, ...context);
  }

  get headerSize() {
    return this.#suite.sizes.streamHeader;
  }

  get pieceSize() {
    return this.#suite.sizes.streamChunk + this.#suite.sizes.streamOverhead;
  }

  header(header: Uint8Array) {
    this.#pull = this.#suite.streamPull(this.#key, header);
  }

  /** `last`: no bytes follow this piece. */
  piece(piece: Uint8Array, last: boolean): Uint8Array {
    if (!this.#pull || this.#done) throw decryptionFailed();
    const { message, final } = this.#pull.pull(piece, this.#ad);
    if (final !== last) throw decryptionFailed(); // early FINAL, or the data ends without one
    if (!final && message.length !== this.#suite.sizes.streamChunk) throw decryptionFailed();
    this.#done = final;
    return message;
  }
}

/** Buffered read: the full plaintext, or `DECRYPTION_FAILED` and nothing (SP-18). */
export function streamDecrypt(
  suite: Suite,
  key: Uint8Array,
  name: Label,
  context: readonly Field[],
  ciphertext: Uint8Array,
): Uint8Array {
  const reader = new ChunkReader(suite, key, name, context);
  const { headerSize, pieceSize } = reader;
  if (ciphertext.length <= headerSize) throw decryptionFailed();
  const messages: Uint8Array[] = [];
  try {
    reader.header(ciphertext.subarray(0, headerSize));
    for (let offset = headerSize; offset < ciphertext.length; offset += pieceSize) {
      const end = Math.min(offset + pieceSize, ciphertext.length);
      messages.push(reader.piece(ciphertext.subarray(offset, end), end === ciphertext.length));
    }
    return concat(...messages);
  } finally {
    suite.wipe(...messages);
  }
}

/**
 * Opt-in streaming read (§3.4): yields only authenticated chunks, and throws
 * `DECRYPTION_FAILED` at the end if the stream is incomplete or doesn't match
 * `expected`. Consumers must then discard what they received.
 */
export async function* streamDecryptChunks(
  suite: Suite,
  key: Uint8Array,
  name: Label,
  context: readonly Field[],
  source: AsyncIterable<Uint8Array>,
  expected: ExpectedStream,
): AsyncGenerator<Uint8Array, void, undefined> {
  const reader = new ChunkReader(suite, key, name, context);
  const { headerSize, pieceSize } = reader;
  const hasher = suite.hasher();
  const queue = new ByteQueue();
  let size = 0;
  let headerRead = false;

  for await (const data of source) {
    size += data.length;
    if (size > expected.size) throw decryptionFailed();
    hasher.update(data);
    queue.push(data);
    if (!headerRead && queue.length >= headerSize) {
      reader.header(queue.take(headerSize));
      headerRead = true;
    }
    // Hold a full piece back until more bytes arrive: only then is it known not to be the last.
    while (headerRead && queue.length > pieceSize) yield reader.piece(queue.take(pieceSize), false);
  }

  if (!headerRead || queue.length === 0 || size !== expected.size) throw decryptionFailed();
  if (!suite.equal(hasher.digest(), expected.hash)) throw decryptionFailed();
  yield reader.piece(queue.take(queue.length), true);
}

class ByteQueue {
  #chunks: Uint8Array[] = [];
  length = 0;

  push(data: Uint8Array) {
    if (data.length === 0) return;
    this.#chunks.push(data);
    this.length += data.length;
  }

  take(count: number): Uint8Array {
    const out = new Uint8Array(count);
    let filled = 0;
    while (filled < count) {
      const head = this.#chunks[0]!;
      const used = Math.min(head.length, count - filled);
      out.set(head.subarray(0, used), filled);
      filled += used;
      if (used === head.length) this.#chunks.shift();
      else this.#chunks[0] = head.subarray(used);
    }
    this.length -= count;
    return out;
  }
}
