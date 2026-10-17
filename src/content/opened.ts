// Opened items and submissions (§7.2, §7.3, §7.6): the manifest, then parts on demand.
import { decryptionFailed, malformed } from "../errors.js";
import { concat } from "../internal/bytes.js";
import type { ManifestEntry } from "../records/manifest.js";
import type { Suite } from "../suites/suite.js";
import type { PartInfo, PartSource } from "./context.js";

type OpenPart = (entry: ManifestEntry, ciphertext: Uint8Array) => Uint8Array;
type OpenPartStream = (entry: ManifestEntry, source: AsyncIterable<Uint8Array>) => AsyncGenerator<Uint8Array, void, undefined>;

/** Holds the content key; `close()` forgets it. */
export class Opened {
  /** Each part's index, `meta` and ciphertext size. */
  readonly parts: readonly PartInfo[];
  readonly #suite: Suite;
  readonly #manifest: readonly ManifestEntry[];
  readonly #maxBufferedSize: number;
  readonly #open: OpenPart;
  readonly #openStream: OpenPartStream;
  readonly #wipe: () => void;
  #closed = false;

  /** @internal */
  constructor(
    suite: Suite,
    manifest: readonly ManifestEntry[],
    maxBufferedSize: number,
    open: OpenPart,
    openStream: OpenPartStream,
    wipe: () => void,
  ) {
    this.#suite = suite;
    this.#manifest = manifest;
    this.#maxBufferedSize = maxBufferedSize;
    this.#open = open;
    this.#openStream = openStream;
    this.#wipe = wipe;
    this.parts = manifest.map((e) => ({ index: e.index, meta: e.meta.slice(), size: e.ciphertextSize }));
  }

  /**
   * One part, buffered: the full plaintext or an error (SP-18). A part above `maxBufferedSize`
   * is refused with `MALFORMED_RECORD` before a fetcher is called (§3.4). Throws `DECRYPTION_FAILED`.
   */
  async part(index: number, source: PartSource): Promise<Uint8Array> {
    const entry = this.#entry(index);
    if (entry.ciphertextSize > this.#maxBufferedSize) throw malformed();
    const resolved = typeof source === "function" ? await source() : source;
    if (resolved instanceof Uint8Array) return this.#open(entry, resolved);
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const chunk of resolved) {
      size += chunk.length;
      if (size > entry.ciphertextSize) throw decryptionFailed();
      chunks.push(chunk);
    }
    return this.#open(entry, concat(...chunks));
  }

  /** One part, streamed: authenticated chunks; ends with `DECRYPTION_FAILED` if incomplete. */
  async *partStream(index: number, source: PartSource): AsyncGenerator<Uint8Array, void, undefined> {
    const entry = this.#entry(index);
    const resolved = typeof source === "function" ? await source() : source;
    const iterable =
      resolved instanceof Uint8Array
        ? (async function* () {
            yield resolved;
          })()
        : resolved;
    yield* this.#openStream(entry, iterable);
  }

  /** Forgets the content key. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#wipe();
  }

  #entry(index: number): ManifestEntry {
    if (this.#closed) throw new Error("crypto-convoy: closed");
    const entry = this.#manifest[index];
    if (!entry) throw malformed();
    return entry;
  }
}

/** An opened submission: its parts, and the sender's informative time (TH-35). */
export class OpenedSubmission extends Opened {
  readonly createdAt: number;

  /** @internal */
  constructor(createdAt: number, ...args: ConstructorParameters<typeof Opened>) {
    super(...args);
    this.createdAt = createdAt;
  }
}

export { Opened as OpenedItem };
export const wipeWith = (suite: Suite, key: Uint8Array) => () => suite.wipe(key);
