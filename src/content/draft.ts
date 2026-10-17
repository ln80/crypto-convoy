// Drafts (§7.1, §7.5, D-27): parts encrypted one at a time, the key record sealed last.
import { partRef, partRefKey, partRefStream } from "../blocks/part-ref.js";
import type { EncryptedStream } from "../blocks/stream.js";
import { LIMITS } from "../encoding/json.js";
import { malformed } from "../errors.js";
import type { ManifestEntry } from "../records/manifest.js";
import type { Suite } from "../suites/suite.js";
import type { PartOptions } from "./context.js";

type EncryptPart = (key: Uint8Array, index: number, content: Uint8Array) => EncryptedStream;
type EncryptPartStream = (
  key: Uint8Array,
  index: number,
  source: AsyncIterable<Uint8Array>,
  onComplete: (r: { size: number; hash: Uint8Array }) => void,
) => AsyncGenerator<Uint8Array, void, undefined>;

/**
 * Holds the content key; never hands it out. Misuse (a part while another is still
 * streaming, anything after `seal` or `discard`) throws a plain `Error`.
 */
export class Draft<SealArgs extends unknown[], Result> {
  readonly #suite: Suite;
  readonly #key: Uint8Array;
  readonly #encrypt: EncryptPart;
  readonly #encryptStream: EncryptPartStream;
  readonly #seal: (key: Uint8Array, manifest: readonly ManifestEntry[], ...args: SealArgs) => Promise<Result>;
  readonly #manifest: ManifestEntry[] = [];
  #refKey: Uint8Array | undefined;
  #streaming = false;
  #closed = false;

  /** @internal */
  constructor(
    suite: Suite,
    encrypt: EncryptPart,
    encryptStream: EncryptPartStream,
    seal: (key: Uint8Array, manifest: readonly ManifestEntry[], ...args: SealArgs) => Promise<Result>,
  ) {
    this.#suite = suite;
    this.#key = suite.randomBytes(suite.sizes.key);
    this.#encrypt = encrypt;
    this.#encryptStream = encryptStream;
    this.#seal = seal;
  }

  /** Number of parts added so far. */
  get partCount(): number {
    return this.#manifest.length;
  }

  /** Encrypts the next part, buffered; returns its ciphertext to store. */
  addPart(content: Uint8Array, options: PartOptions = {}): Uint8Array {
    const index = this.#next(options);
    const { ciphertext, hash } = this.#encrypt(this.#key, index, content);
    this.#manifest.push(entry(index, ciphertext.length, hash, options));
    return ciphertext;
  }

  /** Encrypts the next part as a stream: yields ciphertext chunks to upload; memory stays at one chunk. */
  addPartStream(content: AsyncIterable<Uint8Array>, options: PartOptions = {}): AsyncIterable<Uint8Array> {
    const index = this.#next(options);
    this.#streaming = true;
    return this.#encryptStream(this.#key, index, content, ({ size, hash }) => {
      this.#manifest.push(entry(index, size, hash, options));
      this.#streaming = false;
    });
  }

  /** A keyed reference for a part's plaintext, safe to send to a server (§3.9, SP-21). */
  partRef(content: Uint8Array): string {
    return partRef(this.#suite, this.#refKeyOrDerive(), content);
  }

  partRefStream(content: AsyncIterable<Uint8Array>): Promise<string> {
    return partRefStream(this.#suite, this.#refKeyOrDerive(), content);
  }

  /** Seals the draft with its id (§7.1 step 4, §7.5 step 4). Throws `MALFORMED_RECORD` without parts. */
  async seal(...args: SealArgs): Promise<Result> {
    this.#open();
    if (this.#streaming) throw new Error("crypto-convoy: a streamed part is not finished");
    if (this.#manifest.length < 1) throw malformed();
    const result = await this.#seal(this.#key, this.#manifest, ...args);
    this.discard();
    return result;
  }

  /** Forgets the draft's keys; parts already stored open with no key (D-27). */
  discard(): void {
    this.#closed = true;
    this.#suite.wipe(this.#key);
    if (this.#refKey) this.#suite.wipe(this.#refKey);
  }

  #next(options: PartOptions): number {
    this.#open();
    if (this.#streaming) throw new Error("crypto-convoy: a streamed part is not finished");
    if (this.#manifest.length >= LIMITS.parts) throw malformed();
    if ((options.meta?.length ?? 0) > LIMITS.meta) throw malformed();
    return this.#manifest.length;
  }

  #open() {
    if (this.#closed) throw new Error("crypto-convoy: the draft is sealed or discarded");
  }

  #refKeyOrDerive(): Uint8Array {
    this.#open();
    return (this.#refKey ??= partRefKey(this.#suite, this.#key));
  }
}

const entry = (index: number, size: number, hash: Uint8Array, options: PartOptions): ManifestEntry => ({
  index,
  ciphertextSize: size,
  ciphertextHash: hash,
  meta: options.meta?.slice() ?? new Uint8Array(0),
});
