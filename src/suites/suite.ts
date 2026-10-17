/** A fixed set of primitives, named by the `suite` field of every record (§2, §10). */
export interface Suite {
  readonly id: string;
  readonly sizes: {
    readonly key: number;
    readonly nonce: number;
    readonly tag: number;
    readonly publicKey: number;
    readonly secretKey: number;
    readonly signature: number;
    readonly hash: number;
    readonly salt: number;
    readonly streamHeader: number;
    readonly streamChunk: number;
    readonly streamOverhead: number;
  };

  randomBytes(length: number): Uint8Array;
  /** Constant-time equality of equal-length secrets, MACs or hashes. */
  equal(a: Uint8Array, b: Uint8Array): boolean;
  /** Best-effort zeroing: JavaScript can't guarantee erasure. */
  wipe(...values: Uint8Array[]): void;

  aeadEncrypt(key: Uint8Array, nonce: Uint8Array, ad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  /** Throws `DECRYPTION_FAILED`. */
  aeadDecrypt(key: Uint8Array, nonce: Uint8Array, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array;

  generateEncryptionKeyPair(): KeyPair;
  encryptionPublicKey(secretKey: Uint8Array): Uint8Array;
  isLowOrder(publicKey: Uint8Array): boolean;
  /** Throws `MALFORMED_RECORD` for a low-order key. */
  seal(publicKey: Uint8Array, message: Uint8Array): Uint8Array;
  /** Throws `DECRYPTION_FAILED`. */
  sealOpen(keyPair: KeyPair, sealed: Uint8Array): Uint8Array;

  generateSigningSeed(): Uint8Array;
  signingKeyPair(seed: Uint8Array): KeyPair;
  isValidSigningPublicKey(publicKey: Uint8Array): boolean;
  sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array;
  /** Strict verification (§2); never throws. */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

  hash(message: Uint8Array): Uint8Array;
  keyedHash(key: Uint8Array, message: Uint8Array): Uint8Array;
  /** Incremental BLAKE2b-256, keyed when `key` is given (16–64 bytes). */
  hasher(key?: Uint8Array): Hasher;

  streamPush(key: Uint8Array): StreamPush;
  /** Throws `DECRYPTION_FAILED` for a malformed header. */
  streamPull(key: Uint8Array, header: Uint8Array): StreamPull;

  /** Argon2id within the library's hard bounds (§2). Throws `MALFORMED_RECORD` outside them. */
  passwordHash(password: Uint8Array, salt: Uint8Array, opslimit: number, memlimit: number): Uint8Array;
  oprfBlind(input: Uint8Array): { blind: Uint8Array; blindedElement: Uint8Array };
  /** Throws `MALFORMED_RECORD` for an invalid evaluated element. */
  oprfFinalize(input: Uint8Array, blind: Uint8Array, evaluatedElement: Uint8Array): Uint8Array;

  generateRecoveryPhrase(): string;
  /** Throws `WRONG_CREDENTIAL` for a phrase that isn't valid BIP-39. */
  recoverySeed(phrase: string): Uint8Array;
}

export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface Hasher {
  update(data: Uint8Array): void;
  digest(): Uint8Array;
}

export interface StreamPush {
  readonly header: Uint8Array;
  push(chunk: Uint8Array, ad: Uint8Array, final: boolean): Uint8Array;
}

export interface StreamPull {
  /** Throws `DECRYPTION_FAILED` on a failed chunk or an unknown tag. */
  pull(chunk: Uint8Array, ad: Uint8Array): { message: Uint8Array; final: boolean };
}
