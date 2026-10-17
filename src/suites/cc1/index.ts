// Suite cc1 (§2). The only place, with ./sodium.ts, that touches libsodium.
import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { ConvoyError, decryptionFailed, malformed } from "../../errors.js";
import type { Hasher, KeyPair, StreamPull, StreamPush, Suite } from "../suite.js";
import { ED25519_SMALL_ORDER, X25519_LOW_ORDER, inList, isCanonicalScalar } from "./small-order.js";
import { lib } from "./sodium.js";

const MiB = 1024 * 1024;

/** Hard bounds of §2: the floor protects against weak settings (D-17), the ceiling against memory exhaustion. */
export const ARGON2_BOUNDS = {
  minOpslimit: 2,
  maxOpslimit: 10,
  minMemlimit: 64 * MiB,
  maxMemlimit: 1024 * MiB,
} as const;

const SIZES = {
  key: 32,
  nonce: 24,
  tag: 16,
  publicKey: 32,
  secretKey: 32,
  signature: 64,
  hash: 32,
  salt: 16,
  streamHeader: 24,
  streamChunk: 4 * MiB,
  streamOverhead: 17,
} as const;

const OPRF_ELEMENT = 32;
const OPRF_OUTPUT = 64;
const RECOVERY_ENTROPY = 16;

// libsodium sizes never vary for these fields: a wrong size is a caller bug or hostile input.
function expectSize(value: Uint8Array, size: number, error: () => ConvoyError = malformed) {
  if (!(value instanceof Uint8Array) || value.length !== size) throw error();
}

function randomBytes(length: number): Uint8Array {
  return lib().randombytes_buf(length);
}

function streamPush(key: Uint8Array): StreamPush {
  expectSize(key, SIZES.key);
  const sodium = lib();
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  return {
    header,
    push(chunk, ad, final) {
      const tag = final
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
      return sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag);
    },
  };
}

function streamPull(key: Uint8Array, header: Uint8Array): StreamPull {
  expectSize(key, SIZES.key, decryptionFailed);
  expectSize(header, SIZES.streamHeader, decryptionFailed);
  const sodium = lib();
  let state: ReturnType<typeof sodium.crypto_secretstream_xchacha20poly1305_init_pull>;
  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  } catch {
    throw decryptionFailed();
  }
  return {
    pull(chunk, ad) {
      if (chunk.length < SIZES.streamOverhead) throw decryptionFailed();
      let result: { message: Uint8Array; tag: number } | false;
      try {
        result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk, ad, "uint8array");
      } catch {
        throw decryptionFailed();
      }
      // pull returns false on failure: once mistaken for an empty message.
      if (!result) throw decryptionFailed();
      if (result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        return { message: result.message, final: true };
      }
      if (result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
        return { message: result.message, final: false };
      }
      throw decryptionFailed();
    },
  };
}

export const cc1: Suite = {
  id: "cc1",
  sizes: SIZES,

  randomBytes,

  equal(a, b) {
    return a.length === b.length && lib().memcmp(a, b);
  },

  wipe(...values) {
    for (const value of values) lib().memzero(value);
  },

  aeadEncrypt(key, nonce, ad, plaintext) {
    expectSize(key, SIZES.key);
    expectSize(nonce, SIZES.nonce);
    return lib().crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key);
  },

  aeadDecrypt(key, nonce, ad, ciphertext) {
    expectSize(key, SIZES.key, decryptionFailed);
    expectSize(nonce, SIZES.nonce, decryptionFailed);
    if (ciphertext.length < SIZES.tag) throw decryptionFailed();
    try {
      return lib().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key);
    } catch {
      throw decryptionFailed();
    }
  },

  // Same as crypto_box_keypair, with the secret drawn by randombytes_buf (§3.6).
  generateEncryptionKeyPair(): KeyPair {
    const secretKey = randomBytes(SIZES.secretKey);
    return { publicKey: lib().crypto_scalarmult_base(secretKey), secretKey };
  },

  encryptionPublicKey(secretKey) {
    expectSize(secretKey, SIZES.secretKey);
    return lib().crypto_scalarmult_base(secretKey);
  },

  isLowOrder(publicKey) {
    return publicKey.length !== SIZES.publicKey || inList(X25519_LOW_ORDER, publicKey);
  },

  seal(publicKey, message) {
    expectSize(publicKey, SIZES.publicKey);
    if (inList(X25519_LOW_ORDER, publicKey)) throw malformed();
    return lib().crypto_box_seal(message, publicKey);
  },

  sealOpen(keyPair, sealed) {
    expectSize(keyPair.publicKey, SIZES.publicKey, decryptionFailed);
    expectSize(keyPair.secretKey, SIZES.secretKey, decryptionFailed);
    if (sealed.length < SIZES.publicKey + SIZES.tag) throw decryptionFailed();
    try {
      return lib().crypto_box_seal_open(sealed, keyPair.publicKey, keyPair.secretKey);
    } catch {
      throw decryptionFailed();
    }
  },

  generateSigningSeed() {
    return randomBytes(SIZES.key);
  },

  signingKeyPair(seed) {
    expectSize(seed, SIZES.key);
    const { publicKey, privateKey } = lib().crypto_sign_seed_keypair(seed);
    return { publicKey, secretKey: privateKey };
  },

  isValidSigningPublicKey(publicKey) {
    return publicKey.length === SIZES.publicKey && lib().crypto_core_ed25519_is_valid_point(publicKey);
  },

  sign(secretKey, message) {
    expectSize(secretKey, 64);
    return lib().crypto_sign_detached(message, secretKey);
  },

  // Strict rules of §2, written out instead of trusting one library's defaults.
  verify(publicKey, message, signature) {
    if (publicKey.length !== SIZES.publicKey || signature.length !== SIZES.signature) return false;
    if (!isCanonicalScalar(signature.subarray(32))) return false;
    if (!lib().crypto_core_ed25519_is_valid_point(publicKey)) return false;
    if (inList(ED25519_SMALL_ORDER, signature.subarray(0, 32))) return false;
    try {
      return lib().crypto_sign_verify_detached(signature, message, publicKey);
    } catch {
      return false;
    }
  },

  hash(message) {
    return lib().crypto_generichash(SIZES.hash, message, null);
  },

  keyedHash(key, message) {
    if (key.length < 16 || key.length > 64) throw malformed();
    return lib().crypto_generichash(SIZES.hash, message, key);
  },

  hasher(key?: Uint8Array): Hasher {
    if (key !== undefined && (key.length < 16 || key.length > 64)) throw malformed();
    const sodium = lib();
    const state = sodium.crypto_generichash_init(key ?? null, SIZES.hash);
    return {
      update: (data) => sodium.crypto_generichash_update(state, data),
      digest: () => sodium.crypto_generichash_final(state, SIZES.hash),
    };
  },

  streamPush,
  streamPull,

  passwordHash(password, salt, opslimit, memlimit) {
    expectSize(salt, SIZES.salt);
    const { minOpslimit, maxOpslimit, minMemlimit, maxMemlimit } = ARGON2_BOUNDS;
    if (!Number.isInteger(opslimit) || opslimit < minOpslimit || opslimit > maxOpslimit) throw malformed();
    if (!Number.isInteger(memlimit) || memlimit < minMemlimit || memlimit > maxMemlimit) throw malformed();
    const sodium = lib();
    return sodium.crypto_pwhash(SIZES.key, password, salt, opslimit, memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
  },

  // RFC 9497 base mode; the blinding scalar's randomness comes from libsodium (§3.6).
  oprfBlind(input) {
    const rng = (length?: number) => randomBytes(length ?? 32) as Uint8Array<ArrayBuffer>;
    const { blind, blinded } = ristretto255_oprf.oprf.blind(input, rng);
    return { blind, blindedElement: blinded };
  },

  oprfFinalize(input, blind, evaluatedElement) {
    expectSize(evaluatedElement, OPRF_ELEMENT);
    if (evaluatedElement.every((byte) => byte === 0)) throw malformed();
    let output: Uint8Array;
    try {
      output = ristretto255_oprf.oprf.finalize(input, blind, evaluatedElement);
    } catch {
      throw malformed();
    }
    expectSize(output, OPRF_OUTPUT);
    return output;
  },

  generateRecoveryPhrase() {
    const entropy = randomBytes(RECOVERY_ENTROPY);
    try {
      return entropyToMnemonic(entropy, wordlist);
    } finally {
      lib().memzero(entropy);
    }
  },

  recoverySeed(phrase) {
    const normalized = phrase.normalize("NFKD").trim().split(/\s+/).join(" ");
    if (normalized.split(" ").length !== 12 || !validateMnemonic(normalized, wordlist)) {
      throw new ConvoyError("WRONG_CREDENTIAL");
    }
    return mnemonicToSeedSync(normalized, "");
  },
};
