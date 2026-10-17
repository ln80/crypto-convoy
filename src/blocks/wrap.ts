// wrap / unwrap (§3.1): a short secret under a symmetric key, bound to its context.
import type { Field } from "../encoding/canonical.js";
import { labelled, type Label } from "../encoding/labels.js";
import type { Suite } from "../suites/suite.js";

export interface Wrapped {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export function wrap(
  suite: Suite,
  key: Uint8Array,
  name: Label,
  context: readonly Field[],
  plaintext: Uint8Array,
): Wrapped {
  const nonce = suite.randomBytes(suite.sizes.nonce);
  return { nonce, ciphertext: suite.aeadEncrypt(key, nonce, labelled(name, ...context), plaintext) };
}

/** Throws `DECRYPTION_FAILED`. Context ids come from what the caller expects (§3.1). */
export function unwrap(
  suite: Suite,
  key: Uint8Array,
  name: Label,
  context: readonly Field[],
  wrapped: Wrapped,
): Uint8Array {
  return suite.aeadDecrypt(key, wrapped.nonce, labelled(name, ...context), wrapped.ciphertext);
}

/** BLAKE2b-256(nonce ‖ ciphertext): how signatures and other wraps bind a wrap (§4.5, §4.7). */
export function wrappedHash(suite: Suite, wrapped: Wrapped): Uint8Array {
  const hasher = suite.hasher();
  hasher.update(wrapped.nonce);
  hasher.update(wrapped.ciphertext);
  return hasher.digest();
}
