// seal / open (§3.2). crypto_box_seal has no associated data, so the context travels inside.
import { bytes, Reader, type Field } from "../encoding/canonical.js";
import { labelled, type Label } from "../encoding/labels.js";
import { decryptionFailed } from "../errors.js";
import { sameBytes } from "../internal/bytes.js";
import type { KeyPair, Suite } from "../suites/suite.js";

/** Throws `MALFORMED_RECORD` for a low-order public key (§2). */
export function seal(
  suite: Suite,
  publicKey: Uint8Array,
  name: Label,
  context: readonly Field[],
  body: Uint8Array,
): Uint8Array {
  return suite.seal(publicKey, labelled(name, ...context, bytes(body)));
}

/** Throws `DECRYPTION_FAILED`, also when the label or context differs or bytes follow `body`. */
export function open(
  suite: Suite,
  keyPair: KeyPair,
  name: Label,
  context: readonly Field[],
  sealed: Uint8Array,
): Uint8Array {
  const message = suite.sealOpen(keyPair, sealed);
  try {
    const prefix = labelled(name, ...context);
    if (!sameBytes(message.subarray(0, prefix.length), prefix)) throw decryptionFailed();
    const reader = new Reader(message.subarray(prefix.length));
    const body = reader.bytes();
    reader.end();
    return body;
  } catch {
    throw decryptionFailed();
  } finally {
    suite.wipe(message);
  }
}
