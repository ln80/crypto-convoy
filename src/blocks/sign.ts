// sign / verify (§3.3) over enc(string label(name), fields…).
import type { Field } from "../encoding/canonical.js";
import { labelled, type Label } from "../encoding/labels.js";
import { trustFailure } from "../errors.js";
import type { Suite } from "../suites/suite.js";

export function sign(suite: Suite, secretKey: Uint8Array, name: Label, fields: readonly Field[]): Uint8Array {
  return suite.sign(secretKey, labelled(name, ...fields));
}

/** Throws `TRUST_FAILURE` (`bad_signature`). */
export function verify(
  suite: Suite,
  publicKey: Uint8Array,
  name: Label,
  fields: readonly Field[],
  signature: Uint8Array,
): void {
  verifyPayload(suite, publicKey, labelled(name, ...fields), signature);
}

/** For records whose payload is also hashed (§4.5). Throws `TRUST_FAILURE` (`bad_signature`). */
export function verifyPayload(suite: Suite, publicKey: Uint8Array, payload: Uint8Array, signature: Uint8Array): void {
  if (!suite.verify(publicKey, payload, signature)) throw trustFailure("bad_signature");
}
