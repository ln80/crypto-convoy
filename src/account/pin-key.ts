// Deriving the PIN key (§5.1): Argon2id, then the server's POPRF with its proof checked, combined with keyed BLAKE2b.
import { bytes, string } from "../encoding/canonical.js";
import { labelled } from "../encoding/labels.js";
import { ConvoyError, malformed } from "../errors.js";
import { utf8 } from "../internal/bytes.js";
import { callPort, type Argon2Cost, type OprfPurpose, type OprfService } from "../ports.js";
import type { Kdf } from "../records/account-key-wrap.js";
import type { Suite } from "../suites/suite.js";

/** Why a reader refuses a wrap's `kdf` before any work, or `null`: below `min`, or a key id with no pinned public key (D-53). */
export function refusedKdf(kdf: Kdf, min: Argon2Cost, oprfKeys: ReadonlyMap<number, Uint8Array>): "MALFORMED_RECORD" | "UNSUPPORTED_VERSION" | null {
  if (kdf.opslimit < min.opslimit || kdf.memlimit < min.memlimit) return "MALFORMED_RECORD";
  return oprfKeys.has(kdf.oprfKeyId) ? null : "UNSUPPORTED_VERSION";
}

/**
 * Throws `MALFORMED_RECORD` below `min` or for a malformed answer, `UNSUPPORTED_VERSION` for a key id
 * with no pinned public key, `TRUST_FAILURE` (`bad_signature`) for a proof that doesn't verify,
 * `PIN_RATE_LIMITED`, `STORE_ERROR`. Never retries (§5.1).
 */
export async function derivePinKey(
  suite: Suite,
  oprf: OprfService,
  input: { accountId: string; pin: string; kdf: Kdf; purpose: OprfPurpose; min: Argon2Cost; oprfKeys: ReadonlyMap<number, Uint8Array> },
): Promise<Uint8Array> {
  const { accountId, kdf, min } = input;
  // Before any work: only a key the client's code pins can answer (D-53).
  const refused = refusedKdf(kdf, min, input.oprfKeys);
  if (refused === "MALFORMED_RECORD") throw malformed();
  if (refused) throw new ConvoyError(refused);
  const publicKey = input.oprfKeys.get(kdf.oprfKeyId)!;
  const pin = utf8(input.pin.normalize("NFKC"));
  const a = suite.passwordHash(pin, kdf.salt, kdf.opslimit, kdf.memlimit);
  const info = labelled("pin-oprf", string(accountId));
  const { blind, blindedElement, tweakedKey } = suite.oprfBlind(a, info, publicKey);
  try {
    // One call, one rate-limited attempt: a failure is reported, never retried.
    const evaluated = await callPort(() =>
      oprf.evaluate({ accountId, blindedElement, oprfKeyId: kdf.oprfKeyId, purpose: input.purpose }),
    );
    if (!(evaluated?.evaluatedElement instanceof Uint8Array) || !(evaluated.proof instanceof Uint8Array)) throw malformed();
    const y = suite.oprfFinalize(a, info, blind, blindedElement, evaluated, tweakedKey);
    const pinKey = suite.keyedHash(a, labelled("pin-key", string(accountId), bytes(y)));
    suite.wipe(y);
    return pinKey;
  } finally {
    suite.wipe(pin, a, blind);
  }
}

/** A fresh `kdf` at the writer's cost and the settings' OPRF key id (§5.3, §5.6, D-53). */
export function newKdf(suite: Suite, cost: Argon2Cost, oprfKeyId: number): Kdf {
  return { salt: suite.randomBytes(suite.sizes.salt), opslimit: cost.opslimit, memlimit: cost.memlimit, oprfKeyId };
}
