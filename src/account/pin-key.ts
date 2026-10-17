// Deriving the PIN key (§5.1): Argon2id, then the server OPRF, combined with keyed BLAKE2b.
import { bytes, string } from "../encoding/canonical.js";
import { labelled } from "../encoding/labels.js";
import { malformed } from "../errors.js";
import { utf8 } from "../internal/bytes.js";
import { callPort, type Argon2Cost, type OprfPurpose, type OprfService } from "../ports.js";
import type { Kdf } from "../records/account-key-wrap.js";
import type { Suite } from "../suites/suite.js";

/** Throws `MALFORMED_RECORD` below `min`, `PIN_RATE_LIMITED`, `STORE_ERROR`. Never retries (§5.1). */
export async function derivePinKey(
  suite: Suite,
  oprf: OprfService,
  input: { accountId: string; pin: string; kdf: Kdf; purpose: OprfPurpose; min: Argon2Cost },
): Promise<Uint8Array> {
  const { accountId, kdf, min } = input;
  if (kdf.opslimit < min.opslimit || kdf.memlimit < min.memlimit) throw malformed();
  const pin = utf8(input.pin.normalize("NFKC"));
  const a = suite.passwordHash(pin, kdf.salt, kdf.opslimit, kdf.memlimit);
  const { blind, blindedElement } = suite.oprfBlind(a);
  try {
    // One call, one rate-limited attempt: a failure is reported, never retried.
    const evaluated = await callPort(() =>
      oprf.evaluate({ accountId, blindedElement, oprfKeyId: kdf.oprfKeyId, purpose: input.purpose }),
    );
    const y = suite.oprfFinalize(a, blind, evaluated);
    const pinKey = suite.keyedHash(a, labelled("pin-key", string(accountId), bytes(y)));
    suite.wipe(y);
    return pinKey;
  } finally {
    suite.wipe(pin, a, blind);
  }
}

/** A fresh `kdf` at the writer's cost and the server's current OPRF key (§5.3, §5.6). */
export function newKdf(suite: Suite, cost: Argon2Cost, oprfKeyId: number): Kdf {
  return { salt: suite.randomBytes(suite.sizes.salt), opslimit: cost.opslimit, memlimit: cost.memlimit, oprfKeyId };
}
