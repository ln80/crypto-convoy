// Deriving the recovery key (§5.2).
import { string } from "../encoding/canonical.js";
import { labelled } from "../encoding/labels.js";
import type { Suite } from "../suites/suite.js";

/** Throws `WRONG_CREDENTIAL` for a phrase that isn't valid BIP-39. */
export function deriveRecoveryKey(suite: Suite, accountId: string, phrase: string): Uint8Array {
  const seed = suite.recoverySeed(phrase);
  try {
    return suite.keyedHash(seed, labelled("recovery-key", string(accountId)));
  } finally {
    suite.wipe(seed);
  }
}
