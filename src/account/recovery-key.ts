// Deriving the recovery key and the recovery signing key (§5.2, D-33).
import { string } from "../encoding/canonical.js";
import { labelled } from "../encoding/labels.js";
import type { KeyPair, Suite } from "../suites/suite.js";

/** Throws `WRONG_CREDENTIAL` for a phrase that isn't valid BIP-39. */
export function deriveRecoveryKey(suite: Suite, accountId: string, phrase: string): Uint8Array {
  const seed = suite.recoverySeed(phrase);
  try {
    return suite.keyedHash(seed, labelled("recovery-key", string(accountId)));
  } finally {
    suite.wipe(seed);
  }
}

/** The recovery key and the recovery signing key, from one BIP-39 seed. The caller wipes both. Throws `WRONG_CREDENTIAL`. */
export function deriveRecoveryKeys(suite: Suite, accountId: string, phrase: string): { recoveryKey: Uint8Array; signing: KeyPair } {
  const seed = suite.recoverySeed(phrase);
  const signingSeed = suite.keyedHash(seed, labelled("recovery-signing-key", string(accountId)));
  try {
    return { recoveryKey: suite.keyedHash(seed, labelled("recovery-key", string(accountId))), signing: suite.signingKeyPair(signingSeed) };
  } finally {
    suite.wipe(seed, signingSeed);
  }
}
