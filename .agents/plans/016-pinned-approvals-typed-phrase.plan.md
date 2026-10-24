# Plan 016: approvals pin the keys reviewed; the typed phrase is the only recovery key the vault signs for (review 013 A, B)

## Context

Review 013 (`.agents/reviews/013-adversarial.md`), both reproduced:

- **A (high).** An approval names only `{ accountId, memberKeysVersion }`. `reconcile` checks the proof (or the caller's own custody, D-47) on the record of the team-wide list; the rotation fetches the account's list again and seals to whatever comes back. The server alone swaps the approved keys: it gets the next team key, or an owner seat when the re-key is an owner's own.
- **B (high).** `wrappedRecoveryPublicKey` is a `wrap` under the account key, independent of `wrappedAccountKey` (§4.1). Whoever holds the account key and the session replaces it alone: the user's phrase still opens the account, `secureAccount` refuses it (it compares the phrase with the stored key), and `rekey-needed` leads the user to `rekey(teamId, { phrase })`, which signs, with the real phrase, keys carrying the attacker's recovery key (D-49's "a phrase a bundle carries"). The attacker then proves its own re-keys.

## Design

Reviewed in design mode by review 014 (`.agents/reviews/014-design-plan-016.md`, fresh-context reviewer); its A–E are folded in below.

### D-55: an approval names the keys hash

1. `KeysHandle` becomes `{ accountId, memberKeysVersion, keysHash }`, `keysHash` in base64url: §4.2's keys hash of the record whose proof or custody the overview checked.
2. A rotation that approves a handle seals to the account's newest published record only if it has the handle's keys hash. A newer version is `STALE_VERSION` (keys published since the review); the handle's version with another hash is `TRUST_FAILURE` (`key_mismatch`): the server served two records for one version. Both before anything is written.
3. Two records for one (account, `memberKeysVersion`) in any `member-keys` list the owner reads are `TRUST_FAILURE` (`key_mismatch`) (review 014 A).

Consequence: `reconcile`'s proof check, its custody check (D-47) and the rotation see one record; held keys stay pinned by the roster (review 009 A).

Rejected: re-checking the proof at rotation time (a second rule, which covers neither manual approvals nor D-47); an opaque handle string (handles are plain data the integration stores and shows, D-31).

### D-56: the phrase the user types is the only recovery key the vault uses

1. **One rule.** Given the current phrase, the vault checks it by opening the current recovery wrap's `wrappedAccountKey` (`verifyPhrase`, as rotation and `changePin` already do) and uses the recovery key derived from it for every key it writes or signs, never the stored `wrappedRecoveryPublicKey`. The keys a proof signs carry the key of a phrase typed in that operation: the current phrase, or the new phrase being set.
2. **A spliced wrap is reported, not refused.** A stored key that differs from the typed phrase's is reported by the vault (`recovery-key-mismatch`, action `secureAccount`); the operation goes on with the derived key. `recover` stops refusing it (review 014 B). `rotate`, `secureAccount` and `confirmRecoveryPhrase` write a new recovery wrap from the typed phrase, which repairs it.
3. **Retry after a replacement (D-49 amended).** `rekey(teamId, { phrase, oldPhrase? })`: `phrase` is the current phrase (rule 1), and the new keys carry its key; `oldPhrase`, if given, signs instead, and must be carried by one of the vault's bundles for the team (a usability guard: owners check the roster-pinned keys). `oldPhrase` without `phrase` is `MALFORMED_RECORD`; a `phrase` that doesn't open the recovery wrap is `WRONG_CREDENTIAL`.

Rejected:
- Binding `wrappedRecoveryPublicKey` to `wrappedAccountKey` (a new record version): the account-key holder replaces the whole recovery wrap instead, and the user's phrase stops working (review 013 D's takeover), no better.
- Refusing a spliced wrap (the first design's rule 3): it locks a user without a PIN out of `secureAccount` (review 014 B).
- Dropping D-49: every team that fails during a `secureAccount` with a new phrase would need an owner by hand.
- A locally pinned recovery key: one more local value, forgeable by any script in the origin.

Residual (TH-12 Limit): operations given no phrase (`createTeam`, `joinTeam`, `rekey` without one) read the stored key. Keys made by them while an account-key holder controls the field carry its recovery key: in those teams its re-keys stay proven, so after `secureAccount` a server colluding with it can publish proven keys above the user's (D-43's server rule is defence in depth), until an owner approves the user's re-key by hand (review 014 C).

## Ripple

- D-55: §6.5, §6.6 step 2, §6.8 step 2, §6.9 (handle), §12; SP-22, SP-23; D-37, D-47 consequences if they quote the handle; using and integration guides (`approve`, overview); forgeability row.
- D-56: §4.1 reader checks, §5.4 (recovery), §5.6, §5.11, §6.8 step 1, §12 (`rekey`); D-45 and D-49 (retry wording), D-49 status; SP-23 (verification, a spliced wrap), SP-11/SP-25 if they quote the check; TH-12 (Limit), TH-41 if it cites D-49; using and integration guides (retry with `{ phrase, oldPhrase }`); retired wording (`rekey(teamId, { phrase })` with the old phrase).

## Complexity

- D-55 adds one field, one comparison and one duplicate check.
- D-56 removes a branch and a refusal: `recoverySigner`'s "the current key or any carried one" splits into one rule per argument (`phrase` current, `oldPhrase` carried), every phrase check becomes the `verifyPhrase` rotation uses, and `recover`'s refusal becomes a warning. One warning code added.

## Phases (one commit each)

1. **Spec:** D-55, D-56 (D-45, D-49 amended); the ripple above; `check:spec`. Design review 014 done.
2. **Code and tests:** `membership.ts`, `owner.ts` (handle, pinned approval); `vault.ts`, `recovery.ts` (`secureAccount`, `confirmRecoveryPhrase`, `rekey`, the splice refusal); tests for 013 A (proven, own, manual) and 013 B (splice: `secureAccount` accepts the real phrase and repairs, `rekey` signs keys carrying the typed key and reports the mismatch, `recover` opens and reports, an old-phrase retry carries the current phrase's key) and review 014 A (duplicate records); guards.
3. **Notes:** execution notes, reviews, ledger.

## Execution notes

- **D-55, as built:** `KeysHandle` gains `keysHash` (base64url); `handleOf(keys)` in `membership.ts` builds every handle the overview and `reconcile` return. `TeamOwner.#reviewedKeys` checks the newest record's version (`STALE_VERSION`) then its keys hash (`TRUST_FAILURE`, `key_mismatch`, session marked `unverified`); `#ascending` refuses two records for one version in both lists the owner reads.
- **D-56, as built:** `typedPhrase(ports, account, phrase)` in `recovery.ts` opens the recovery wrap's `wrappedAccountKey` and returns the phrase's signing key and whether the wrap names another key; `oldPhraseSigner` keeps D-49's carried-key guard; `phrasePublicKey` derives a new phrase's key. `recoverySigner` is gone. `secureAccount`, `confirmRecoveryPhrase` (with `currentPhrase`) and `rekey` use `typedPhrase`; `secureAccount`'s re-keys carry the typed key (no read-back, review 014 E); `recover` reports instead of refusing; the vault holds `#recoveryMismatch` (memory, like `#upgradeFailure`), reported as `recovery-key-mismatch` (action `secureAccount`) and cleared by `rotate`, `secureAccount` and `confirmRecoveryPhrase`.
- **API:** `rekey(teamId, { phrase?, oldPhrase?, anchor? })`; `VaultWarning` gains `recovery-key-mismatch`; `KeysHandle.keysHash` (an integration that builds handles by hand must fill it).
- **Tests:** `key-substitution.test.ts` (D-55: a member's proven re-key, an owner's own re-key, a manual approval and a hand-built wrong hash, two records for one version); `recovery-proof.test.ts` (D-56: a spliced wrap with `rekey`, `secureAccount` with and without a new phrase, `confirmRecoveryPhrase`, `recover`, a phrase that doesn't open the wrap; D-49's retry now `{ phrase, oldPhrase }`). The fake store gains `replaceInList` and `addToList` (a different answer per query; a second record for one identity). Tests that built handles by hand use `keysHandle` from `test/support/teams.ts`; three exact handle assertions now match on the fields they check.
- **Guards:** dropping the keys-hash check (3 failures), the duplicate check (1), carrying the stored key in `rekey` (1) or `secureAccount` (1), refusing in `recover` (1), not reporting in `rekey` (1), and the old phrase-vs-stored-key comparison (4) each fail a test.
- **Checks:** `typecheck`, `npm test` (741), `test:browser` (10), `check:spec`, `build`, `test:package` pass.
- **Change review (this session):** the ripple's terms searched in `docs/` and `README.md`; D-36's `rekey(teamId, { phrase })` stays right without a new phrase; D-49's body is history under its amended status. Retired wording added for the old handle, the old `rekey` comment and §5.4's comparison.
- **Integration (doconvoy e2eev2):** pass overview handles unchanged (they carry `keysHash`); retries after a phrase replacement become `rekey(teamId, { phrase: new, oldPhrase: old })`; show `recovery-key-mismatch` with a `secureAccount` prompt.
- **Not committed;** the local course (`learning/`) not updated.
