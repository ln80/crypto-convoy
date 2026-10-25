# Plan 024: the owner's-anchor repair replaces the local anchor; a private wrap that doesn't parse is present but unreadable (review 035 A, B; edits 034 A, B, 035 C, D, E)

## Context

Review 034 (`change`, plan 023) found nothing to fix and left two text edits. Review 035 (`adversarial`, fresh context) found no break of confidentiality or integrity. Two of its findings are for the action rule to fix:

- **035-A** (medium; A2 alone after a first contact, or A9): the repair with an owner's anchor (D-54, D-59) replaces the vault's anchor but not this device's local anchor. The local anchor stays a root of every open (§6.1 step 1). So a device that once accepted a forged chain stays `unverified` (`chain_conflict`) after the repair. TH-04 and SP-07 say the repair "replaces every root".
- **035-B** (medium; A11 alone): `fetchWrap` parses a wrap the vault reads by its identity, and throws when it doesn't parse.
  - A PIN wrap that doesn't parse makes `status()` and `warnings()` throw, and refuses `changePin` with the phrase, `secureAccount` with `newPin`, and the end of `recover`.
  - This device's device wrap that doesn't parse refuses `recover`.
  - A recovery wrap that doesn't parse makes `status()` throw.
  - D-58 applies its "absent" rule to lists only. D-56's amendment covers only `warnings()`' read of the recovery wrap.

The rest is text, or a one-line code change:
- **034-A:** "the only owner" in the scope and §5.9.
- **034-B:** §6.7 and the comments don't name the owner refusal.
- **035-C:** the action for a recovery wrap that doesn't parse, and `UNSUPPORTED_VERSION`.
- **035-D:** an owner approved in the same rotation.
- **035-E:** a recovery public key the server replays.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-54 amended (035-A) | Small | One more `replace` in the repair: this device's local anchor. No new state, fallback or duty | None. Users: the repair repairs the device it runs on |
| D-58 amended (035-B) | Free | Removes failure modes. One reader for the PIN, recovery and device wraps, read by identity: absent, present and readable, or present and unreadable. The operations that write a method replace an unreadable record without reading it | None. Users: status and warnings work under a session's garbage, and the repairs run |
| 035-C | Small | The warning's action for a recovery wrap that doesn't parse; `UNSUPPORTED_VERSION` rethrown | None |
| 034-A, 034-B, 035-D, 035-E | Small (text) | Scope, §5.9, §6.7, §12, §4.1, TH-12, two comments | None |

Reach: unchanged. API: no change.

## Design

### D-54 amended: the repair replaces this device's local anchor

When `rekey` runs with an owner's anchor (`rekeyTeam` with `ownerAnchor`), the vault replaces, in the context it runs in:
- the vault's anchor, as it does today;
- the local anchor (`LocalKeyStore`), with the new floor (the verified tip), replaced even if the stored one is higher.

Other devices and contexts keep their own local anchors:
- another device runs the repair itself, or is reset;
- a receiving context gets a new transfer (§3.8).

TH-04 and SP-07's assumptions say this: "replaces every root the vault holds, and this device's local anchor; other devices repair the same way".

### D-58 amended: a private wrap read by identity that doesn't parse is present but unreadable

The vault reads the PIN wrap, the recovery wrap and this device's wrap by their identity. For each, the reader returns one of three answers:
- absent (no record);
- readable (it parses);
- present but unreadable: it doesn't parse, or declares a known `v` and suite but fails its shape or context checks.

An unknown `v` or suite stays `UNSUPPORTED_VERSION`, since readers ship first (§10). A store error stays `STORE_ERROR`.

What a present but unreadable wrap means:
- **`status()`:** that method reads as set up.
- **`warnings()`:**
  - for the PIN, `pin-not-set-up` (action `changePin`);
  - for recovery, `recovery-key-mismatch`, with action `beginRecoverySetup` when the wrap doesn't parse (035-C) and `secureAccount` when only its key can't be read.
- **Unlocking with that method:** `WRONG_CREDENTIAL` for the PIN and the phrase, as a garbled ciphertext already gives. `DEVICE_NOT_REGISTERED` for this device, which then registers again with the PIN or the phrase.
- **The operations that write the method** replace the live record without reading it:
  - `changePin`; `#refuseCurrentPin` skips its check, since it can't open the wrap, as for a spent share (§5.11);
  - `confirmRecoveryPhrase`, already (D-56);
  - the device registration in `unlockWithPin` and `recover`.

Consequence: a session's garbage in one of these wraps costs that method, never the account's other methods, reports or repairs. Support restores it, as before (SP-26).

### Edits

- **034-A:** scope (Devices and accounts) and §5.9 "Delete an account": "refusing to delete an account that is a listed owner of a team (D-65)".
- **034-B and 035-D:**
  - §6.7 step 1: "New owners must hold version n, or have keys the same rotation approves; the rotation must keep or approve them, else `MALFORMED_RECORD` before anything is built".
  - §12's `setOwners` line says the same.
  - The `setOwners` and `rotate` comments in `owner.ts` name `MALFORMED_RECORD`.
- **035-E:** §4.1, "Whoever holds the account key can rewrite `wrappedRecoveryPublicKey` alone", gains: "and the server can replay an earlier one of the same version, which gives nothing a holder of the old phrase doesn't already have with it (TH-36)". TH-12's residual row cites the same.

## Ripple

- **Protocol:** §4.1, §5.4 (unlock with an unreadable wrap), §5.5 (registration), §5.6, §5.9, §5.11, §6.7, §12.
- **Decisions:** D-54 and D-58 (amended), D-59 (the repair).
- **Threats:** TH-04, TH-12, TH-20, TH-46.
- **Properties:** SP-07 (assumptions), SP-25 or SP-26 (the reports under garbage).
- **Scope:** the integration's duties.
- **Guides:** the using guide (`warnings()` and `status()`).

## Phases (one commit each)

1. **Spec.** D-54 and D-58 amended, and the text edits; `check:spec`. No design review: neither fix adds an input, fallback or state. A reuses the repair's existing `replace`, and B removes failure modes.
2. **Code and tests.**
   - **Code:**
     - `unlock-methods.ts`: a `readWrap` returning absent, readable or unreadable, used by `fetchWrap`'s callers that read by identity.
     - `vault.ts`: `status`, `warnings`, `changePin`, `#refuseCurrentPin`, `#registration`, `recover`, `unlockWithPin`.
     - `recovery.ts`: `storedRecoveryKey` rethrows `UNSUPPORTED_VERSION`; `rekeyTeam` replaces the local anchor with an owner's anchor.
     - `owner.ts`: the comments.
   - **Tests:**
     - `rollback.test.ts` or `account-rotation.test.ts`: dave's device accepts a forged first contact, the server turns honest, and the repair with an owner's anchor makes the device open `ready`.
     - `record-archive.test.ts`:
       - a PIN wrap that doesn't parse: `status()` and `warnings()` work, `changePin` with the phrase replaces it, `secureAccount` with `newPin` runs;
       - a device wrap that doesn't parse: `recover(phrase)` registers again;
       - a recovery wrap that doesn't parse: `status()` works, and the warning's action is `beginRecoverySetup`;
       - a recovery wrap at an unknown `v`: `UNSUPPORTED_VERSION`.
     - `owner-continuity.test.ts`: `setOwners` with an approved joiner as owner is accepted (035-D, specified behaviour).
   - **Guards:** each fix reverted fails its test.
3. **Notes.** Execution notes, then a `change` review and a fresh `adversarial` review.

## Execution notes

(empty)
