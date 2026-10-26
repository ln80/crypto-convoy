# Plan 025: a PIN or device wrap that can't be used costs only its method; what the vault's anchor and the repair really stop (review 037 B to E; edits 036 A, B)

## Context

Review 036 (`change`, plan 024) found nothing to fix and left two text edits. Review 037 (`adversarial`, fresh context) found no break of confidentiality or integrity by one actor. Under the stop rule as changed after it (availability-only fixes don't count), the ledger stands at 2 of 2: this plan does the work left before the first release, and its `change` review is the only review it needs.

Two availability fixes, small, by A11 alone:

- **037-B** (low): a PIN wrap that parses but whose `kdf` can't be used (an `oprfKeyId` the settings don't pin, or a cost under the reader minimum and above the hard floor) reads as readable. `#refuseCurrentPin` rethrows `UNSUPPORTED_VERSION` or `MALFORMED_RECORD`, so `secureAccount({ newPin })` refuses. D-58's amendment says a session's garbage "costs that method only".
- **037-C** (low): this device's wrap that parses but doesn't open under the device key breaks `unlock()` for good (`DECRYPTION_FAILED`). `#registration` counts it as a registration, so the PIN or phrase unlock never registers the device again, and `status().deviceRegistered` is true. D-58's amendment says the device registers again.

Two wrong claims, combined attacks, accepted (**server-controlled history**):

- **037-D** (medium; A7 or A9 with the open vault, and A2): `rekey({ anchor })` needs no credential, so whoever holds the open vault replaces the vault's anchor, the local anchor and the floor. TH-20 and SP-07 say a vault that has opened the team refuses a planted floor.
- **037-E** (medium; A7 or A9 once, then A2): a planted wrap survives `secureAccount` (re-wrapped) and the owner's-anchor repair (archived). A server serving it to a new device, with the repaired wrap withheld, roots that device on the forged chain. TH-20, D-54's consequence and SP-07 say the owner's anchor repairs it.

Text only:

- **036-A:** §5.4 gives the failures for a missing wrap, not for one that can't be read.
- **036-B:** the using guide's `status()` line doesn't say what an unreadable wrap reads as.

037-A (the previous-key link, an acceptance with text in TH-17) is not in this plan; it stays open in the ledger.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-58 amended (037-B) | Small | `#refuseCurrentPin` skips its check when the live PIN wrap can't be used: `UNSUPPORTED_VERSION` or `MALFORMED_RECORD` from its `kdf`, as already for a wrap that doesn't parse and for a spent share. No state, fallback or failure added | None. Users: `secureAccount` with a new PIN runs under a session's garbage |
| D-58 amended (037-C) | Small | "Unreadable", for this device's wrap, also covers one that doesn't open under this device's key. One open in `status()` and `#registration`; `unlock()` maps the failure to `DEVICE_NOT_REGISTERED` | None. Users: the device registers again with the PIN or the phrase, as for a wrap that doesn't parse |
| 037-D, 037-E | Text, accepted | TH-20, SP-07 Assumptions, D-54's consequence; two ledger residuals (already added by review 037) | None |
| 036-A, 036-B | Text | §5.4, the using guide | None |

Reach: unchanged. API: no change. No design review: neither fix adds an input, a state or a fallback. B widens a branch whose input (the live PIN wrap) the session already controls through a wrap that doesn't parse (D-58); C reads a value only this device can produce (its random device key), which nothing honest makes fail.

## Design

### D-58 amended again (037-B): a PIN wrap whose `kdf` can't be used

The vault reads the PIN wrap by its identity as today: absent, readable or unreadable. When it then derives with a readable wrap's `kdf`:

- **Unlock with the PIN:** unchanged. `UNSUPPORTED_VERSION` for an unpinned key id (honestly: the settings lag the OPRF service), `MALFORMED_RECORD` for a cost outside the reader's bounds.
- **The same-PIN check** (§5.11, `#refuseCurrentPin`): skipped when the derivation refuses the wrap's `kdf` (`UNSUPPORTED_VERSION`, `MALFORMED_RECORD`), as for a wrap that doesn't parse and a spent share. `TRUST_FAILURE` (a bad proof) and `STORE_ERROR` still throw: they are the OPRF service's or the store's, not the wrap's.
- **`changePin`:** unchanged; with the phrase it replaces the wrap, with the current PIN it fails as unlocking does.

Accepted, as for a wrap that doesn't parse: with the check skipped, the user can set again the PIN of a retired version (SP-19); a server must still serve that version to a stateless device. §5.11's paragraph names the case.

### D-58 amended again (037-C): this device's wrap that doesn't open

This device's wrap is present but unreadable also when it parses but doesn't open under the `deviceKey` held in `LocalKeyStore`. A random device key never fails honestly, so the server can't choose this branch for an honest device; only a writer of the record can, which already makes it unreadable by garbling it.

- **`unlock()`:** `DEVICE_NOT_REGISTERED` (not `DECRYPTION_FAILED`).
- **`#registration`** (in `unlockWithPin` and `recover`): counts this device's wrap as a registration only if it opens; otherwise registers a new device under a new id, as today for one that doesn't parse.
- **`status().deviceRegistered`:** true only if it opens. `status()` already reads `LocalKeyStore`; this is one more unwrap, with no account key needed.
- **`listDevices()`:** unchanged (it lists wraps that parse, for display only).

### Text (037-D, 037-E)

- **TH-20 disposition:** replace "a vault that has opened or exported the team refuses it, … and an anchor from an owner repairs it (D-54)" with:
  - the vault's anchor refuses a floor planted by raw writes, but whoever holds the open vault can also give an owner's anchor through `rekey` (§6.8), which needs no credential and replaces the vault's anchor: on that device, only the user's re-key from an anchor an owner gave them repairs it (037-D);
  - the repair roots the device it runs on; the planted wrap stays the account's until the clean-up archives it, and a server that serves it to a new device of the account, withholding the repaired wrap, roots that device on the planted chain, until it is given an owner's anchor itself (037-E).
- **SP-07 Assumptions:** "a vault holding its own anchor for the team refuses it (the re-key fails), and an anchor from an owner repairs it, also on a device with no anchor" becomes: "a vault holding its own anchor refuses a floor written directly (the re-key fails), not one given through the open vault; an anchor from an owner repairs the device it runs on, while a server can still serve a new device the planted wrap (TH-20)".
- **D-54's consequence:** "the owner's anchor repairs it" gains "on the device that runs the repair; a new device trusts the floor of the wrap it is served (TH-20)".
- Ripple check: TH-04's paragraph on owner's anchors, §6.8, the integration guide's duty row for repair anchors (unchanged: still deliver them outside the server).

### Edits (036-A, 036-B, and 037-C's wording)

- **§5.4 Same device:** "If the wrap is gone (revoked, or removed by a rotation), or can't be read: it doesn't parse, or doesn't open under this device's key (D-58), the device must register again: `DEVICE_NOT_REGISTERED`."
- **§5.4 PIN:** "A PIN wrap that doesn't parse is `WRONG_CREDENTIAL`, before any evaluation."
- **§5.4 Recovery phrase:** "A recovery wrap that doesn't parse is `WRONG_CREDENTIAL`."
- **§4.1** (the paragraph on wraps read by identity): "or, for this device's wrap, doesn't open under its key".
- **§5.11** (same-PIN check): "It is skipped when the current version has no PIN wrap, one that can't be read, or one whose `kdf` the reader refuses (D-58), or when that share is spent".
- **Using guide**, after the `status()` line: "A PIN or recovery wrap that can't be read reads as `set-up`, and `warnings()` names it. This device's wrap that can't be read reads as `deviceRegistered: false`: offer the PIN or the phrase, which registers the device again."

## Ripple

- **Protocol:** §4.1, §5.4, §5.5 (registration), §5.11.
- **Decisions:** D-58 (amended), D-54 (consequence), D-40 (the same-PIN check, cited).
- **Threats:** TH-20, TH-46 (session garbage), TH-04 (checked, likely unchanged).
- **Properties:** SP-07 (assumptions), SP-19 (the same-PIN check), SP-26 (the reports under garbage).
- **Guides:** the using guide; the integration guide (checked).
- **Retired wording:** "a vault that has opened or exported the team refuses it" into `scripts/retired-terms.json`.

## Phases (one commit each)

1. **Spec.** D-58 amended, the TH-20, SP-07, D-54 text and the edits; `check:spec`.
2. **Code and tests.**
   - **Code:**
     - `vault.ts`: `#refuseCurrentPin` returns on `UNSUPPORTED_VERSION` and `MALFORMED_RECORD` from `openWithPin`; `unlock()` maps a device wrap that doesn't open to `DEVICE_NOT_REGISTERED`; `#registration` and `status()` count this device's wrap only if it opens.
     - Possibly a helper in `unlock-methods.ts` (`openDeviceWrap(ports, wrap, device)`, returning the key or `null`), shared by the three.
   - **Tests** (`record-archive.test.ts`, next to plan 024's):
     - a PIN wrap with an unpinned `oprfKeyId`: `secureAccount({ phrase, newPin })` runs and rotates; `unlockWithPin` stays `UNSUPPORTED_VERSION`;
     - a PIN wrap with a cost under the reader minimum: `secureAccount({ newPin })` runs;
     - a PIN wrap with an honest bad proof still throws `TRUST_FAILURE` from the check (the OPRF service's, not the wrap's);
     - this device's wrap that parses but doesn't open: `unlock()` is `DEVICE_NOT_REGISTERED`, `status().deviceRegistered` is false, `unlockWithPin` registers a new device, and `unlock()` then works.
   - **No tests** for D and E: they are acceptances. Review 037's reproductions are the record of the residual.
   - **Guards:** each fix reverted fails its test.
3. **Notes.** Execution notes; then the `change` review (038). A fix beyond availability found there resets the stop rule's count.

## Execution notes

- **037-B, as built:** the check skips the wrap on a test of its `kdf` before any evaluation, not on the derivation's errors. `refusedKdf` (`pin-key.ts`) gives the reason a reader refuses a `kdf` (a cost below `min`: `MALFORMED_RECORD`; a key id with no pinned key: `UNSUPPORTED_VERSION`), and `derivePinKey` throws from it, so the check and the derivation share one rule. Catching the derivation's errors would also have skipped the check on a malformed OPRF answer (`MALFORMED_RECORD` too), which is the service's, not the wrap's.
- **037-C, as built:** `openDeviceWrap` (`unlock-methods.ts`) gives this device's account key, or `null` for a wrap that is absent, unreadable or doesn't open (`DECRYPTION_FAILED`). `unlock()` throws `DEVICE_NOT_REGISTERED` on `null`; `status()` and `#registration` count the wrap through `#registered`, which wipes the key it opened.
- **Spec:** unchanged while coding. §5.11's "one whose `kdf` the reader refuses" is the `refusedKdf` test.
- **Tests** (`record-archive.test.ts`, "a PIN wrap whose kdf is refused, or this device's wrap that doesn't open, costs only its method"):
  - an unpinned key id: `unlockWithPin` stays `UNSUPPORTED_VERSION`, `secureAccount` with a new PIN runs, and the new PIN unlocks;
  - a cost below the reader's minimum: `secureAccount` with a new PIN runs;
  - a bad proof: the check still throws `TRUST_FAILURE` (`bad_signature`) and nothing is rotated;
  - this device's wrap that parses but doesn't open: `DEVICE_NOT_REGISTERED`, not registered in `status()`, the PIN registers a new device id, and the same-device unlock works.
- **Guards:** the `kdf` skip, `openDeviceWrap`'s `null` on `DECRYPTION_FAILED`, and `#registration`'s open, each reverted, fail their tests.
- **Checks:** `typecheck`, `check:spec`, `npm test` (786), `test:browser` (10), `build`, `test:package` and fuzz (30) pass.
- **Integration (doconvoy e2eev2):** no API change. A device whose wrap a session garbled now reads `deviceRegistered: false`, as for one that doesn't parse: offer the PIN or the phrase.
