# Review 038: change, plan 025

Mode: `change`. Scope: plan 025's spec (`849e020`) and code (`517e5e3`), and what they ripple into. Read only.

## Checked

- **Baseline.** `check:spec` passes. The ledger stood at 2 of 2 under the stop rule as changed after review 037; plan 025 closes 036-A, B and 037-B to E.
- **Properties → protocol.**
  - SP-07 Assumptions: "a vault holding its own anchor refuses one written directly … not one given through the open vault": §5.9 and §6.8 (the re-key's roots), and `vault.rekey` taking `anchor` with no credential (`vault.ts:559-563`).
  - SP-19 (the same-PIN check): §5.11 names the new skips; the accepted side effect is in D-58's amendment.
  - SP-26: the property holds; its Verification lacks the new tests (B).
- **Threats → mechanism.** TH-20's two new limits are review 037's reproductions D and E; the "fails the re-key" claim is `rekeyTeam`'s check of the floor against the vault's anchor (D-54), unchanged.
- **Decisions → text.** D-58's amendment (037 B, C): §4.1, §5.4, §5.11 and the using guide agree. D-54's consequence: TH-20 and SP-07 agree. The two retired phrases match nowhere outside history. TH-04, §6.8 and the integration guide's anchor row need no change.
- **Spec → code.**
  - §5.11's "one whose `kdf` the reader refuses" is `refusedKdf`, the same test `derivePinKey` throws from, before any evaluation. A bad proof and a malformed answer still throw (tested for the proof).
  - §4.1 and §5.4's "doesn't open under this device's key" is `openDeviceWrap`, used by `unlock()`, `status()` and `#registration`. `status()` still calls no OPRF.
- **Plan notes.** One change while coding (the `kdf` test before the evaluation, not the derivation's errors), recorded; it narrows the skip, so no new residual.
- **Not checked:** the browser adapter; races between devices.

## Findings

### A. `listDevices()` marks this device `current` while `status()` says it isn't registered

- **Kind:** wrong claim. **Severity:** low (display only). **Disposition:** correct the text.
- **Where:** `listDevices()` (`vault.ts:340-356`) lists every device wrap that parses and marks `current` by `deviceId`. A wrap that parses but doesn't open under this device's key (037-C) is listed with `current: true`, while `status().deviceRegistered` is false, until the next PIN or phrase unlock registers a new id. The using guide calls the list "per registered device"; §5.5 says the list is for display only.
- **Evidence:** read. The window is short: listing needs an open vault, and an unlock with the PIN or the phrase registers again first; it stays only for a vault already open when the wrap is replaced.
- **Fix:** §5.5 List: "`current` marks this device's `deviceId`; whether its wrap still opens is `status().deviceRegistered`". The using guide: "per device wrap that parses".

### B. SP-26's Verification doesn't list plan 025's tests

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** SP-26 Verification, `record-archive.test.ts`, ends with review 035 B's tests. The traceability test passes (the file is listed), but the sentence doesn't name the 037 B, C cases.
- **Fix:** append: "A PIN wrap whose `kdf` the reader refuses, or this device's wrap that doesn't open, costs only that method too: `secureAccount` with a new PIN runs, a bad proof still refuses, and the device registers again (review 037 B, C)."

## Edits ready now (no decision)

A, B: done after this review (§5.5, the using guide, SP-26).

## Stop rule

Nothing here is for the action rule to fix: still **2 of 2**, freeze candidate (037 `adversarial`, 038 `change`). Next: the formal model and the external audit.
