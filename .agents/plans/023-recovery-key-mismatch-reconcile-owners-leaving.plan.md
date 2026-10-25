# Plan 023: a garbled recovery key is a mismatch; `reconcile` skips stale approvals; a listed owner steps down before leaving (review 032 A, B, C; accept 032 F; edits 031 A, 032 D, E, G)

## Context

Review 031 (`change`, plan 022) found nothing to fix and left one edit. Review 032 (`adversarial`, fresh context) found no critical finding, and three medium findings for the action rule to fix:

- **032-A** (A11 alone): a session garbles `wrappedRecoveryPublicKey` in the recovery wrap.
  - `typedPhrase` then throws `DECRYPTION_FAILED`, which refuses `secureAccount`, `rekey` with the phrase, `confirmRecoveryPhrase` and `recover`.
  - `warnings()` throws too.
  - D-56 says a stored key that differs is reported, never refused.
- **032-B** (A5 alone, or A11 on a member with a pending proven re-key): a member publishes a newer proven re-key between `reconcile`'s snapshot and its apply, twice. `reconcile` then throws `STALE_VERSION`, and the inactive holders it planned to remove stay in (SP-22, TH-14).
- **032-C** (honest use): `leaveTeam` refuses only the sole listed owner. Two listed owners leaving one after the other leave a team with listed owners and no keys, frozen for good (TH-18, SP-16, §5.9 overclaimed).

The rest:
- **032-F** is accepted: a wrap the server withholds during a rotation stays at the retired version.
- Text and code edits:
  - **031-A:** §12's `rekey-needed` answer.
  - **032-D:** `createTeam`'s `TypeError`.
  - **032-E:** an owner's caller mistakes reported as `TRUST_FAILURE`.
  - **032-G:** TH-25's residual: members can't leave after a garbage version.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-56 amended (032-A) | Free | Removes a failure mode: a stored recovery key that doesn't open counts as a mismatch. No new state, fallback or warning | None. Users: `secureAccount` repairs it; `warnings()` reports `recovery-key-mismatch` |
| D-64 (032-B) | Small | One filter at apply time; the report gains the skipped accounts (in `needsHuman`, an existing field, or a new `skipped` list, see design) | Integrators: possibly one report field |
| D-65 (032-C) | Small | One check in `leaveTeam`; `LAST_OWNER` covers a listed owner | Users: an owner who leaves steps down first. Integrators: the owner-leave flow calls `setOwners` first; §9 and the using guide change the action |
| 032-F | Small (text) | D-58, TH-28 | None |
| 031-A, 032-D, E, G | Small | A §12 line; a local floor in `createTeam`; two input checks before building a version; a TH-25 sentence | None |

Reach: unchanged. API:
- `leaveTeam` refuses more cases, with the same error.
- `reconcile`'s report may gain a field.
- `remove` and `setOwners` refuse bad input with `MALFORMED_RECORD`, not `TRUST_FAILURE`.

## Design

### D-56 amended: a stored recovery key that doesn't open is a mismatch

Wherever the vault compares the typed phrase's key with the stored recovery public key (`typedPhrase`), a stored key that doesn't open under the account key counts as a mismatch:
- the phrase was already checked by opening `wrappedAccountKey`;
- the typed phrase's key is used;
- the mismatch is reported as before.

The other places:
- **`warnings()`:** a recovery wrap whose public key doesn't open gives `recovery-key-mismatch` (action `secureAccount`), as one naming another key does. A recovery wrap whose `wrappedAccountKey` doesn't open with the phrase is indistinguishable from a wrong phrase, and stays so.
- **A recovery setup with the PIN** (`confirmRecoveryPhrase` with `currentPin`) replaces the wrap without reading the old public key. It already doesn't need it: D-61 checks the PIN.
- **Operations that need the stored key and take no phrase** (`createTeam`, `joinTeam`, `rekey` without a phrase) still fail. They have no other source for the key, and that is D-56's existing rule.

Consequence:
- `secureAccount` repairs the garbled wrap. Its rotation writes a fresh recovery wrap for the typed phrase (D-45).
- A wrap with both parts garbled shows in `warnings()`. Its remedies are a recovery setup with the PIN (D-61), or support (SP-26).

### D-64: `reconcile` approves only keys still the newest at apply time, and rotates with the rest

`reconcile` (§6.9) plans its approvals from a snapshot. At apply time, an approved account whose newest published keys aren't the planned ones (`STALE_VERSION`) is left out of that rotation and reported. The removals and the other approvals go ahead. That account's newer keys are planned at the next `reconcile`, or reviewed by a person.

Things that don't change:
- `approve`, called with a person's handles, still refuses `STALE_VERSION` for the whole call: a person reviewed those exact keys.
- `TRUST_FAILURE` (another record for the reviewed version) still stops `reconcile`.

Report: the skipped accounts are listed in the existing `needsHuman` with a reason, if its type allows one. Otherwise they go in a new `skipped: string[]`. The choice is made in phase 1 from `ReconcileReport`'s shape.

Rejected:
- **Retrying until the keys settle:** a member publishing continuously keeps it failing.
- **Splitting removals and approvals into two rotations:** that is twice the versions for every `reconcile`.

### D-65: a listed owner steps down before leaving

`leaveTeam` refuses any account in the newest version's owner list, with `LAST_OWNER`:
- The account steps down first, through `setOwners` without itself, called by any owner, itself included. `setOwners` keeps at least one owner.
- The only owner can't step down, so it can never leave (TH-18, unchanged).
- §9's `LAST_OWNER` now reads "the account is a listed owner: it steps down first (`setOwners`); the only owner can't".

Rejected:
- **Counting owners who still hold keys:** nothing in the chain says who deleted their wraps.
- **Having `leaveTeam` step down by itself:** a leave would then write a team key version, which needs the owner's signing key, and would change the owner list without a separate act.

### 032-F accepted

- **D-58's Consequence and TH-28:** a wrap the server withholds while the account rotates isn't re-wrapped. It is archived with the retired version.
  - `secureAccount` reports that team failed.
  - After a plain `rotate()`, the team reads `not-joined` until support restores the wrap (SP-26).
- **Ledger:** a residual.

### Edits

- **031-A:** §12's `warnings()` line: "teams whose keys need re-keying (`rekey-needed`; answer: `rekey` with the phrase, D-56)".
- **032-D:** `createTeam` records the vault anchor from the version record it committed (version 1 and its hash), not from a read-back.
- **032-E:** `remove` and `setOwners` refuse, before building, with `MALFORMED_RECORD`:
  - an owner in `remove`'s list;
  - a new owner whose account `keep` leaves out.

  §12's comments say so.
- **032-G:**
  - TH-25's residual gains "members can't leave such a team (`leaveTeam` verifies the chain first)".
  - It also notes that a session's unbounded garbage records cost availability only, and that rate limits are the integration's.

## Ripple

- **Protocol:** §4.1 (D-56 text), §5.9 (leave), §6.9 (reconcile), §9 (`LAST_OWNER`), §12 (`warnings`, `leaveTeam`, `reconcile` report, `remove` and `setOwners` errors).
- **Decisions:** D-56 (amended), D-64 and D-65 (new), D-58's Consequence.
- **Threats:** TH-14, TH-18, TH-25, TH-28, TH-45 (the "seen" premise holds again).
- **Properties:** SP-16, SP-22 (removals aren't blocked by a stale approval), SP-23 (`secureAccount` repairs a garbled key), SP-25.
- **Guides:** the using guide (`LAST_OWNER`'s action, the report field); the integration guide (the last-owner duty, the owner-leave flow).
- **Retired terms:** "until another owner is added" (§9, using guide). Check before adding.

## Phases (one commit each)

1. **Spec.** The D-56 amendment, D-64, D-65, 032-F's acceptance and the text edits; run `check:spec`. Then a fresh-context `design` review of D-64 and D-65: they change an owner operation's outcome and a public refusal. Its questions:
   - Can a skipped approval be used to keep a removal from happening?
   - Can stepping down be forced, or blocked?
   - Does treating an unopenable stored key as a mismatch let a phrase holder do anything new?
2. **Code and tests.**
   - **Code:**
     - `recovery.ts` (`typedPhrase`, `currentRecoveryKey` users) and `vault.ts`: `warnings`, `confirmRecoveryPhrase` with the PIN, `leaveTeam`, `createTeam`.
     - `owner.ts`: `reconcile`'s apply filter and report; `remove` and `setOwners` input checks.
   - **Tests:**
     - `secure-account.test.ts` or `record-archive.test.ts`, a garbled recovery public key:
       - `warnings()` reports `recovery-key-mismatch`;
       - `secureAccount` succeeds and repairs it;
       - `rekey` with the phrase works.
     - `reconcile` (`member-rekey.test.ts` or the reconcile tests): a member publishes newer proven keys mid-`reconcile`. The inactive holder is removed, and the member is skipped and reported.
     - A new `leave.test.ts` (or `owner-changes`):
       - a listed owner's `leaveTeam` is `LAST_OWNER`;
       - after stepping down, it leaves;
       - two owners can't both leave;
       - a non-owner leaves.
     - `createTeam` with its wrap withheld gives a `ConvoyError`, or succeeds with the local anchor.
     - `remove([owner])` gives `MALFORMED_RECORD`.
   - **Guards:** each fix reverted fails its test.
3. **Notes.** Execution notes, then a `change` review and a fresh `adversarial` review.

## Execution notes

(empty)
