# Review 032: adversarial, tenth round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `5ac2c31` (after plan 022). Read only.

## Checked

- **Baseline.** `check:spec` passes. The ledger was at 1 of 2: review 031 (`change`, plan 022) found nothing to fix.
- **Fresh-context reviewer.** It got the adversarial brief and no access to `.agents/`, `learning/` or history. The brief also asked about operations that write before they check, about one record that stops an account-wide or team-wide operation, and about reports a user would act on harmfully.
  - It found no critical finding.
  - It reproduced its findings 1 to 3 and 5a with throwaway tests, which it deleted.
  - This session reproduced 1 (variant b), 2 and 5a again (throwaway tests, deleted), and read 3 and the rest in the code.
- **Pairs checked, nothing beyond accepted threats:**
  - A2 + A11 (the server writes as any account);
  - A2 + A9 (TH-46, TH-49);
  - A2 + A4 (TH-50, TH-30);
  - A2 + A6 (TH-38);
  - A7 + A11 and A8 + A11 (TH-45, TH-11), except A below;
  - A2 with a relayed link, anchor or transfer (TH-04, TH-21, TH-23, TH-39, TH-49).
- **Dropped:**
  - The reviewer's 4a, `rekey-needed`'s advice: 030-F changed the text.
  - Its 4b, `foreign-member-keys` for a withheld record: 030-E.
  - Its 4d, a garbage PIN wrap that reads as a wrong PIN. A wrap under a PIN-derived key that doesn't open can't be told from a wrong PIN; that is the TH-36 and TH-46 premise, restored by support.
- **Not checked:**
  - the cc1 internals, the canonical reader, and the wrap, seal and sign blocks;
  - the browser adapter;
  - drafts, inboxes and submissions in detail;
  - vectors.

## Findings

### A. A session garbling the recovery wrap's public key refuses the phrase everywhere, and stops the warnings

- **Kind:** wrong claim, spec → code. **Severity:** medium (one actor; the documented remedy is refused, though the failure is visible as an error). **Actors:** A11 alone. **Disposition:** fix (small).
- **Where:** a session may `replace` a live `account-key-wrap` (rule 7 archives it). Two ways to garble it:
  - **(b) Only `wrappedRecoveryPublicKey` is garbled,** so `wrappedAccountKey` still opens with the phrase.
    - `typedPhrase` (`recovery.ts:57`) opens the stored public key after checking the phrase, and throws `DECRYPTION_FAILED`.
    - So `secureAccount`, `rekey(teamId, { phrase })`, `confirmRecoveryPhrase` and `recover` all fail.
    - `warnings()` throws too (`currentRecoveryKey`, `recovery.ts:29-32`).
    - D-56 and §4.1 say instead that the vault "reports a stored key that differs (`recovery-key-mismatch`) without refusing", so `secureAccount` can repair it (`vault.ts:290`).
  - **(a) Both ciphertexts are garbled.** The phrase is `WRONG_CREDENTIAL`, and a new setup with the PIN fails `DECRYPTION_FAILED`. Meanwhile `status()` still says recovery is set up, and `warnings()` throws instead of reporting.
- **Evidence:** reproduced, variant (b): `warnings()`, `secureAccount` and `rekey` with the phrase all throw `DECRYPTION_FAILED`. The reviewer reproduced (a).
- **Impact:** a session alone disables the phrase-based remedies, including `secureAccount` after a stolen device (TH-10, TH-12). The PIN and devices keep working, so nothing locks the user out. TH-45's acceptance ("the user is locked out, so it is seen") doesn't hold here.
- **Fix:** a stored recovery public key that doesn't open counts as a mismatch, not a failure:
  - `typedPhrase` returns `mismatch: true`, so `secureAccount` proceeds, and its rotation writes a fresh recovery wrap for the typed phrase.
  - `warnings()` reports `recovery-key-mismatch` (action `secureAccount`).
  - A recovery setup with the PIN replaces the wrap without reading the old public key.
  - Operations that need the stored key and take no phrase (`createTeam`, `joinTeam`, `rekey` without a phrase) fail as they do now.
  - Variant (a) then shows up in `warnings()`; its remedy is a setup with the PIN (D-61) or support.
- **Budget:** small (one branch per reader; no state, fallback or duty).

### B. A member publishing proven re-keys fast enough makes `reconcile` fail, so inactive members are never rotated out

- **Kind:** missing threat. **Severity:** medium (one actor; a guarantee the integration relies on, SP-22). **Actors:** A5 alone (a member holding its phrase), or A11 on a member with a pending proven re-key. **Disposition:** fix (small).
- **Where:**
  - `reconcile` plans the approvals of proven re-keys and the removals of inactive holders in one rotation (`owner.ts:141-146`).
  - At apply time, `#reviewedKeys` (`owner.ts:185-191`) refuses keys that are no longer the newest (`STALE_VERSION`).
  - `reconcile` retries once (`owner.ts:84-98`), then throws.
  - A member who publishes a newer proven re-key between the snapshot and the apply, twice, blocks every removal.
  - TH-47 and SP-12's Limit accept that bait keeps the member's *own* keys unapprovable. They don't say it blocks removing *other* accounts (SP-22, TH-14).
- **Evidence:** reproduced by the reviewer: with carol inactive, `reconcile(["alice", "bob"])` threw `STALE_VERSION`, and carol still held the current version. This session read the code path.
- **Fix:** `reconcile` leaves out of the rotation an approval whose keys are no longer the newest, and rotates with the rest. The skipped member is approved at the next `reconcile`, and is reported (`needsHuman` or a skipped list). `approve` called by a person keeps refusing `STALE_VERSION`, since a person reviewed those exact keys.
- **Budget:** small (a filter at apply time). **Workaround today:** `owner.remove(...)` approves nothing, so it still works.

### C. `LAST_OWNER` counts listed owners, so two owners leaving one after the other freeze the team

- **Kind:** wrong claim (overclaim of TH-18, SP-16, §5.9). **Severity:** medium (honest use; availability for the whole team, for good). **Actors:** none needed. **Disposition:** fix (small); needs a decision.
- **Where:** `leaveTeam` (`vault.ts:568-569`) refuses only when the account is the only listed owner. `leaveTeam` doesn't remove its account from the owner list, and `reconcile` never removes owners. So with owners alice and bob, bob leaves, then alice leaves: the list still names both, and nobody holds keys.
- **Evidence:** reproduced: both `leaveTeam` calls succeed with owners `[alice, bob]`. No test covers `leaveTeam` or `LAST_OWNER`.
- **Fix (recommended):** a listed owner can't leave. An owner steps down first (`setOwners` without them, by any owner, themself included, which keeps at least one owner), then leaves. `leaveTeam` refuses a listed owner with `LAST_OWNER`, and §9 reads "a listed owner steps down first; the only owner can't". **Budget:** small (one check). **Product cost:** an owner leaving takes one more step. Integrators: the owner-leave flow calls `setOwners` first.

### D. `createTeam` throws a `TypeError` when the server withholds the new wrap

- **Kind:** spec → code (D-23). **Severity:** low. **Actors:** A2. **Disposition:** correct the code.
- **Where:** `createTeam` (`vault.ts:475-476`) reads the new bundle back from the server for its floor (`created!.floor!`). The floor is version 1 of the record it just built, and is known locally.
- **Evidence:** reproduced: `TypeError`, not a `ConvoyError`.
- **Fix:** record the vault anchor from the version record it committed.

### E. An owner's caller mistakes are reported as tampering

- **Kind:** wrong claim (error code). **Severity:** low. **Disposition:** correct the code.
- **Where:** `owner.remove([anOwner])`, or `setOwners(owners, { keep })` with a `keep` that leaves out a new owner, build a version whose owner has no roster entry. The self-check in `versionOp` (`rotation.ts:52`) reports it as `TRUST_FAILURE` (`not_an_owner`). §9 reserves `TRUST_FAILURE` for a check that failed in a record.
- **Fix:** refuse these inputs before building, with `MALFORMED_RECORD` for a bad request, as other caller errors are refused.

### F. A wrap the server withholds during a rotation stays behind at the retired version

- **Kind:** missing threat (availability). **Severity:** low. **Actors:** A2. **Disposition:** accept and document.
- **Where:** a rotation re-wraps the wraps it lists (`rotation.ts:33`, D-58). A wrap withheld then is archived with the retired version. `secureAccount` reports that team failed. `rotate()` reports nothing, and the team reads `not-joined` until support restores it.
- **Why accept:** withholding is TH-28's, and the restore brings it back (SP-26).
- **Acceptance text:** D-58's consequence and TH-28.

### G. Notes, accepted as they are

- **`leaveTeam` verifies the chain first** (`currentOwners`). After a garbage team key version (TH-25, accepted), members can't leave, and the team stays failed in every account-wide report. This is a consequence of 025-C's acceptance; TH-25's residual gains the sentence.
- **Unbounded garbage `member-keys` and wrap pairs from a session.** They cost each vault operation a list and an unwrap per record: availability. Rate limits are the integration's (TH-31's reasoning).

## Edits ready now (no decision)

D, E (code), F, G (text); with 031-A.

## Needs a decision

- **A:** a stored recovery key that doesn't open counts as a mismatch (recommended).
- **B:** `reconcile` skips approvals that went stale and rotates with the rest (recommended).
- **C:** a listed owner steps down before leaving (recommended).

## Stop rule

A, B and C are for the action rule to fix: **0 of 2**.
