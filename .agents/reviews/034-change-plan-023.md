# Review 034: change, plan 023 (D-56 amended, D-64, D-65)

Mode: `change`. Scope: the `docs/` changes of plan 023 (`544a811`, TH-46 adjusted in `230bfad`) and what they ripple into, against the code at `e63c839`. Read only.

## Checked

- **Baseline:**
  - `npm run check:spec` passes.
  - Ledger: 0 of 2, nothing open to fix. Still open, low: 011-A. For the next complexity review: 026-F, 028-C.
  - Plan 023's checks pass: 776 tests, browser 10, fuzz 30, build, package.
- **Properties → protocol:** every changed sentence was traced to a § and to the code.
  - SP-16: a listed owner can't leave, with its new Limit. Traced to §5.9, §9 and `leaveTeam`.
  - SP-22: keys published during `reconcile` never stop its removals. Traced to §6.9 step 3 and `#rotate`/`#recipients` with `reconcile`.
  - SP-23: a garbled or unparsable recovery wrap is reported. Traced to §4.1, `storedRecoveryKey` and `typedPhrase`.
- **Threats → mechanism:**
  - TH-14 (removals not stopped) and TH-18 (owners step down).
  - TH-25 (members can't leave after a garbage version) and TH-28 (a wrap withheld during a rotation).
  - TH-46: what `secureAccount` repairs, and what needs the PIN setup.
- **Decisions → text.** D-56, D-64 and D-65 were searched across `docs/`, `README.md`, the guides and the comments in `src/`. Terms searched:
  - "only owner", "until another owner", `LAST_OWNER`;
  - `rekey-superseded`, `not_an_owner`;
  - "must hold the current version", `DECRYPTION_FAILED`.
- **Spec → code:**
  - `#rotate` refuses an owner that is neither kept nor approved before it builds anything. `versionOp`'s `not_an_owner` stays as a backstop.
  - `HumanReason` is unchanged.
  - `storedRecoveryKey` still throws `STORE_ERROR`.
  - `confirmRecoveryPhrase` uses `replace` for a live wrap it can't parse.
- **Plan notes:** the three residuals the plan accepted are in the ledger.
- **Not checked:** the doconvoy owner-leave flow.

## Findings

### A. The integration's account deletion still says "the only owner"

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** two places still say "the only owner of a team":
  - `scope.md:80`, "refusing to delete an account that is the only owner of a team";
  - §5.9 "Delete an account" (`protocol.md:590`), which also says "the integration must refuse while the account is the only owner of a team".

  D-65's Consequence and the integration guide say the integration refuses "a listed owner", as `leaveTeam` does. Deleting one of two listed owners is the freeze D-65 closes for leaving.
- **Fix:** "a listed owner of a team (D-65)" in both.

### B. §6.7 and two comments don't name the new refusal

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:**
  - §6.7 step 1 says new owners "must hold version n", without saying what happens otherwise.
  - The `setOwners` and `rotate` comments in `owner.ts:116-136` list their errors without the new `MALFORMED_RECORD` for an owner left out of `keep`.
  - §12 already names it.
- **Fix:**
  - §6.7 step 1: "… and the rotation must keep them, else `MALFORMED_RECORD` before anything is built".
  - The two comments name it.

## Not found

- **D-64 needs no new reason or field.** §6.9's reasons and `using.md`'s report line are back to their earlier text.
- **TH-45's premise holds.** The variants that left the user unaware are now reported, and the one that isn't (a garbled `wrappedAccountKey`) locks out the phrase in a way the user sees.
- **A rotation with nothing left writes nothing.** `reconcile`'s report then gives no `rotatedTo`, as §6.9 says.

## Edits ready now (no decision)

A, B.

## Stop rule

Nothing here is for the action rule to fix: **1 of 2**. A fresh `adversarial` review that finds nothing to fix makes the freeze candidate.
