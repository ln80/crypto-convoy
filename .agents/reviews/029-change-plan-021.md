# Review 029: change, plan 021 (D-58 amended)

Mode: `change`. Scope: the `docs/` changes of plan 021 (`2e54f9c`) and what they ripple into, against the code at `f4484b5`. Read only.

## Checked

- **Baseline:**
  - `npm run check:spec` passes.
  - Ledger: 0 of 2, nothing open to fix. Open, low: 011-A. Waiting for the next complexity review: 026-F and 028-C.
  - Plan 021's checks passed: 764 tests, browser 10, fuzz 30, build, package.
- **Properties → protocol:** SP-26's new sentence was traced to D-58's amendment, §5.6, §12 and `recovery.ts`:
  - with a failing team, the warnings list it and a phrase replacement reports it failed;
  - the account's other teams are re-keyed.
- **Threats → mechanism:** each claim was traced to code and to plan 021's tests:
  - TH-20: a planted mismatched wrap fails its team; the account's other teams and its warnings go on; a planted bundle with no floor trusts the served chain.
  - TH-28: D-63's accepted risk of a withheld newest wrap.
- **Decisions → text:** D-58's amendment searched across `docs/`, `README.md`, the guides and `src/` comments, for `foreign-member-keys`, `rekey-needed`, "the warnings" and `confirmRecoveryPhrase`.
- **Spec → code:**
  - `teamBundles` catches every `ConvoyError` except `STORE_ERROR`.
  - Two functions use it: `teamsWithForeignKeys`, and `teamsWithOldRecoveryKey`. `teamsWithOldRecoveryKey` has two callers, `confirmRecoveryPhrase` and `warnings()`; A comes from the second.
  - `secureAccount` was already caught per team in `rekeyTeams`.
- **Plan notes:** no risk accepted on the plan's own. The doconvoy note says `foreign-member-keys` may name a team whose record was withheld.
- **Not checked:** doconvoy's handling of the warnings.

## Findings

### A. A team whose bundles fail is also listed under `rekey-needed`, with the opposite advice

- **Kind:** spec → code. **Severity:** low (advice only; both remedies leave the team reported, and no security consequence). **Disposition:** correct the code.
- **Where:**
  - `warnings()` (`vault.ts:451-455`) builds `rekey-needed` from `teamsWithOldRecoveryKey`. That function now lists a failing team on purpose, so that `confirmRecoveryPhrase` reports the team (`recovery.ts:188-196`).
  - The same team then appears under `rekey-needed` (action `rekey`) and under `foreign-member-keys` (action `secureAccount`). The using guide tells the integration to answer `foreign-member-keys` "with `secureAccount`, not `rekey`" (D-54), and says `rekey-needed` is for "teams whose keys predate the current phrase".
- **Evidence:** reproduced with a throwaway test, now deleted. With `team-2`'s published record withheld, `warnings()` returns `rekey-needed: ["team-2"]` and `foreign-member-keys: ["team-2"]`.
- **Fix:** `warnings()` leaves the teams of `foreign-member-keys` out of `rekey-needed`, in one line. The record-archive test asserts that `rekey-needed` doesn't list them.

## Not found

- `confirmRecoveryPhrase` returns its report: a failing team is listed in `failed` and the others are re-keyed.
- `STORE_ERROR` still stops both account-wide functions, as D-58 says ("any error but `STORE_ERROR`").
- D-63's new accepted risk is in the ledger's residuals (TH-28) and matches `readServerState`.
- §5.6, §12's `warnings()` line, the using guide and SP-26 agree with D-58's amendment.

## Edits ready now (no decision)

A.

## Stop rule

Nothing here is for the action rule to fix (A is low, with no security consequence): **1 of 2**. A fresh `adversarial` review that finds nothing to fix makes the freeze candidate.
