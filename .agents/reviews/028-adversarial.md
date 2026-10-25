# Review 028: adversarial, eighth round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `9e984b7` (after plan 020). Read only.

## Checked

- **Baseline.** `check:spec` passes. The ledger stood at 1 of 2: review 027 (`change`, plan 020) found nothing to fix.
- **Fresh-context reviewer.** It had the adversarial brief and D-62 and D-63 named as the newest rules, with no access to `.agents/`, `learning/` or history. It found no one-actor attack around D-62 or D-63. It reproduced F1 with throwaway tests, then deleted them. This session reproduced F1 again (throwaway test, deleted) and read F2, F4 and F5 in the code.
- **D-62 and D-63, the questions put to the reviewer:**
  - Everyone who can make `team-state` absent (A11 with garbage or an unknown `v`, A2, an account-key holder) could already delete or withhold it.
  - A planted newest bundle needs the account key.
  - Contexts can't take turns, since the roster holds one entry per account.
  - No path reads `team-state` with older keys under a floor, unless the server withholds the newest wrap (B).
- **Pairs checked, nothing beyond accepted threats:**
  - A2 + A11 and A2 + A9 (TH-20, TH-39, TH-49).
  - A2 + A4: TH-50, and TH-05 for a new device served an older wrap and a matching older `team-state`.
  - A2 + A6 (TH-38); A7 + A11 and A8 + A11 (TH-45, TH-11).
  - A2 with a relayed link or transfer (TH-04, TH-21, TH-23, TH-49).
- **Not checked:**
  - the cc1 suite internals and the stream code;
  - vector correctness and the fuzz run;
  - `setOwners` edge cases;
  - concurrency between two owners beyond reading;
  - the browser adapter beyond reading.

## Findings

### A. One bad record stops the warnings and the phrase replacement for the whole account

- **Kind:** spec → code, overclaim. **Severity:** medium.
- **Actors:**
  - **One actor in practice:** an account-key holder with the session. A9 in the vault has both, and so does A7 with a signed-in device.
  - **A2 alone,** for the second half.
- **Disposition:** fix (small).
- **Where:**
  - `teamsWithForeignKeys` and `teamsWithOldRecoveryKey` (`src/account/recovery.ts:166-186`) call `openBundles` for every team of the account without catching. `openBundles` throws when a wrap that opens doesn't match its published record (`member-custody.ts:55`), or when that record fails its checks or is missing.
  - `warnings()` (`vault.ts:443-461`) and `confirmRecoveryPhrase` (`vault.ts:218-223`) call those two functions. `confirmRecoveryPhrase` commits the new recovery wrap first, then calls them.
  - What the docs promise instead: D-58 says one record no longer stops "the warnings"; TH-20 and the record-archive test say such a wrap "fails its team, not the account"; §5.6 says `confirmRecoveryPhrase` reports the teams re-keyed and those that failed.
- **Evidence (reproduced; throwaway test deleted):**
  - Setup: bob's account key and session plant, for a made-up team `zz`, a `member-keys` record that fails its checks and a wrap that opens under the account key.
  - `warnings()` throws `TRUST_FAILURE`. That hides `foreign-member-keys` and `recovery-key-mismatch`, the warnings meant to reveal this attacker.
  - `team-1` still opens `ready`.
  - `confirmRecoveryPhrase` replaces the phrase, then throws. `team-1` stays at member keys version 1, still carrying the old phrase's recovery key, and no report comes back.
  - The reviewer also showed the A2 half: the server withholds one team's `member-keys` record, and `confirmRecoveryPhrase` throws `MALFORMED_RECORD` after replacing the phrase.
- **Why it matters:** the user who replaces a leaked phrase gets an error after the replacement. A thief holding the old phrase can still prove re-keys for the teams left un-re-keyed (TH-41) until the user re-keys them; doing so with proof needs `oldPhrase` (D-49).
- **Fix:** in both functions, a team whose bundles fail their checks (a `ConvoyError` other than `STORE_ERROR`) stops only that team. The account's other teams carry on.
  - `teamsWithOldRecoveryKey` lists the team, so `rekeyTeams` tries it and reports it `failed`. `confirmRecoveryPhrase` then returns its report.
  - `warnings()` lists the team under `foreign-member-keys` (action `secureAccount`). That is accurate: only someone else's keys or a planted wrap get there.
- **Budget:** small (no state, fallback or duty; no new warning code). **Product cost:** none; the warnings and the report become what the docs already say.
- **Needs:** a line in D-58's Consequence saying where such a team is reported, then code with a test and its guard.

### B. The server picks which keys open `team-state` by withholding the newest wrap

- **Kind:** missing threat (availability). **Severity:** low. **Actors:** A2, with a forged record written earlier under keys the account later replaced (A7 or A9). **Disposition:** accept and document.
- **Where:** `readServerState` takes "the newest bundle" from the wraps the server serves (`anchors.ts:35,44`). If the server withholds the newest wrap and replays an archived forged `team-state` written under the older keys, that record counts again, and the result is `state_conflict`.
- **Evidence:** read.
- **Why accept:** the server can already deny service. The floor and the vault's anchor still bound the chain, so nothing moves back.
- **Fix:** D-63's accepted risks: "a server withholding the newest wrap chooses the older keys, and can replay a forged state written under them (availability, TH-28)". An edit.

### C. With a floor, `team-state` bounds nothing against the server

- **Kind:** simplification. **Severity:** none.
- **Where:** D-62's consequence says `team-state` "still bounds rollback above the floor for a context with no local anchor". The only actor who can roll the chain back is the server, and it can serve an older revision, or none.
- **Disposition:** goes with 026-F to the next `complexity` review. It is the same question.

### D. A stale comment on the clean-up

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** `src/account/member-custody.ts:265-267` still says the team state "is rewritten under the newest keys". Plan 020 deleted that rewrite (D-63, §6.8 step 4). Review 027's search missed it, because the comment says "team state", not `team-state`.
- **Fix:** "their wraps are deleted; a team state under them is absent and the next advance replaces it (D-63)".

### E. TH-20's "trusts what it holds" with a planted bundle that has no floor

- **Kind:** overclaim. **Severity:** low. **Disposition:** correct the text.
- **Where:** TH-20 says "a vault that never did trusts what it holds". With a planted newest bundle that has no floor, the vault holds no root at all, and `rekeyTeam` (`recovery.ts:126-127`) verifies the chain the server serves from version 1. §5.11 step 2 already says so (plan 020).
- **Fix:** TH-20: "… trusts what it holds, or, with a planted bundle that has no floor, the chain the server serves". An edit.

## Edits ready now (no decision)

B, D, E (text), and 027-A.

## Needs a decision

A: one line in D-58, then the code (recommended).

## Stop rule

A is a one-actor finding the action rule says to fix, so the count goes back to **0 of 2**. After a plan that fixes A, a `change` review and a fresh `adversarial` review that find nothing to fix make the freeze candidate.
