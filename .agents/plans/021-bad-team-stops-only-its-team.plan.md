# Plan 021: a team whose bundles fail stops only that team (review 028 A; text for 027 A, 028 B, D, E)

## Context

Review 027 (`change`, plan 020) found nothing to fix. Review 028 (`adversarial`, fresh context) found no critical or high finding, and one finding the action rule says to fix:

- **028-A** (medium). The actor is one in practice: an account-key holder with the session (A9 in the vault, or A7 with a signed-in device). A2 alone causes the second half.
  - **Cause:** `teamsWithForeignKeys` and `teamsWithOldRecoveryKey` (`src/account/recovery.ts`) call `openBundles` for every team of the account, with no catch. A wrap that opens but doesn't match its published record throws. So does a published record that fails its checks or is missing.
  - **`warnings()`** throws, which hides `foreign-member-keys` and `recovery-key-mismatch`.
  - **`confirmRecoveryPhrase`** replaces the phrase, then throws. No team is re-keyed and no report is returned, although §5.6 promises one.
  - **Docs contradicted:** D-58 ("the warnings" are no longer stopped by one record), and TH-20 and the record-archive test ("fails its team, not the account").

The rest is text and one test:
- **027-A:** fuzz the revision reader.
- **028-B:** accept that a server withholding the newest wrap chooses the older keys for `team-state`.
- **028-D:** a stale comment on the clean-up.
- **028-E:** TH-20 on a planted bundle with no floor.

028-C goes, with 026-F, to the next `complexity` review.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-58 amended (028-A) | Small | One catch per team in two existing loops. No new state, fallback, duty, error or warning code | None. Users: the warnings and `confirmRecoveryPhrase`'s report name the failing team instead of failing for the account |
| 028-B | Small (text) | An accepted risk in D-63 | None |
| 027-A, 028-D, 028-E | Small (text, test) | A fuzz entry, a comment, a TH-20 clause | None |

Reach: unchanged. API: no change. `confirmRecoveryPhrase` already returns `{ rekeyed, failed }`, and `foreign-member-keys` already exists.

## Design

### D-58 amended: a team whose bundles fail stops only that team

When the vault lists a team's bundles for every team of the account, it does so in three places: the warnings, the teams `confirmRecoveryPhrase` re-keys, and `secureAccount`. A team whose bundles fail their checks then stops only that team. The failing cases are:
- a wrap that opens but doesn't match its published record;
- a published record that fails its checks, or is missing.

That is any `ConvoyError` other than `STORE_ERROR`, which still stops the call, since it isn't about one team's records.

Where the failing team is reported:
- **`confirmRecoveryPhrase`** (and every caller of `teamsWithOldRecoveryKey`) counts it among the teams to re-key. `rekeyTeams` tries it and reports it in `failed`. The user retries it with `rekey`, or repairs it with an owner's anchor, as for any failed team.
- **`warnings()`** lists it under `foreign-member-keys` (action `secureAccount`). The label is accurate: only keys or a wrap the account's vault didn't make, or a server withholding the account's published record, can get a team there. `secureAccount` already reports such a team `failed` (`rekeyTeams` catches per team).

The rest of the account's teams carry on.

Rejected:
- **A new warning code for a team that fails:** it is new public API for a case that `foreign-member-keys` already describes, and that has the same remedy.
- **Leaving the failing team out of the lists:** the user would never learn of it, and `confirmRecoveryPhrase` would report the phrase replaced with that team silently keeping the old recovery key.

### Text and test

- **028-B:** D-63's accepted risks gain one sentence: a server withholding the newest wrap chooses the older keys, and can replay a forged `team-state` written under them. This is availability only, like TH-28; the floor and the vault's anchor still bound the chain.
- **028-D:** the `maintainBundles` comment (`src/account/member-custody.ts`): "their wraps are deleted; a team state under them is absent, and the next advance replaces it (D-63)".
- **028-E:** TH-20: "… a vault that never did trusts what it holds, or, with a planted bundle that has no floor, the chain the server serves".
- **027-A:** a `team-state revision` entry in `test/support/parsers.ts`, so `readTeamStateRevision` is fuzzed with the other parsers.

## Ripple

- **Decisions:** D-58 (an amendment: where such a team is reported), D-63 (the accepted risk).
- **Threats:** TH-20.
- **Protocol:** §5.6, if it says how failed teams are reported; §12's `warnings()` line.
- **Properties:** SP-26's verification (the record-archive test now covers the warnings and `confirmRecoveryPhrase`).
- **Guides:** the using guide, if it describes `foreign-member-keys`.

## Phases (one commit each)

1. **Spec.** The D-58 amendment, D-63's accepted risk and the TH-20 clause; run `check:spec`. No design review: the change is small, adds no input or fallback, and review 028 proposed it.
2. **Code and tests.**
   - **Code:**
     - `recovery.ts`: one helper that opens a team's bundles and returns the team as failing on a `ConvoyError` other than `STORE_ERROR`. `teamsWithForeignKeys` and `teamsWithOldRecoveryKey` list such a team.
     - The `member-custody.ts` comment.
     - The `parsers.ts` entry.
   - **Tests:** in `record-archive.test.ts`, extend the TH-20 test, or add one beside it. A planted mismatched wrap in another team id, and a published record the server withholds:
     - `warnings()` returns, with that team under `foreign-member-keys`.
     - `confirmRecoveryPhrase` returns `{ rekeyed: ["team-1"], failed: [that team] }`.
     - `team-1`'s new keys carry the new recovery key.
   - **Guard:** remove the catch, and the test fails.
3. **Notes.** Execution notes, then a `change` review and a fresh `adversarial` review toward the stop rule.

## Execution notes

- **D-58 amended, as built:** `teamBundles` (`recovery.ts`) wraps `openBundles` and returns null on any `ConvoyError` except `STORE_ERROR`.
  - `teamsWithForeignKeys` lists such a team.
  - `teamsWithOldRecoveryKey` lists it too, so `rekeyTeams` reports it `failed`.
  - `secureAccount` already caught errors per team, and is unchanged.
- **Text:**
  - D-58's status and amendment; D-63's accepted risk (028-B); TH-20, its planted bundle with no floor (028-E) and its account-wide wording.
  - §5.6, §12's `warnings()` line, the using guide, and SP-26's verification.
- **028-D:** the `maintainBundles` comment.
- **027-A:** the fuzz parser for `team-state` reads the revision first, as `readServerState` does; the fuzz project passes (30).
- **Tests:** `record-archive.test.ts`, two cases. In each, the account's other team is re-keyed, `warnings()` lists the failing team under `foreign-member-keys`, and `confirmRecoveryPhrase` reports it `failed`.
  - A planted mismatched wrap in `team-1`: that team still opens `key_mismatch`.
  - A withheld published record in `team-2`.
- **Guard:** removing the catch fails both tests.
- **Checks:**
  - `typecheck`, `check:spec`, `test:browser` (10), `build`, `test:package` and the fuzz project pass.
  - `npm test` passes (764). Its first run had two unit smoke tests time out near 5 s while the machine was loaded. Both pass alone, in the unit project, and in a full rerun.
- **Integration (doconvoy e2eev2):** no change. `foreign-member-keys` may now name a team whose published record the server didn't serve.
