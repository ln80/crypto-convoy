# Plan 018: a join keeps the vault's anchor; `secureAccount` knows the product's teams; a missing recovery wrap isn't a first setup (review 019 A, B, D, C, E)

## Context

Review 019 (`.agents/reviews/019-adversarial.md`), all reproduced, one actor each:

- **A (high).** The server withholds an existing member's wraps (absent under D-58); `joinTeam` without an anchor then verifies from version 1, ignoring the vault's own anchor, and moves that anchor up to a forged tip. New devices and contexts open the forged team.
- **B (high).** A device thief with the session copies a team's bundle and deletes its wrap: `secureAccount` lists teams from wraps that open, so it neither re-keys nor reports that team, and the stolen keys stay rostered.
- **D (medium, one actor with the user's help).** A session deletes the recovery wrap of an account in teams; the `recovery-not-set-up` warning leads to a credential-free first setup and unprovable re-keys in every team.
- **C, E (text).** An unproven re-key trusts the keys the server shows, like a join; `listDevices` still lists well-formed garbage; the Duties table omits the retry before `reconcile`; withholding a proven re-key delays its approval (TH-05).

## Gate (hardening direction)

Reviewed by review 020 (`.agents/reviews/020-design-plan-018.md`); its findings reshaped the first design toward fewer rules.

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-59 (A) | Free | One rule replaces the per-operation root lists: every vault verification roots on the vault's own anchor and the floor it holds, joins included; only `rekey`'s owner anchor replaces them, now also with no bundle (a refusal lifted) | Integrators: re-join only with an owner's anchor (a Duty). Users: a stuck join is repaired by `rekey` with an owner's anchor |
| D-60 (B) | Small | `secureAccount` takes optional `teamIds`; a listed team with no wrap that opens is reported failed; it is repaired by a proven `rekey` with an owner's anchor | Integrators: pass the product's team list. API: one optional input |
| D-61 (D) | Free | Deleted: "a first recovery setup takes none". Every recovery setup needs a current credential: the PIN when there is no recovery wrap | Users: the PIN once more at onboarding (one evaluation). An account with neither wrap needs a support restore (only tampering reaches it) |

## Design

### D-59: the vault's own anchor roots every vault verification

Every chain the vault verifies (open, export, leave check, re-key, join) contains the vault's own anchor for the team, when it has one, and the newest bundle's floor, when it holds one (D-54). A join adds the invite anchor; a chain that doesn't contain every root fails, and nothing is written. Only an owner's anchor given to `rekey` or `secureAccount` replaces the roots (D-54), and `rekey` with one now runs when the vault holds no bundle for the team: the repair for a join refused by a forged vault anchor, and for a team whose wraps were removed (review 020, 2 and 5). With no root at all (a device with no vault anchor, the wraps withheld), a join is a first contact (TH-04): the integration re-joins an existing member only with an owner's anchor.

### D-60: `secureAccount` reports the product's teams it can't re-key

`secureAccount({ ..., teamIds? })`: the teams the integration's product says the user belongs to (validated as ids, without duplicates). A listed team with no wrap that opens is reported in `failed`. The repair is `rekey(teamId, { phrase, anchor })` with an owner's anchor: a proven re-key, which owners' `reconcile` approves against the held keys' recovery key, ending the old ones (SP-12, SP-23). With no bundle, `oldPhrase` isn't checked against carried keys (the check was a typing guard; owners check the proof). `teamIds` comes through the integration, so the server controls it: it can only add reports (a team it adds is repaired only with an owner's anchor), and leaving one out is today's behaviour (review 020, 3). `warnings()` keeps reading the wraps (accepted: a deleted wrap with bait keys hides `foreign-member-keys` for that team until `secureAccount` with `teamIds`, review 020, 4).

### D-61: every recovery setup needs a current credential

"A first recovery setup takes none" is deleted (§5.6, D-35, D-41). With no recovery wrap, a setup needs the current PIN (one evaluation); with one, the current phrase or PIN, as before. So a deleted recovery wrap no longer leads to a credential-free setup, through the vault, whatever the server serves (review 020, 6). The re-keys of a setup with the PIN carry no proof; a user who kept the old phrase proves them with `rekey(teamId, { phrase, oldPhrase })` (review 020, 7). `recover` with no recovery wrap answers `RECOVERY_NOT_SET_UP`, not `STORE_ERROR`. Accepted (TH-45): a script holding the account key still writes wraps directly.

### Text (019-C, E)

- TH-04 and AS-06: an unproven re-key, like a join, trusts the keys the server shows; an existing member re-joining on a device with no vault anchor is a first contact.
- D-58 and §5.5: a device wrap that doesn't parse is left out; a session can still create well-formed ones (display only).
- Duties: retry a team `secureAccount` reported failed before the next `reconcile` as an owner; re-join an existing member only with an owner's anchor; pass `teamIds` to `secureAccount`.
- TH-05: a server withholding a re-key's record from owners delays its approval.

## Ripple

§5.6, §5.10, §5.11, §6.4, §12 (`secureAccount`, warnings); D-35, D-41, D-49 consequences if they state the setup rule; SP-07, SP-25 (Limit), SP-12 or SP-23 (the failed team); TH-04, TH-05, TH-45, TH-46; AS-06; integration Duties and guides; using guide.

## Phases (one commit each)

1. **Spec:** D-59 to D-61, the text items; `check:spec`. Design review 020 done.
2. **Code and tests:** `vault.ts` (`joinTeam`, `secureAccount`, `rekey`, `confirmRecoveryPhrase`, `recover`), `recovery.ts` (`rekeyTeam` with no bundle, listed teams); the test fixtures' onboarding passes the PIN; tests for each, with guards.
3. **Notes:** execution notes, ledger.

## Execution notes

- **D-59, as built:** `joinTeam` adds the vault's own anchor to the invite anchor as roots, in both branches; `rekeyTeam` runs with no bundle when given an owner's anchor (numbering from published records, the anchor the only root, the vault anchor replaced).
- **D-60, as built:** `secureAccount({ teamIds })`, checked with `checkId` and deduplicated (`productTeams`) before anything is written; teams listed with no wrap that opens after the rotation are passed to `rekeyTeams` as `missing` and reported failed. `rekey` with `oldPhrase` and no bundle signs unchecked (`recoverySigningKey`).
- **D-61, as built:** `confirmRecoveryPhrase` asks for `currentPin` whenever there is no recovery wrap, or no `currentPhrase`; `recover` with no recovery wrap answers `RECOVERY_NOT_SET_UP`.
- **Onboarding:** the README, the using guide, the package smoke test, the test fixtures and three tests that onboard directly now pass `{ currentPin }`; three budget tests count the extra evaluation; the TH-45 test now shows the refused setup and the single-record restore.
- **Tests:** `account-rotation.test.ts` (D-59: a refused forged re-join, the no-bundle repair), `secure-account.test.ts` (D-60: a deleted wrap reported, the proven repair ends the stolen keys; bad `teamIds`), `credential-rotation.test.ts` and `record-archive.test.ts` (D-61).
- **Guards:** the join without the vault anchor, `NOT_GRANTED` with no bundle, listed teams not reported, a free first setup, `STORE_ERROR` in `recover`: each fails a test. (A first guard run passed a file list as one zsh word and ran nothing; rerun with the files spelled out.)
- **Checks:** `typecheck`, `npm test` (756), `test:browser` (10), `check:spec`, `build`, `test:package` pass.
- **Integration (doconvoy e2eev2), breaking:** the first `confirmRecoveryPhrase` needs `{ currentPin }`; pass `teamIds` to `secureAccount`; re-join an existing member only with an owner's anchor.
