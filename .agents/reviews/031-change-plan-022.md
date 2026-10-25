# Review 031: change, plan 022

Mode: `change`. Scope: the `docs/` changes of plan 022 (`8ca53be`) and what they ripple into, against the code at `5ac2c31`. Read only.

## Checked

- **Baseline:**
  - `npm run check:spec` passes.
  - Ledger: 0 of 2, nothing open to fix. Still open, low: 011-A. For the next complexity review: 026-F, 028-C.
  - Plan 022's checks pass: 768 tests, browser 10, fuzz 30, build, package.
- **Properties → protocol:** each changed sentence is delivered by a §, and by code:
  - SP-12: reported for the teams where the vault holds keys; its new Limit; `teamsWithForeignKeys` goes through `accountTeams`.
  - SP-26: a store error while listing writes nothing, and a retry re-keys. Delivered by §5.6, §5.11 step 1, and the order in `confirmRecoveryPhrase` and `secureAccount`.
- **Threats → mechanism:**
  - TH-37's new attack (a team created under the account) and its acceptance: `secureAccount` with `teamIds` reports such a team (D-60).
  - TH-47: "reported" is limited to the teams where the vault holds keys.
  - Each matches the code, and the ledger records the residual.
- **Decisions → text.** I searched `docs/`, `README.md`, the guides and `src/` for:
  - the creator's `memberKeysVersion` (§6.3, §11's team creation row, the key hierarchy's "Creating a team");
  - `rekey-needed` and its advice;
  - `foreign-member-keys`;
  - the identity check (scope rule 3, the integration guide);
  - "lists before" in D-58's amendment.
- **Spec → code:**
  - `confirmRecoveryPhrase` derives the new key and lists the teams before its commit.
  - `secureAccount` lists `accountTeams` before the PIN check and the rotation. Neither of those writes to the store; the PIN check spends one evaluation (D-40).
  - `newTeamOps` writes the numbered version.
  - `advanceAnchor` checks a re-read anchor only from the chain's first record to its tip.
  - `warnings()` builds `foreign-member-keys` first and leaves those teams out of `rekey-needed`.
- **Plan notes:** no risk accepted on the plan's own beyond 030-C, which is in the ledger.
- **Not checked:** the doconvoy key store's identity check.

## Findings

### A. §12's `warnings()` line doesn't give `rekey-needed`'s answer

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** §12 (`protocol.md:884`) says "teams whose keys need re-keying". The using guide and the `VaultWarning` comment now give the answer: `rekey(teamId, { phrase })`, which takes the typed phrase's key (D-56, review 030 F). §12 gives the answer for the other warnings.
- **Fix:** "teams whose keys need re-keying (`rekey-needed`; answer: rekey with the phrase, D-56)".

## Not found

- A first recovery setup lists the teams after the PIN check and before its commit. A store error there costs one PIN evaluation per manual retry and writes nothing; the library never retries on its own (§5.1).
- A rotation re-wraps the teams `accountTeams` listed before it, so the teams listed and the teams re-keyed agree (D-58: a rotation re-wraps every wrap that opens).
- `createTeam`'s roster entry and the published record name the same version, so the chain's roster check (§4.5) holds.
- A conflict that re-reads a state below the chain loops at most three times and returns; the anchor stays local, as in §6.1 step 7.

## Edits ready now (no decision)

A.

## Stop rule

Nothing here is for the action rule to fix: **1 of 2**. A fresh `adversarial` review that finds nothing to fix makes the freeze candidate.
