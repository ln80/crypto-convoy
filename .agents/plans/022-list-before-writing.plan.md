# Plan 022: list before writing; `createTeam`'s roster version (reviews 030 A, B; accept 030 C; text and edits for 029 A, 030 D–G)

## Context

Review 029 (`change`, plan 021) found nothing to fix and left one edit. Review 030 (`adversarial`, fresh context) found no critical or high finding. Two of its findings are for the action rule to fix:

- **030-A** (medium; A2 alone, or a transient store failure). Both functions write before they list the teams they re-key, so a store error leaves them half done:
  - `confirmRecoveryPhrase` replaces the recovery wrap and clears the pending phrase. Its list of teams to re-key then throws `STORE_ERROR`: no team is re-keyed, no report comes back, the old phrase is refused, and a retry is `WRONG_CREDENTIAL`.
  - `secureAccount` rotates, then lists the account's teams.
- **030-B** (low; A11 alone, or any leftover `member-keys` record). `createTeam` numbers its keys above any published version (§5.9), but writes `memberKeysVersion: 1` in the roster. The team can never verify, and its id is used up.

The others:
- **030-C** (medium, overclaim) is accepted. The vault reports keys it didn't make only for teams where it holds a wrap. A session can create a team under the account with its own keys, and nothing reports it.
- The rest is text, or one-line code:
  - **029-A:** a failing team is also listed under `rekey-needed`.
  - **030-D:** the conflict path refuses a `team-state` below the chain.
  - **030-E:** `foreign-member-keys` also names a withheld record.
  - **030-F:** `rekey-needed` should say to pass the phrase.
  - **030-G:** the identity check isn't in the server contract.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| 030-A | Small | Two reorderings: list before the first write. No new state, fallback, duty or error | None. Users: a store error during a phrase replacement or `secureAccount` writes nothing, and a retry works |
| 030-B | Small | One field (the roster's version), one sentence in §6.3 | None |
| 030-C | Small (text) | TH-37, TH-47, SP-12 (a Limit), a ledger residual | None. The integration's `teamIds` in `secureAccount` already reports such a team (D-60) |
| 029-A, 030-D | Small (code) | One filter in `warnings()`; one condition in `advanceAnchor` | None |
| 030-E, F, G | Small (text) | Warning texts in the using guide and `VaultWarning`; a sentence in scope rule 3 | Integrators: none new. The identity check is already in the integration guide |

Reach: unchanged. API: no change.

## Design

### 030-A: list before writing

- **`confirmRecoveryPhrase`:**
  - Before the commit, it derives the new phrase's public key from the pending wrap. That key doesn't depend on the commit.
  - It then lists the teams to re-key (`teamsWithOldRecoveryKey`).
  - Only then does it replace the recovery wrap, clear the pending phrase, and run `rekeyTeams`, which reports each team's failure.
  - A `STORE_ERROR` while listing writes nothing and keeps the pending phrase, so a retry works.
- **`secureAccount`:**
  - It lists the account's teams (`accountTeams`) before the rotation.
  - A rotation re-wraps every wrap that opens without changing which teams they name (D-58), so the list before and the list after are the same.

§5.6 and §5.11 gain a sentence: "the teams are listed before anything is written; a store error then writes nothing". The decision is D-58's amendment, extended to port failures. There is no new D-: the rule is the §8 spirit of checking before writing, applied to two operations.

### 030-B: the roster takes the numbered version

`newTeamOps` writes the roster entry with the `memberKeysVersion` its keys were numbered with. §6.3 step 1 becomes: "the vault creates the creator's member keys (§5.9), at the next version: 1 unless keys were published under the account for that team id". The team's version 1 is still the creator's, and the chain checks it as for any other roster entry.

### 030-C accepted

- **TH-37:**
  - **Attack:** a session creates a team under the account, with its own keys as the owner's, and invites people as the user.
  - **Disposition:** keys the vault didn't make are reported for the teams where it holds keys. `secureAccount` with the product's `teamIds` reports a listed team with no wrap that opens (D-60). The rest is accepted: a session acts as the user in the product.
- **TH-47 and SP-12:** "reported" is limited to the teams where the vault holds keys. SP-12 gains a Limit.
- **Ledger:** a residual (A11; a team created or keys published under the account where the vault holds no keys go unreported; revisit when the store can list an account's published keys across teams).

### Edits

- **029-A:** `warnings()` leaves the teams of `foreign-member-keys` out of `rekey-needed`.
- **030-D:** `advanceAnchor`'s conflict path checks the re-read anchor only at or above the chain's first record. Below it, the anchor isn't followed (§6.1 step 2).
- **030-E:** the `VaultWarning` comment and the using guide say three things:
  - `foreign-member-keys` can also mean the server didn't serve the account's published keys;
  - a team `secureAccount` then reports failed with a planted wrap needs support (TH-20);
  - the "someone holds the session" reading is the likely one, not the only one.
- **030-F:** the using guide and the `VaultWarning` comment: answer `rekey-needed` with `rekey(teamId, { phrase })`, which takes the typed phrase's key and never the stored one (D-56).
- **030-G:** scope rule 3 gains "store a record only under the key its identity fields name", which D-58's rotation relies on. The integration guide already says it.

## Ripple

- **Protocol:** §5.6, §5.11, §6.1 step 7 (below the chain on conflict), §6.3.
- **Scope:** rule 3.
- **Threats and properties:** TH-37, TH-47, SP-12, SP-26 (the phrase replacement's report).
- **Decisions:** D-58 (the amendment covers port failures before a write).
- **Guides and comments:** the using guide; the `VaultWarning` comment.

## Phases (one commit each)

1. **Spec.** 030-A's sentences, §6.3, 030-C's acceptance, and the texts of 030-D, E, F, G; run `check:spec`. No design review: no input, fallback or state is added, and review 030 proposed each fix.
2. **Code and tests.**
   - **Code:**
     - `vault.ts`: `confirmRecoveryPhrase` and `secureAccount` list before writing; `warnings()` filters foreign teams out of `rekey-needed`; the `VaultWarning` comment.
     - `member-custody.ts`: the roster version in `newTeamOps`.
     - `anchors.ts`: the conflict condition.
   - **Tests:**
     - `credential-rotation.test.ts` or `record-archive.test.ts`: one `member-keys` read fails during `confirmRecoveryPhrase`. Nothing is written, the old phrase still works, and the retry re-keys and reports.
     - `secure-account.test.ts`: the same for `secureAccount`'s listing.
     - `secure-account.test.ts` or a team test: keys published under the account before `createTeam`. The team opens `ready`, and its roster names the numbered version.
     - `record-archive.test.ts`: `rekey-needed` doesn't list a failing team.
     - `rollback.test.ts`: on a conflict, a re-read `team-state` below the chain is left alone.
   - **Guards:** each fix reverted fails its test.
3. **Notes.** Execution notes, then a `change` review and a fresh `adversarial` review.

## Execution notes

(empty)
