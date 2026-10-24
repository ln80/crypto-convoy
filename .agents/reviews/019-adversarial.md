# Review 019: adversarial, fifth round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `f0568ad` (after plan 017 and review 018). Read only.

## Checked

- **Baseline.** `check:spec` passes; ledger 1 of 2 (review 018 clean); nothing open to fix.
- **Fresh-context reviewer** with the adversarial brief and the recent changes named (D-55 to D-58); four repros, kept outside the repository (`scratchpad/repro3/`), rerun and read by this session: all reproduce. This session's own pass found A independently.
- **Not checked:** the `cc1` internals, `stream.ts` edge cases, parsers beyond spot checks, fuzzing, timing.

## Findings

### A. `joinTeam` on an existing member re-roots it on a forged chain

- **Kind:** forgeable input, wrong claim. **Severity:** high. **Actors:** the server (A2) alone, when the integration calls `joinTeam(teamId)` without an anchor for an account already in the team (§6.4 says that is harmless). **Disposition:** fix.
- **Where:** `src/account/vault.ts:470-475` (returns early only when bundles open; otherwise verifies from version 1, without the vault's own anchor); `src/account/member-custody.ts:189-192` (`recordVaultAnchor` moves up to any higher anchor). §6.4, TH-04 ("limited to the join"), SP-07 / D-54.
- **Evidence (reproduced):** the server withholds the account's wraps (absent under D-58) and serves a forged chain; `joinTeam` makes new keys with the forged tip as floor and vault anchor (real v3 replaced by forged v4). A new device and a new receiving context then open the forged team `ready` (owners `["mallory"]`), with no report; only a context with its own real anchor sees `chain_conflict`.
- **Fix proposed:** `joinTeam` verifies from the vault's own anchor too, when it has one (the roots rule of D-54); with one, a chain that doesn't contain it fails the join. Budget: small. Needs a decision.

### B. `secureAccount` silently skips a team whose wrap was deleted, leaving stolen keys rostered

- **Kind:** missing threat. **Severity:** high (a documented remedy leaves a compromised user compromised). **Actors:** a device thief with the session (A7), one actor in practice; or the server alone, for the loss of the team. **Disposition:** fix.
- **Where:** `src/account/rotation.ts:33-38`, `src/account/recovery.ts:85-89, 120-140` (an account's teams are those with a wrap that opens); TH-46 (support restore), SP-12.
- **Evidence (reproduced):** the thief copies the bundle, then deletes the team's wrap through the session. `secureAccount` returns `{ rekeyed: [], failed: [] }`, `warnings()` is empty, the team shows `not-joined`, owners' `reconcile` does nothing (bob still holds), and after a later rotation the stolen keys open the new team key. A restore of the old account key version would bring the thief back.
- **Fix proposed (needs design):** the vault needs a list of the account's teams that doesn't come from wraps a session can delete: for example the vault's own anchors (it keeps one per team it verified), with `secureAccount` reporting a team it has an anchor for but no wrap as failed. Budget: small to costly depending on the source; a design review decides.

### C. A key swap on an unproven re-key is a second first contact

- **Kind:** overclaim. **Severity:** medium (a human approval, and the member goes `unverified`). **Actors:** A2 alone, with an owner's routine approval. **Disposition:** accept and document (server-controlled history group, D-11).
- **Where:** TH-04 ("limited to the join"); AS-06 and D-32 assume the owner can check the keys out of band, but no API shows a member its own keys hash or fingerprint.
- **Evidence (reproduced):** the server serves its own record at the re-keyed version; an approved member's entry opens with the server's key; for another owner's re-key, the new owner key is the server's, reported only as "rekeyed".
- **Fix proposed:** TH-04 and AS-06 say an unproven re-key, like a join, trusts the keys the server shows; recommend proven re-keys (with the phrase). An edit.

### D. Deleting the recovery wrap of an account in teams steers the user into unprovable re-keys

- **Kind:** combined attack, wrong premise. **Severity:** medium. **Actors:** a session (A11) alone, then the user following the `recovery-not-set-up` warning. **Disposition:** fix (one actor; review 013 D's hardening, declined then as needing an open vault, is reachable by A11 alone with the user's help).
- **Where:** `src/account/vault.ts:206-211` (`old === null` is a first setup, no credential); SP-25's Limit and D-35 ("the account can't be in a team before").
- **Evidence (reproduced):** after the deletion, the warning leads to a first setup; every team is re-keyed unproven, and even `secureAccount` stays unproven (held keys carry the old recovery key; `secureAccount` has no `oldPhrase`).
- **Fix proposed:** an account with team wraps but no recovery wrap reports `recovery-missing` (action: support restore) instead of `recovery-not-set-up`, and a credential-free setup is refused then. Budget: small. Needs a decision.

### E. Low

- `listDevices` lists well-formed garbage device wraps a session creates: display only; D-58's "never a device of the account's" overclaims. Edit.
- The Duties table says to run `reconcile` at every owner session, but not to retry failed teams first (§5.11 step 3). Edit.
- A server withholding a proven re-key in owners' lists keeps stolen keys rostered (A2 with A7/A9): TH-05-class delay, not stated for re-keys. Edit (TH-05).

## Stop rule

A, B and D are one-actor findings to fix: **0 of 2**.
