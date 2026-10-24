# Review 016: adversarial, fourth round

Mode: `adversarial`, with a fresh-context reviewer, the first under the [hardening direction](../guides/direction.md). Scope: `docs/`, `src/` and `test/` at `7ffd023` (after plan 016, the acceptances of review 013, and review 015). Read only.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: 1 of 2 toward the freeze (review 015, `complexity`, nothing to fix); open: 011-A only.
- **Fresh-context reviewer.** A `general-purpose` subagent with the adversarial brief (one-actor attacks first), `docs/`, `src/` and `test/`; told that accepted risks and the integration's Duties table aren't new. It returned five candidates and reproduced A, B and C with throwaway tests kept outside the repository.
- **This session's pass,** on what changed since review 013 (D-55, D-56, scope rule 3, the `enroll` share) and on inbox, submission and link paths: nothing new. It reran the reviewer's tests, read them, and extended A with a second-device case (`second-device.test.ts`, outside the repository).
- **Not checked:** the `cc1` internals, fuzzing, the IndexedDB adapter in real browsers, concurrency between devices, metadata and timing.

## Findings

### A. Change reports appear once per account, and never in a split layout

- **Kind:** overclaim, spec → code. **Severity:** high. **Actors:** a stolen owner key (A6) alone. **Disposition:** fix.
- **Where:** §6.1 step 3 ("for every record newer than the highest anchor"); `src/team/chain.ts:103-114` (the highest of every root, the floor included, and the `team-state` anchor); `src/account/member-custody.ts:215-230` (the export moves the floor to the tip before sealing it); SP-15 ("every newly approved member key is reported on every member's client"), D-44 ("every access change since the client last verified the team"), TH-17 (detection is the mitigation).
- **Evidence (reproduced):** a stolen owner key admits carol (v3) and removes her (v4) between two opens.
  - In the vault's context, the next open reports both. But a second device of the same account, opening after the first, reports nothing: the first device moved the floor and `team-state`, which count as already seen.
  - In a split layout, nothing is ever reported: the export verifies the chain, moves the floor to its tip, and seals that floor, so the receiving session starts at the tip.
- **Why it matters:** detection is the whole mitigation of TH-17; a split layout loses it entirely, and every other device of an account loses it once one device has looked.
- **Fix proposed:** reports cover the records newer than **this device's** local anchor (the sessions' `LocalKeyStore` anchor); with none (a fresh device or context), newer than the highest root, as today. The floor and `team-state` stay roots for verification; they stop counting as "seen". Budget: **small** (one rule changes which anchor bounds the report; no state, no API). Product cost: none for integrators; users see each change once per device or context, which is what SP-15 says.
- **Needs:** a decision (protocol-change; §6.1 step 3, D-44).

### B. A session alone plants a private record that blocks the remedy, and no restore removes it

- **Kind:** missing threat, wrong claim. **Severity:** high (a documented procedure leaves a compromised user compromised). **Actors:** a session (A11) alone, so also A7 or A9. **Disposition:** fix.
- **Where:** `src/account/rotation.ts:31-43` (a rotation opens every `member-keys-wrap` the server lists, and fails on one); `src/account/member-custody.ts:23-40` (`openBundles` throws on any wrap that doesn't open; `openSession` catches only `TRUST_FAILURE`); `src/account/vault.ts` (`warnings`, `confirmRecoveryPhrase` through `teamsWithOldRecoveryKey`); `src/testing/memory-record-store.ts:66-71, 83-97` (a restore needs an archived generation); TH-46 and SP-26 ("support restores it"), TH-10 ("a support restore undoes it").
- **Evidence (reproduced):** a session creates a garbage `member-keys-wrap` under a new identity at the current account key version: `secureAccount`, `rotate` and `warnings()` fail with `MALFORMED_RECORD`; `confirmRecoveryPhrase` stores the new phrase, then fails before re-keying. With the real `teamId`, `openTeam` fails on every device. The identity is new, so `restore` has nothing to bring back, and `restoreVersion` of the current version doesn't touch it. A variant (a garbage recovery wrap at version a+1) makes every rotation `STALE_VERSION`; restoring the current version does clear that one.
- **Fix proposed:**
  1. A `member-keys-wrap` that doesn't open is treated as absent, as if withheld: the vault's account-wide operations (rotation, warnings, re-keys) and `openBundles` skip it, and an account-wide operation reports its team as failed. Only the account key opens a wrap, so a wrap that doesn't open was never the account's; one that opens but doesn't match its published keys stays `TRUST_FAILURE` (`key_mismatch`).
  2. Server rule (scope rule 7, §11): an `account-key-wrap` or `member-keys-wrap` is created only at the account's current version, or in the batch that switches to the next one; the kit enforces it.

  Budget: **small** (one skip rule replacing a failure path; one server condition; no state, no API). Product cost: a server condition to add; users stop needing support for this case.
- **Needs:** a decision (protocol-change; §4.3, §5.7, §11, TH-46).

### C. One malformed `member-keys` record stops a team for every member

- **Kind:** missing threat. **Severity:** low by the rubric (availability), but team-wide and permanent. **Actors:** any account allowed to join (before any approval), or a session on any member's account. **Disposition:** fix (a small change exists).
- **Where:** `src/team/load.ts:44-46` (`verifiedChain` parses every `member-keys` record of the team, and one bad signature throws); `src/team/owner.ts:154-170` (owners' lists, the same); `src/records/member-keys.ts:90`; scope rule 3 and §11 now forbid deleting public records (review 013 F), so nothing removes it; TH-25 names only the server.
- **Evidence (reproduced):** `mallory`, a joiner, publishes her next `member-keys` record with a garbage signature: every member, owners included, becomes `unverified` (`bad_signature`), and owners' overviews fail, so no owner operation can run.
- **Fix proposed:** readers treat a `member-keys` record that fails its checks as unpublished: they leave it out of the team's list. A roster entry naming it then fails as an unpublished record would (`key_mismatch`), so nothing that could be used is accepted; one bad record no longer stops the others. Optionally the server verifies the self-signature (rule 8, defence in depth). Budget: **small**. Product cost: none.
- **Needs:** a decision (protocol-change; §4.2, §6.1, TH-25).

### D. Resetting other devices removes the anchors that would catch a planted floor

- **Kind:** stale text. **Severity:** low. **Actors:** an account-key holder (A7, A9) with the server (A2). **Disposition:** accept and document.
- **Where:** TH-20's residual and D-54 ("a vault that never verified the team on this device still trusts the floor it holds"); the integration guide asks to clear the account's local state on other devices after `secureAccount`.
- **Evidence (read):** after that reset, every device is fresh, so a planted floor with a matching forged chain is trusted everywhere until an owner's anchor is given. Already accepted (server-controlled history); the guide doesn't say that the reset widens it.
- **Fix proposed:** one sentence in TH-20's disposition and the integration guide: after `secureAccount`, re-key or open each team on the securing device before resetting the others, so its vault anchor is current; a team reported failed is repaired with an owner's anchor.
- **Needs:** an edit.

### E. A planted bundle survives a rotation and can be self-approved after a failed re-key

- **Kind:** combined attack. **Severity:** low. **Actors:** an account-key holder with the session, then a re-key that fails. **Disposition:** accept and document.
- **Where:** `src/account/rotation.ts:31-43` (re-wraps every wrap that opens); D-47 (an owner's own `reconcile` approves keys its session holds); `src/account/recovery.ts` (`foreign-member-keys` no longer flags held keys).
- **Evidence (read):** keys the attacker made and wrapped with the old account key are carried into the new version; if that team's re-key in `secureAccount` fails, the owner's next `reconcile` may approve them. D-47's consequence covers the account-key holder; the failed-retry window isn't named.
- **Fix proposed:** one sentence in §5.11 step 3 and the using guide: retry a failed team before the owner's next `reconcile`.
- **Needs:** an edit.

## Already accepted, not new

The reviewer listed and set aside: forged transfers and substituted requests (TH-39, TH-49), relayed invite and repair anchors (TH-04), items and inboxes rewritten by a key holder with the server (TH-50), a rewritten recovery key (TH-12), garbage `team-state` and deleted wraps (TH-46), a deleted recovery wrap (TH-36, TH-45), bait keys (TH-47), retired versions on stateless devices (TH-05, SP-19), and replayed local state (TH-05).

## Edits ready now (no decision)

D and E.

## Stop rule

A and B are high, and A, B and C are for the action rule to fix: the count goes back to **0 of 2**. All three fixes are in the small class; none adds state.
