# Plan 012: the floor is the root of trust (review 006 B and C, review 007)

## Context

Review 006 (`.agents/reviews/006-adversarial.md`):
- **B (high):** a local anchor above the floor drops the floor (§6.1 step 1), so a record at the local anchor's version is trusted by its hash alone. A script in the origin, or someone with the device, with the server, opens a forged team; `advanceAnchor` then writes it into `team-state`, and `secureAccount` into the floor.
- **C (high):** a `teamStateKey` holder (the TH-20 attacker) writes a valid `team-state` with a forged anchor; the re-key in `secureAccount` makes it the floor. D-51's Consequence is wrong.

Review 007 (`.agents/reviews/007-design-d52.md`, design mode, fresh-context reviewer) checked the proposal (the floor always read; the floor moved only along a chain verified from it; rotation keeps floors) and found: the read cost is the steady state (A); an account key holder can still plant a floor (B); a forged `team-state` blocks every device with no remedy (C); a failed verification at a re-key is unspecified (D); floors fall behind (E); the server can make an older genuine floor the root (F).

**Decisions (user):** the floor as root (006 B, C); 007-A: advance the floor when the vault opens or exports a team; 007-B: `secureAccount` verifies from the device's local anchor; 007-C: a new reason, `state_conflict`, restored by support. D, E, F are edits.

## Design (D-52, superseding D-51 and amending D-50)

1. **Read (§6.1 step 1):** the **roots** are the newest bundle's floor and the local anchor (and the `team-state` anchor only for keys with no floor). The chain is fetched from the lowest root and must contain every root. The `team-state` anchor is then checked against the verified chain: below its first record, not followed; at a version the chain holds with another hash, `TRUST_FAILURE` (`state_conflict`); above its tip, `rollback`; otherwise it counts as an anchor.
2. **Advance (§5.8, §6.8 step 4):** when the vault opens or exports a team and the verified chain's tip is above the newest bundle's floor, it replaces that bundle's wrap with the tip as its floor (`replace`, archiving the old wrap), in the same batch as the clean-up when that runs. Best effort.
3. **Re-key (§5.9, §6.8 step 1):** the new floor is the tip of the chain verified from the newest bundle's floor alone; in `secureAccount` (§5.11), from this device's local anchor when it has one, else from the floor. If the verification fails, the current floor.
4. **Rotation (§5.7 step 4):** each bundle keeps the floor it carries.
5. **Store:** `replace` also takes a `member-keys-wrap` (§11, §12, scope rule 7).
6. Creation and join unchanged. No layout or vector change; one new reason (§9).

## Phases (one commit each)

1. **Spec:** D-52; D-51 Status (superseded), D-50 and D-48 Status, D-39 (replace); §4.3, §4.4, §5.7 step 4, §5.8, §5.9, §5.11, §6.1 steps 1–2, §6.8 steps 1 and 4, §9, §11, §12; SP-07, SP-26; TH-04, TH-05, TH-20, TH-46 and the index; scope rule 7 and the interfaces; key hierarchy; integration guide (cost table); retired wording. 006-D: §7.3 and TH-23 Limit. Review 006 and 007 files, ledger.
2. **Code and tests:** `src/team/load.ts` (roots, `state_conflict`), `src/errors.ts`, `src/account/recovery.ts` (floor from a verified chain), `src/account/rotation.ts` (carry), `src/account/member-custody.ts` (advance with the clean-up, on open and export), `src/account/vault.ts` (`secureAccount` root), the store ports and `MemoryRecordStore` (`replace` of a member keys wrap). Tests: review 006 B and C, review 007 B, the advance, a failed verification at a re-key, rotation carrying floors. Prove each guard.
3. **Notes:** execution notes, reviews and ledger.

## Execution notes

- **Read rule, as built:** `loadChain` passes the roots (the newest bundle's floor and the local anchor; `team-state` only for keys with no floor) to `verifiedChain`, and the `team-state` anchor as `state`; `verifyChain` checks `state` after the roots, and counts it for change reports when it lies on the chain.
- **Advance, as built:** `maintainBundles` replaces `dropReplacedBundles`. On a vault open it runs after the session loads, from the chain the session verified (no second download); on an export it verifies the chain itself (one download per export, from the floor). One batch: the `replace` of the newest wrap, and the clean-up when it applies.
- **Re-key, as built:** `verifiedFloor(current, root)` returns the tip of the chain verified from `root`, or `current` when that throws `TRUST_FAILURE`. No "never below the current floor" clause: verified from the floor, the tip is at least the floor; verified from the local anchor (`secureAccount`), a planted floor above it must not win.
- **Rotation** re-wraps each bundle as it is, floor included; it fetches nothing.
- **Tests:** `rollback.test.ts` (a forged local anchor above the floor, refused and not spread; a forged `team-state`, `state_conflict` then `rollback`, and support's restore; the receiving context now refuses with `rollback`, since the export moved the floor), `account-rotation.test.ts` (rotation keeps floors, a vault open and a re-key move them, an export moves them, a failed verification keeps the floor, a planted floor replaced by `secureAccount`; review 005's two cases adapted). D-50's two rotation tests were replaced.
- **Guards:** weakening each rule fails a test: the D-50 read rule back, `state_conflict` ignored, rotation dropping floors, no advance, a re-key without verification, `secureAccount` from the floor, a failed verification dropping the floor.
- **Checks:** `typecheck`, `npm test` (716 tests), `check:spec`, `build` and `test:package` pass.
- **No layout or vector change.** New: the reason `state_conflict`; `replace` of a `member-keys-wrap` (a server contract change: integrations must accept it). Integration (doconvoy e2eev2): its key store must allow `replace` on member keys wraps, archiving the old one.
- **Not changed after all:** SP-26, TH-04 and §6.8 step 4 (the clean-up now runs in §5.8 step 3's batch, its text still holds).
- **Left:** the local course (maintain-course); review 006 A and E.

