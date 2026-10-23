# Plan 011: the floor comes only from the account's own records (review 005 A), with B

## Context

Review 005 (`.agents/reviews/005-plan-010.md`):
- **A (medium):** D-50 writes a bundle's floor from the highest of the bundles' floors, the local anchor and the `team-state` anchor. The local anchor is the one source a script or a thief on the device can write (A9, A7), and nothing checks it against a chain. A re-key or a rotation, `secureAccount` included, copies it into every bundle of the team: alone, the attacker makes the team unopenable on every new device; with the server, new devices open a forged team. Reproduced.
- **B (low):** the integration and using guides still say the transfer carries the invite anchor; §3.8 step 4 still says "the bundles' floors".

**Decision (user):** the recommended fix: the floor comes only from the bundles' floors and the `team-state` anchor (D-51, amending D-50).

**Design review:** review 005 A states the change and its alternative. It removes an input and adds none, state or fallback: a `team-state` that doesn't open is still skipped (TH-46), as under D-50. No separate `design` review.

## Design (D-51)

- **Write (re-key, rotation):** the floor is the highest (by version) of the team's bundles' floors and the `team-state` anchor opened with any of the team's bundles. The local anchor isn't a source.
- **Read:** unchanged (§6.1 step 1): the local anchor still counts as an anchor for this device's own opens.
- Creation and join: unchanged (version 1; the tip verified at join).
- No layout, vector or API change.

## Phases (one commit each)

1. **Spec:** D-51; D-50 Status points to it; §4.3, §5.9 (create member keys); SP-07 text and Verification; TH-05; key hierarchy `:405`; retired wording. B: integration guide `:119`, using guide `:84`, §3.8 step 4; retired wording.
2. **Code and tests:** `src/account/recovery.ts` (`newestTrustedAnchor` without the local anchor); review 005's two cases in `account-rotation.test.ts` (a local anchor written on the device doesn't reach the floor; the new device opens). Prove the guard by putting the local anchor back.
3. **Notes:** execution notes, review 005 and ledger updated.

## Execution notes

- **As built:** `newestTrustedAnchor` reads the bundles' floors and the `team-state` anchor only. The read rule (§6.1 step 1, `loadChain`) is unchanged.
- **Tests:** two in `account-rotation.test.ts`, from review 005's throwaway cases: a garbage local anchor stays out of the floor at a re-key and at `secureAccount`, and a new device opens the team; a local anchor naming a version the server forged doesn't reach the floor, and a new device served that version with `team-state` withheld refuses it (`chain_conflict`). Putting the local anchor back fails both.
- **Checks:** `typecheck`, `npm test` (712 tests) and `check:spec` pass.
- **No layout, vector or API change.** Integration (doconvoy e2eev2): nothing to change.
- **Course:** review 005 C done through maintain-course (local, gitignored).

