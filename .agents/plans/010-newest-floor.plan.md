# Plan 010: the floor is the newest trusted anchor (review 004 A, B, E, F), with C and D

## Context

Review 004 (`.agents/reviews/004-anchor-floor.md`):
- **A:** the floor counts only when a device has no other anchor, so an archived `team-state` below the floor wins (reproduced).
- **B:** the floor never advances, and a joiner without an invite anchor has none: each new device is a fresh first contact while `team-state` is withheld. The "carry, else fill" rule is written in five places.
- **E:** `joinTeam` ignores the anchor when keys exist. **F:** rotation fills a missing floor from one bundle only.
- **C:** a transfer is anonymous: whoever sees the request can seal keys to it (reproduced, with A2). **D:** three guides claim more than TH-04 for invite links.

**Decision (user):** one rule, D-50.

## Design (D-50)

- **Write:** a bundle's floor is the newest anchor the vault trusts when it writes the bundle:
  - creation: version 1;
  - join: the tip of the chain the vault verifies at join, from the invite anchor if given, else from version 1 (the first contact happens once, at join);
  - re-key and rotation: the highest (by version) of the team's bundles' floors, the local anchor and the `team-state` anchor opened with any of the team's bundles (a `team-state` that doesn't open is skipped, TH-46). Every bundle of the team gets that floor at a rotation (F).
- **Read (§6.1 step 1):** the newest bundle's floor counts as an anchor unless it is below the lowest other anchor. The fetch still starts from the lowest anchor: no extra download.
- **E:** `joinTeam` with an anchor when keys exist verifies the chain contains it (`TRUST_FAILURE`), writes nothing, and doesn't change the floor.
- No layout change, no vector change.

## Phases (one commit each)

1. **Spec:** D-50; D-48 Status and D-29 Consequence point to it; §3.8 step 4, §4.3, §4.4, §5.7 step 4, §5.9, §6.1 step 1, §6.4, §6.8 step 1; SP-07 text, Assumptions, Verification; TH-04, TH-05 and the index; key hierarchy `:153`, `:367`, `:405`. C: TH-49 (accepted, integration duty), index, TH-39, SP-02 Limit and Related threats, integration guide `:118`. D: integration guide `:103`, key hierarchy `:367`, using guide `:116`. Retired wording for the old rules.
2. **Code and tests:** `src/team/load.ts` (read rule), `src/account/recovery.ts` (`newestTrustedAnchor` replaces `trustedAnchor`), `src/account/rotation.ts` (per team, all bundles), `src/account/vault.ts` (`joinTeam`). Tests in `rollback.test.ts` (A, B1 join floor, Limit at join, E) and `account-rotation.test.ts` (floor advances at rotation and re-key; F). Prove each guard by weakening the rule.
3. **Notes:** gates, execution notes, review 004 marked done.
