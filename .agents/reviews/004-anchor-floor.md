# Review 004: anchor floor and transfers, round 4

Scope: `docs/` and the matching `src/` at `dbe7394` (after plan 009), reviewed with the [spec-review](../workflows/spec-review.md) workflow. Goals: consistency, hardening, less complexity. Discussion first: nothing here is planned yet.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Last review: 003 (all its findings closed by plan 009).
- **Decisions since review 003:** D-48 (anchor floor), D-49 (proof by the carried phrase), read against §3.8, §4.3, §4.4, §5.7, §5.9, §6.1, §6.4, §6.8, SP-07, TH-04, TH-05, TH-46, the key hierarchy, the using and integration guides. D-45 to D-47 were checked in review 003.
- **Code paths:** `src/team/load.ts` (`loadChain`), `src/team/anchors.ts`, `src/team/receiver.ts`, `src/records/transfer.ts`, `src/account/recovery.ts` (`rekeyTeam`, `trustedAnchor`), `src/account/rotation.ts`, `src/account/vault.ts` (`joinTeam`, `rekey`), `src/account/member-custody.ts` (`exportBundles`, clean-up).
- **Actors × operations:** A2 and A11 against `joinTeam`, `exportTeamKeys` and the receiver's `openTeam`; A2 against `openTeam` on a new device.
- **Not re-read this round:** the properties and threats untouched by plan 009 (review 003 found no divergence there, and plan 009 didn't change them).
- **Double-check:** A and C were reproduced with a throwaway test (`test/security/zz-review-004.test.ts`, deleted after the review). B, D, E and F are read from the code and the text quoted below.

## Findings

### A. An older `team-state` is followed even when the floor is above it

- **Kind:** hardening (accepted residual larger than needed). **Severity:** low to medium.
- **Where:** §6.1 step 1, D-48 ("a device uses the floor only when it has no local anchor and no readable `team-state`"), `src/team/load.ts:27-29`; plan 009's execution notes accepted it.
- **Evidence (reproduced):** bob joins without an invite anchor; the team reaches version 4; bob re-keys, so his bundle's floor is filled with version 4. A new device of bob's is served an archived `team-state` revision (anchor version 2) and a chain cut at version 3: it opens `ready` at version 3. The floor would have refused it (`rollback`).
- **Fix proposed:** count the floor as an anchor whenever it is above every other anchor (not only when there is none). The fetch still starts at the lowest anchor, so there's no extra download, which was D-48's reason to reject "the floor on every open". One rule change in §6.1 step 1 and `loadChain`; one test.
- **Needs:** a decision (small). Pairs with B.

### B. The floor never moves forward, and a joiner without an invite anchor has none

- **Kind:** hardening and simplification. **Severity:** medium (B1), low (B2).
- **Where:** D-48, §4.3, §5.7 step 4, §5.9, §6.4, §6.8 step 1; `rekeyTeam`, `rotateAccount`, `joinTeam`.
- **Evidence:**
  - **B1.** `joinTeam` without an anchor writes no floor (`vault.ts:405-409`). Each new device of that member, while the server withholds `team-state`, is a fresh first contact: the server gets one more chance to show a forged team per device, until the member's first re-key or rotation (the TH-04 Limit test in `rollback.test.ts` shows it).
  - **B2.** Once set, the floor is only carried: a creator's stays at version 1, a joiner's at the invite anchor, forever. With A's fix, a floor bounds rollback only if it is recent.
  - The rule "carry the newest bundle's floor, else fill it from the local anchor, else from `team-state`" is written in five places (D-48, §4.3, §5.7, §5.9, §6.8) with two branches.
- **Fix proposed:** one rule: **a bundle's floor is the newest anchor the vault trusts when it writes the bundle**: the highest of the carried floor, the local anchor and the `team-state` anchor. At join, the vault verifies the served chain (from the invite anchor if given, else from version 1: the first contact moves from the first open to the join, where it happens once) and takes its tip as the floor. Re-keys and rotations then advance it.
  - Cost: `joinTeam` without an anchor downloads the chain once, which the first open does anyway; a join to a team with no chain fails at join instead of at open. No layout change.
  - Gain: every member has a floor from join on; the floor is at most one re-key or rotation old; one rule instead of "carry, else fill".
- **Needs:** a decision.

### C. Missing threat: a transfer is anonymous, so whoever sees the request can seal keys to it

- **Kind:** missing threat (TH-39 covers reading and replaying a transfer, not forging one). **Severity:** medium when the integration's channel between contexts passes through its server; low otherwise.
- **Where:** §3.8, SP-02, TH-39, D-29, integration guide `:118`, `src/team/receiver.ts`.
- **Evidence (reproduced):** `crypto_box_seal` doesn't authenticate the sender. A malicious server that also sees the request and can deliver the transfer (for example when the two contexts talk through it) publishes `member-keys` of its own under the member's account, serves a forged chain rostering them with a floor pointing at it, withholds `team-state`, and seals those keys to the request. A fresh receiving context opens the forged team `ready`, and what it writes is readable by the server. With an honest server, the injected keys aren't in any roster: the session is `pending` or `unverified`, never forged.
- **Fix proposed:** an edit. A new threat (TH-49), accepted as the integration's duty: the transfer request and the transfer travel on a channel the server can't write (same-origin `postMessage` with origin checks, a `MessageChannel`), never relayed by the server. Cite it in TH-39, SP-02's Limit and the integration guide. A protocol fix would need a secret both contexts already share, which they don't have; not proposed.
- **Needs:** an edit.

### D. Invite text claims more than TH-04

- **Kind:** overclaim. **Severity:** low.
- **Where:** `docs/integration.md:103` ("so a joiner can't be shown a forged team"), `docs/key-hierarchy.md:367` ("so a forged team is refused"), `docs/using.md:116`.
- **Evidence:** TH-04 and SP-07 say it holds for a joiner "whose invite anchor travelled outside the server". An invite email sent by the product's own server lets it choose the anchor, as for inbox links (TH-21).
- **Fix proposed:** add "when the link reaches the joiner outside your server (TH-04)" in the three places.
- **Needs:** an edit.

### E. `joinTeam` drops an anchor silently when keys already exist

- **Kind:** spec → code gap. **Severity:** low.
- **Where:** `src/account/vault.ts:406` returns before the anchor is checked; §6.4 doesn't say.
- **Evidence:** a member who joined without the anchor and retries with it (or retries after an interrupted join) gets no check and no floor, with no error. With B, a later re-key would pick up the newest trusted anchor anyway; still, a wrong anchor passes silently.
- **Fix proposed:** check the anchor against the served chain even when keys exist (refuse on failure), and say in §6.4 that an existing member's floor isn't changed. Folds into B.
- **Needs:** an edit with B.

### F. Rotation fills a missing floor with one bundle only

- **Kind:** code (minor). **Severity:** low.
- **Where:** `src/account/rotation.ts:47` passes `[held]` to `trustedAnchor`, while `rekeyTeam` passes every bundle of the team.
- **Evidence:** right after a re-key, before any open, `team-state` is still under the older bundle's `teamStateKey`; a vault without `anchors` (split layout) then fills the older bundle's floor but not the newest's. Harmless while the older bundle exists (§6.1 takes the newest bundle that has a floor); after the clean-up, the newest has none until the next re-key or rotation. Same kind as review 003 I.
- **Fix proposed:** open the team's bundles together and pass them all. Disappears with B, which computes one floor per team.
- **Needs:** a fix (or B).

## Edits ready now (no decision)

- C: TH-49, its index row, TH-39, SP-02 Limit and Related threats, integration guide `:118`.
- D: integration guide `:103`, key hierarchy `:367`, using guide `:116`.

## Need a decision

- A and B together (recommended as one change: "the floor is the newest trusted anchor at write time, and counts whenever it is above every other anchor"), with E and F folded in.

## Not found

No divergence in D-49's phrase rule (`vault.rekey` accepts the current phrase or one a held bundle carries; proof verified against the held keys, §4.2), in the transfer layout and checks (§3.8 step 3 matches `openTransfer` and the receiver), in the clean-up's `team-state` rewrite (§6.8 step 4), or in review 003 I's fix (`advanceAnchor` rereads with every bundle).
