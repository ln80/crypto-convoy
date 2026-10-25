# Plan 020: with a floor, `team-state` counts only under the newest key (reviews 024 A, 025 B, 026; accept 025 C; text for 024 B, C, 025 D, E)

## Context

Review 024 (`change`, plan 019) and review 025 (`adversarial`, fresh context) found nothing critical or high. Two findings are for the action rule to fix, and one is accepted:

- **024-A / 025-A** (medium, A11 alone): a `team-state` that fails its shape checks (`parseTeamState`) stops the team before D-62's "absent" branch, with a floor too. `leaveTeam` and `exportTeamKeys` fail as well, and a record with `v: 2` or an unknown suite reads as `UNSUPPORTED_VERSION`.
- **025-B** (medium; one actor in practice: A9 in the vault, or A7 with a signed-in device): someone with a copied `teamStateKey` writes a readable forged `team-state`. It survives `secureAccount`, because every held bundle opens `team-state` and the old bundle stays held until approval. Every open is then `state_conflict`, so a sole owner's own `reconcile` never approves the new keys, and the copied owner key stays valid until support restores.
- **025-C** (medium, availability, A11 on an owner's account): a garbage team key version at the next version stops the chain for good. Accepted and documented: both fixes are costly (a server signature check, or a support exception to rule 3).

The rest is text: 024-B, 024-C, 025-D and 025-E.

The first design wrote `team-state` at every re-key (D-63 as a write). Review 026 (`design`, fresh context) showed that this write could be undone in two ways: the server replays the archived forged revision (reproduced), or anyone with the old key and a live session rewrites it. The write could also fail silently (026-C) or move an anchor back (026-D). Review 026 proposed a read rule in its place, which deletes rules instead of adding them (026-A). It also found that an unknown version treated as replaceable breaks readers-first (026-B). This plan takes both.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-63 (025-B, 026-A) | Free | **Deletes:** the loop over every bundle in `readServerState` and the clean-up's `team-state` rewrite (§6.8 step 4), for keys with a floor. **Adds:** one read rule (with a floor, `team-state` counts only under the newest bundle's key; otherwise it is absent, D-62) | None. Users: `secureAccount` followed by the owner's own `reconcile` closes the window again, even if a forged state is rewritten or replayed |
| D-62 amended (024-A, 026-B) | Free | Removes a failure mode. With a floor, a known version that fails its checks is absent and replaced. An unknown `v` or suite is absent and never replaced | None. Users: a malformed `team-state` no longer stops a team whose keys hold a floor |
| 024-B, 026-E | Small (text) | Scope rule 4 and §11: a `team-state` write is accepted only at the current revision + 1 (1 for the first). The library relies on this rule | Integrators: the Go key store checks it, if it doesn't already |
| 025-C | Small (text) | Accepted: TH-25, an SP-18 Limit, the integration guide, a ledger residual | Integrators: a recommendation (grant the owner capability only to the chain's owners); no new duty |

Reach: unchanged. API: no change.

## Design

### D-63: with a floor, `team-state` counts only under the newest key

When the newest bundle holds a floor, `team-state` counts only if it opens under that bundle's `teamStateKey`. A record that opens only under an older bundle's key, or under none, is absent (D-62). As before, the anchor advance (§6.1 step 7) replaces an absent record only if the newest bundle is in the tip's roster. Writers already write under the newest bundle's key.

Consequences:
- **After a re-key** (`secureAccount`, `rekey`, the repair with an owner's anchor), a state under the old key is absent:
  - it doesn't matter who wrote it, or whether the server replays it;
  - the pending new keys don't replace it, and an absent state stops nothing, so the owner's `reconcile` approves;
  - the first advance with the new keys held replaces it.
- **Clean-up** (§6.8 step 4) no longer rewrites `team-state`. It deletes the older bundles' wraps, and the next advance replaces the old-key state.
- **Contexts never take turns:**
  - While a re-key is pending, a stale context holding the old keys may write under them. Contexts holding the new keys ignore that record and write nothing.
  - Once the new keys are approved, the old keys aren't in the roster, so the stale context never writes again.
- **Keys with no floor** are unchanged. There `team-state` is a root, and every held bundle still opens it.

Cost: while a re-key is pending, a `team-state` written under the old keys neither bounds rollback nor shows a split view to contexts holding the new keys. The floor (D-50) and the local anchor still bound them. With a floor, `team-state` chooses nothing (D-52) and bounds no report (D-57).

This revisits D-52's rejection of "overwriting a `team-state` the chain contradicts" only for records under keys the account is replacing. A forged record under the newest key still fails with `state_conflict` or `rollback`, as D-52 says.

Rejected:
- **The re-key writing `team-state` under the new keys** (the first design of this plan). The server replays the archived forged revision, and a holder of the old key with a session rewrites it. A failed write would be silent, and it could move an anchor back (review 026 A, C, D).
- **A support step in the remedy:** a documented procedure would leave the user compromised until a human acts.

### D-62 amended: a malformed `team-state`

Read `revision` first. It must be an integer from 1 to 2^53 − 2. If it fails, the record is `MALFORMED_RECORD`, whatever the floor. This field's name and meaning are fixed in every future `team-state` layout (§4.4).

With a floor, the rest depends on the version:
- **Unknown `v` or suite:** absent, and never replaced. Readers ship first (§10), so an older client must not overwrite a newer client's record.
- **Known version that fails its shape, context or decryption checks:** "doesn't open". The record is absent, and the anchor advance replaces it at revision + 1, under D-62's roster rule.

With no floor, every failure is the error it is today: `MALFORMED_RECORD`, `UNSUPPORTED_VERSION` or `TRUST_FAILURE` (`state_unreadable`).

Consequence: a session's `v: 99` record is never replaced. The account goes without a server-side anchor for that team until support restores the record. This is the same as a session deleting the record, which the floor bounds (D-50, TH-46).

Rejected:
- **Narrowing the claim to well-formed records** (the TH-46 residual). The text needed to explain the difference would cost more than the branch.
- **Treating an unknown version as replaceable** (review 026 B). With mixed library versions on one account, the record would switch formats back and forth.

### 025-C accepted

TH-25 gains an Attack sentence and a Disposition sentence:
- **Attack:** an owner's session, or anyone the integration grants the owner capability, publishes a version that fails its checks at the next version.
- **Disposition:** a chain can't leave a version out, and a version's identity is written once, so the team stops for good for every member. The server's check of the caller (rule 8) is the only barrier.

Elsewhere:
- **SP-18:** a Limit, "a team key version that fails its checks stops the chain (TH-25)", with a test.
- **Integration guide:** grant the owner capability only to the chain's owners. A server that can verify a version's signature against the previous version's owners should do so.
- **Ledger:** a residual (actor: A11 or an owner-capability holder; availability; revisit: a server-side signature check, or support freeing a version identity).

### Text

- **024-B, 026-E:** scope rule 4 and §11's `team-state` row: "accepted only at the current revision + 1 (1 for the first)". The library relies on this rule: without it, a session's revision near the cap would stop the team.
- **024-C:** the `openTeamState` comment in `src/records/team-state.ts`; the course (`learning/course/03-the-team/03-anchors.md`, `02-the-account/answers.md`) through maintain-course.
- **025-D:** TH-20 and §5.11 step 2: "a planted floor, or a planted bundle with none, on a device whose vault never verified the team, is trusted …"; the TH-20 residual row names both.
- **025-E:** §6.1 step 7: "check that the chain contains one at or below its tip; a newer one is left to the next open".

## Ripple

- **§ and scope:** §4.4, §6.1 steps 1 and 7, §6.8 step 4, §10 (the fixed `revision` field), §11, scope rule 4.
- **Decisions:** D-62 (amended), D-52 (status: revisited by D-63), D-47 and TH-12 (the remedy now holds).
- **Threats and properties:** TH-20, TH-25, TH-46, SP-07, SP-18, SP-26.
- **Other text:** the key hierarchy's `teamStateKey` row if it names older bundles; the integration guide; the course.
- **Retired terms:** "rewrites the server's `team-state` with the same anchor" (§6.8 step 4). Check before adding.

## Phases (one commit each)

1. **Spec.** D-63, the D-62 amendment, 025-C's acceptance and the text items; `check:spec`. Design review 026 is done (`.agents/reviews/026-design-plan-020.md`): A and B are taken, C and D are moot, E is taken, F is left for the next `complexity` review.
2. **Code and tests.**
   - **Code:**
     - `records/team-state.ts`: a revision reader separate from the full parse; the `openTeamState` comment.
     - `team/anchors.ts`: `readServerState` opens with the newest bundle only when it holds a floor, and returns `anchor: null` for any failure of a known version. It also returns a flag for an unknown version, which the advance never replaces.
     - `team/load.ts`: with no floor, the original error is rethrown.
     - `account/member-custody.ts`: the clean-up's `team-state` rewrite is deleted.
   - **Tests:**
     - `record-archive.test.ts`: a short ciphertext is replaced with a floor; a `v: 2` record is left alone.
     - `rollback.test.ts`: a malformed state with no floor still fails.
     - `secure-account.test.ts`: a readable forged state under the old key, then `secureAccount`; the sole owner's own `reconcile` approves and the team opens, both when the state is rewritten and when the server replays it.
     - `account-rotation.test.ts` or the clean-up's test: after approval, the clean-up deletes the old wraps and the next open replaces the old-key state.
     - SP-18's Limit: an owner's session publishes a garbage version, and every member is `unverified` (`bad_signature`).
   - **Guards:**
     - the loop over every bundle restored (the replay test fails);
     - the full parse moved back in front of the version check;
     - an unknown version made replaceable (the `v: 2` test fails).
3. **Notes.** Execution notes, then a `change` review of plan 020 and a fresh `adversarial` review toward the stop rule.

## Execution notes

(empty)
