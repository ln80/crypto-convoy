# Plan 019: with a floor, an unreadable `team-state` is absent (review 022 B; text for A, C, D)

## Context

Review 022 (`.agents/reviews/022-adversarial.md`), no critical or high finding. **B (medium, availability, one actor):** a session deletes a team's wrap; the repair D-59 and D-60 document (`secureAccount` with `teamIds`, `rekey` with an owner's anchor, the owner's approval) leaves every device of the member `state_unreadable`, because the server's `team-state` is under the deleted bundle's `teamStateKey` and an unreadable `team-state` stops §6.1 at step 1. A, C, D are text.

## Gate (hardening direction)

| Fix | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-62 (B) | Free | A failure mode deleted: with a floor, an unreadable `team-state` is absent and the next anchor advance replaces it; `state_unreadable` remains only for keys with no floor, where `team-state` is a root | None. Users: the repair restores access; a garbage `team-state` no longer stops a team for keys with a floor (TH-46) |
| 022-A | Small (text, a kit action) | The residual corrected; the support process can archive a live private record | Integrators: one support action |

## Design

### D-62: with a floor, an unreadable `team-state` is absent

When the keys hold an anchor floor, `team-state` is not a root and bounds nothing (D-52, D-57): a `team-state` that doesn't open under any `teamStateKey` the session holds is treated as absent, like a wrap that doesn't open (D-58), and the anchor advance (§6.1 step 7) replaces it, by compare-and-set on its revision, with the verified tip under the newest bundle's `teamStateKey`. For keys with no floor, `team-state` is a root and an unreadable one stays `TRUST_FAILURE` (`state_unreadable`). The vault's clean-up (§6.8 step 4) rewrites a readable `team-state` only.

Revisits D-42's rejected "repair an unreadable team state from a device": its reason was that a device holding an older bundle could overwrite a newer `team-state` and move the account's anchor back. With a floor, `team-state` chooses nothing (D-52) and bounds no report (D-57), so an overwrite moves nothing back.

Rejected: rewriting `team-state` in the repair only (`rekey` with no bundle): a garbage or stale `team-state` from any other cause would still stop every device.

### Text (022-A, C, D)

- **A:** a wrap planted with the account key that opens with mismatched keys fails its team until support archives it; the integration's support process can archive a live private record (an archive, not a restore); the kit gains `archive(key)`. TH-20, D-58's consequence, the integration guide, the ledger residual.
- **C:** TH-41: against the server, the race ends only once it stops publishing for the thief (as TH-47 for sessions).
- **D:** §5.11: the old PIN is never set again unchecked, unless that one evaluation is refused and the next answered.

## Ripple

§6.1 steps 1 and 7, §6.8 step 4, §4.4 if it states the failure; D-42 (status), D-52; TH-46, SP-26 (the garbage `team-state` test), SP-07; integration guide (support), TH-20, TH-41, §5.11.

## Phases (one commit each)

1. **Spec:** D-62 and the text; `check:spec`. Design review 023 done (`.agents/reviews/023-design-plan-019.md`): roster-held writers only, the revision kept, the premise corrected, the revision capped.
2. **Code and tests:** `anchors.ts` (`readServerState` returns an absent anchor; `advanceAnchor` replaces it), `load.ts` (unreadable only fatal with no floor), `member-custody.ts` (clean-up skips an unreadable state); the kit's `archive`; the repair test asserting the open afterwards; the TH-46 test; guards.
3. **Notes.**

## Execution notes

- **D-62, as built:** `ServerState.anchor` is null when no held `teamStateKey` opens the record; `loadChain` throws `state_unreadable` only when the newest bundle has no floor; `advanceAnchor` compares only a readable anchor, writes over an unreadable one at its revision + 1 only when the newest bundle is in the tip's roster, and skips the conflict path's hash check for an unreadable one; `maintainBundles` rewrites a readable state only and still deletes older wraps. `parseTeamState` caps `revision` at 2^53 − 2.
- **022-A:** the kit's `MemoryRecordStore.archive(key)` (private records only), with a unit test; TH-20, D-58, the integration guide and the ledger residual say support archives a planted wrap.
- **022-C, D:** TH-41 and §5.11 text.
- **Tests:** `secure-account.test.ts` (the repair now ends with the member's open; an older context leaves the state alone), `record-archive.test.ts` (TH-46: garbage replaced at the next open), `rollback.test.ts` (unreadable stops keys with no floor, is absent with one), `memory-store.test.ts` (support archive).
- **Guards:** unreadable throwing again (3 failures), no roster check (1), floorless keys tolerating it (1).
- **Checks:** `typecheck`, `npm test` (759), `test:browser` (10), `check:spec`, `build`, `test:package` pass.
- **Integration (doconvoy e2eev2):** support needs an "archive a live private record" action; no API change.
