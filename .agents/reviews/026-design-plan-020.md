# Review 026: design of plan 020 (D-62 amended, D-63)

Mode: `design`, with a fresh-context reviewer. Input: plan 020's first design, at `1e98e7b`. Read only.

## Checked

- **Fresh-context reviewer.** It was given the design brief, the proposal and `docs/` and `src/`, and not `.agents/` or the history. It ran a throwaway test (deleted) showing four things:
  - today, a readable forged `team-state` still blocks a sole owner after `secureAccount`;
  - a simulated D-63 write unblocks the open, and the owner's `reconcile` approves;
  - a context holding only the old keys replaces the D-63 record once;
  - the server replaying the archived forged revision blocks again.
- **This session's pass.** It found three candidates, all covered below:
  - D-63 must also overwrite a forged anchor above the tip (`rollback`) (in D);
  - a thief who keeps a session rewrites the forged state after D-63 (in A);
  - clients that haven't updated yet downgrade a newer `team-state` format (B).
- **Not checked:**
  - how the write would sit in `secureAccount` next to the account rotation;
  - account key version restores (D-42) after the change;
  - the browser adapter's local anchors.

## Findings

### A. D-63 writes around a read rule; a read rule is smaller and holds

- **Kind:** simplification. **Severity:** medium, because D-63 doesn't fix 025-B against every actor it names.
- **Actors D-63 doesn't stop:**
  - **A2 alone.** The server replays the archived forged revision (reproduced).
  - **A7, A9 or A11 with the old `teamStateKey` and a live session.** They rewrite the state at revision + 1.
- **Where:** `readServerState` opens `team-state` with every bundle held (`anchors.ts:28-33`). The vault keeps the old bundle until approval and clean-up (§6.8 step 4), so any live record under the old key still counts until then.
- **Proposed rule:** with a floor, `team-state` counts only if it opens under the **newest** bundle's `teamStateKey`. Otherwise it is absent (D-62).
- **What the rule does:**
  - After a re-key, a forged state under the old key is absent, whether it is replayed or rewritten.
  - The pending new keys don't replace it, because of D-62's roster rule. Absent stops nothing, so the owner's `reconcile` approves. The next advance, now with held keys, replaces the state.
  - Writers already use the newest key (`advanceAnchor`, `anchors.ts:48,63`).
- **What it deletes:**
  - D-63 entirely, with its write, its retry and its silent failure (C).
  - The loop over every bundle in `readServerState` for keys with a floor. Keys with no floor keep it: there `team-state` is a root.
  - The clean-up's `team-state` rewrite (§6.8 step 4, `member-custody.ts:299-309`). An old-key state is absent there, and the next advance replaces it.
- **Contexts can't take turns:**
  - While the re-key is pending, a stale context holding the old keys may write under them. The new-keys context ignores that write and writes nothing itself.
  - After approval, the stale context's keys aren't in the roster, so it never writes again.
- **Cost:** while a re-key is pending, a `team-state` written under the old keys neither bounds rollback nor shows a split view to contexts holding the new keys. The floor (D-50) and the local anchor still bound them. With a floor, `team-state` chooses nothing (D-52) and bounds no report (D-57).
- **Budget:** free (it deletes more than it adds). **Product cost:** none.
- **Disposition:** take it, in place of D-63.

### B. Treating an unknown `v` or suite as absent and replaceable breaks readers-first (§10)

- **Kind:** forgeable input, spec gap. **Severity:** medium. **Actors:** no attacker needed: the user's own devices on mixed library versions. A11 can also write `v: 99`.
- **Where:** §10 says "first readers that understand the new format, then writers that produce it". Today an old library refuses a newer `team-state` with `UNSUPPORTED_VERSION`. Under item 1, an old device whose keys are in the roster would replace a newer device's v2 record with a v1 record, and the newer device would write v2 again. The record would switch format back and forth and lose whatever only v2 carries.
- **Fix:**
  - An unknown `v` or suite is absent with a floor, and never replaced. Only a known version that fails its shape, context or decryption is absent and replaceable.
  - Reading `revision` before the version check freezes that field's name and meaning in every future layout. §4.4 says so.
- **Consequence:** a session's `v: 99` record is never replaced, so the account loses its `team-state` until support restores it. That is no worse than a session deleting the record, which the floor bounds (D-50, TH-46).
- **Budget:** small.

### C. D-63's failure would be silent

- **Kind:** spec gap. **Severity:** low. Moot if A is taken.
- **Where:** `rekeyTeams` reports the team as re-keyed (`recovery.ts:152-153`). If the write failed, the sole owner would stay at `state_conflict` with nothing that names a retry.

### D. D-63's write could move the anchor back

- **Kind:** hardening. **Severity:** low. Moot if A is taken.
- **Where:** `rekeyTeam` verifies without the `team-state` (`recovery.ts:126-127`), and D-63 compared only revisions.
- **Effect:** with an owner's anchor, or roots behind a session's advance, a server cutting the chain gets a lower tip written over a higher legitimate anchor. That erases the `rollback` or split-view evidence the user is likely reacting to. The server could already serve older revisions (§4.4).

### E. The server's revision rule carries TH-46's availability

- **Kind:** spec gap. **Severity:** low.
- **Where:** item 1 keeps "a revision that fails is `MALFORMED_RECORD`". Without the server's "current revision + 1" rule (024-B), a session writes `2^53 − 2`, and the replacement at `2^53 − 1` then fails the parser's cap for good.
- **Fix:** scope rule 4 states the rule as one the library relies on, not as defence in depth.

### F. Noted for the next `complexity` review

The reviewer's more radical option: with a floor, `team-state` never fails an open, and `state_conflict` and `rollback` become reports. Its signal against the server alone is weak, since the server can serve an older revision instead (§4.4). This is out of scope for a design review, and it changes D-52's detection. Recorded for the next `complexity` review, not proposed here.

## Recommended revision of plan 020

1. **D-63, redefined.** With a floor, `team-state` counts only if it opens under the newest bundle's `teamStateKey`; otherwise it is absent (D-62). This replaces the re-key's write.
2. **D-62 amended.** `revision` is read first. An unknown `v` or suite is absent and never replaced. Any other failure of a known version is absent and replaceable under the roster rule. With no floor, every failure stays as it is today.
3. **Deletions.** The loop over every bundle in `readServerState`, for keys with a floor. The clean-up's `team-state` rewrite.
4. **Scope rule 4 and §11.** "Current revision + 1", relied on.
5. **Tests.**
   - The sole owner after `secureAccount`, with the forged state rewritten and with it replayed by the server.
   - A v2 `team-state` that an old reader leaves alone.
   - The clean-up without its rewrite.
   - Guards for each.

## Stop rule

No change: **0 of 2**. 024-A and 025-B stay open until plan 020 lands.
