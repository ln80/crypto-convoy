# Review 017: design of plan 017 (D-57, D-58)

Mode: `design`, with a fresh-context reviewer. Input: plan 017's first design (D-57: reports from this device's local anchor; D-58: absent wraps and member keys, a server rule on wrap versions), at `e8db45f`. Read only.

## Checked

- **Fresh-context reviewer:** a `general-purpose` subagent with the design brief (inputs, fallbacks, costs, the smallest rule), the proposal, `docs/` and the code it touches; not `.agents/`. Read from the code; no tests run.
- **This session:** each finding checked against the code it cites; the folded design re-checked for new state, fallbacks and API (none).
- **Not checked:** `team/rotation.ts`, the browser store, reproduction (plan 017's tests reproduce the cases).

## Findings

### A. A wrap that opens but doesn't match still blocks `secureAccount`

- **Kind:** forgeable input. **Severity:** high. **Actors:** an account-key holder (A7, or A9 in the vault) with the session. **Disposition:** fix.
- **Where:** `src/account/rotation.ts:31-43` (the rotation checks each wrap against its published record; a mismatch or a missing record throws); the first design kept that as an error.
- **Fix (taken):** the rotation re-wraps every wrap that opens and checks nothing else; the check runs when a team is opened. Deletes a rule. Leaving mismatched wraps behind was rejected: a server withholding records could make a rotation drop real bundles.

### B. Absent wraps in numbering let a session take the user's next identity

- **Kind:** forgeable input. **Severity:** medium-high. **Actors:** a session (A11) alone. **Disposition:** fix.
- **Where:** `src/account/member-custody.ts:55-63` (numbering from published records and held bundles); the server's write-once rule.
- **Evidence (read):** a garbage wrap at (team, next version, current account version) makes the user's own create `STALE_VERSION`, on a re-key or a join, with no warning.
- **Fix (taken):** a `member-keys-wrap` is created only in the batch that creates its `member-keys` record, or in a rotation's batch; numbering then uses published records only, and `held` goes.

### C. Garbage wraps that parse still list a team

- **Kind:** spec gap. **Severity:** medium. **Actors:** A11. **Disposition:** fix.
- **Where:** `src/account/recovery.ts:85-88` (`accountTeams` parses only).
- **Fix (taken):** an account's teams are those with at least one wrap that opens, so `secureAccount` never reports a team the account doesn't have.

### D. A reload drops reports not yet read

- **Kind:** spec gap. **Severity:** medium. **Actors:** none (a lost report). **Disposition:** fix.
- **Where:** `src/team/session.ts:307-308` (each load replaces the reports); owner operations and the `STALE_VERSION` retry reload after the local anchor moved.
- **Fix (taken):** a session adds the reports of each reload to those it holds. Integration duty: every context that opens a team shows its reports.

### E. A smaller rule for the report bound

- **Kind:** simplification. **Severity:** medium (the first design kept a fallback, and a context without an anchor store reported nothing).
- **Where:** `src/team/chain.ts:110-114`.
- **Fix (taken):** reports cover every record above the lowest root, the version the chain is fetched from. It deletes the "highest anchor" branch and the fallback; hiding reports needs every root raised, the floor included. Cost: repeated reports while the floor lags behind the local anchor, which floor upkeep makes rare.

### F. The paths the absent rules must and must not cover

- **Kind:** spec gap. **Severity:** medium. **Disposition:** fix.
- **Where:** `src/account/member-custody.ts:28-30` (parse before the team filter); `src/team/owner.ts:160-171` (`#allKeys` and `#publishedKeys`); `load.ts:44-46`; numbering and `foreign-member-keys` (`member-custody.ts:56-60`, `recovery.ts:150-154`).
- **Fix (taken):** skip at the parse; cover every list used for verification, overviews, `reconcile` and approvals, before D-55's duplicate check; leave numbering and foreign-key detection reading every published version, or the server's newest-plus-one rule breaks.

### G. The server rule and its batch; device wraps

- **Kind:** spec gap. **Severity:** low-medium. **Disposition:** fix.
- **Where:** `src/testing/memory-record-store.ts:166-197` (no such check; operations applied in order, the version switch last); `src/account/vault.ts:317-327` (`listDevices` throws on a garbage device wrap).
- **Fix (taken):** the kit checks wraps against the batch's final version; a device wrap that doesn't parse is left out of `listDevices`.

### H. An absent wrap hides a garbage replace

- **Kind:** hardening. **Severity:** low. **Actors:** A11. **Disposition:** accept and document.
- **Evidence (read):** a live wrap replaced with garbage now looks like a deletion (an older bundle, or not joined) instead of `DECRYPTION_FAILED`: the power A11 already has with `delete` (TH-46), restorable from the archive, with less evidence.
- **Accepted** in plan 017's design and TH-46.

### Positive finding

Today a `teamStateKey` holder (A7, A9, a copied bundle or transfer) can write `team-state` at the tip and hide reports on every device of the account; an account-key holder can do it through the floor. D-57 removes both.

## Simpler alternative

E is the simpler alternative for problem A, and was taken. For problem B, the batch rule (B) replaces the first design's version clause and deletes `held`.
