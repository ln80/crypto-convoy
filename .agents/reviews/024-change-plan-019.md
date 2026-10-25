# Review 024: change, plan 019 (D-62)

Mode: `change`. Scope: the `docs/` changes of plan 019 (`3d17022`) and what they ripple into, against the code at `81b60c3` (`e8571cb` for `src/`). Read only.

## Checked

- **Baseline.** `npm run check:spec` passes; ledger 0 of 2, nothing open to fix; open, low: 011-A. The four test files plan 019 touched pass (63 tests).
- **Properties → protocol.** SP-07 (a corrupted `team-state` stops keys with no floor, is absent with one) and SP-26 (garbage replaced at the next open): each sentence traced to §4.4, §6.1 steps 1 and 7, §6.8 step 4, and to `readServerState`, `loadChain`, `advanceAnchor` and `maintainBundles`.
- **Threats → mechanism.** TH-46 (garbage `team-state`), TH-20 (support archives a planted wrap), TH-41 (the race against the server): each claim traced to code or to plan 019's tests (`record-archive`, `rollback`, `secure-account`, `memory-store`).
- **Decisions → text.** D-62 and its revisit of D-42 searched across `docs/`, `README.md`, the guides, `src/` comments and the local course (`state_unreadable`, "never ignored", "last readable", "restores").
- **Spec → code.** The roster check (`held`: account, member keys version and keys hash of the newest bundle), the floor read from the newest bundle, the conflict path with an unreadable state, the clean-up keeping its deletes, the revision cap against the writer's `revision + 1`, and the kit's `archive` (private records only).
- **Plan notes.** No risk accepted on the plan's own; the integration's new support action is in the integration guide.
- **Not checked:** the doconvoy integration's support tooling.

## Findings

### A. A malformed `team-state` still stops the team where the keys hold a floor

- **Kind:** overclaim, spec → code. **Severity:** low (availability only). **Actors:** A11 alone. **Disposition:** fix (small).
- **Where:** `src/team/anchors.ts` `readServerState`: `parseTeamState` runs before the keys are tried, so a record that fails its shape checks (a `wrappedState` of the wrong size, an unknown suite, a context mismatch) throws `MALFORMED_RECORD` whatever the floor. D-62's consequence ("A garbage `team-state` now stops only keys with no floor"), §4.4 and SP-26's verification don't limit the claim to well-formed records; TH-46's attack does ("a well-formed `team-state`"), but the server contract asks no shape check (scope rule 4) and the kit makes none.
- **Evidence:** reproduced with a throwaway test (deleted): after a `compare-and-set` at `revision + 1` with `wrappedState: { nonce: 3 bytes, ciphertext: 3 bytes }`, `bob.vault.openTeam("team-1")` throws `MALFORMED_RECORD`, on every open, until support restores the previous revision.
- **Fix:** with a floor, a `team-state` whose `revision` reads but whose other fields fail their checks is unreadable too (absent, replaced at its revision + 1); with no floor it stays a failure. One branch in `readServerState` and one clause in D-62 and §4.4. **Budget:** small (no state, fallback or duty; a failure mode removed). **Product cost:** none. **Needs:** an amendment of D-62 (a decision line), then code with a test and its guard.
- **Alternative:** accept and narrow the text to well-formed records (TH-46 residual: support restores). Rejected as the default: the fix is smaller than the text it would take to explain the difference.

### B. The server contract doesn't say a `team-state` revision grows by one

- **Kind:** spec → code. **Severity:** low. **Actors:** A11 alone, on a server that follows the contract as written. **Disposition:** correct the text (the kit is right).
- **Where:** scope rule 4 and §11's `team-state` row say "compare-and-set on `revision`"; the kit refuses any write but current + 1 (`memory-record-store.ts`, "revision must increase by one"). Without that rule, a session writes a `revision` of 2^53 − 2 (or 2^53 − 1): the next advance writes 2^53 − 1, which the parser's new cap refuses forever, so §4.4's cap ("below 2^53 − 1") holds only with it.
- **Evidence:** read (code paths above); the kit refusing a jump was checked with the same throwaway test.
- **Fix:** scope rule 4 and §11: "a `team-state` write is accepted only at the current revision + 1 (1 for the first)". **Budget:** small (one sentence; every conforming compare-and-set already numbers this way). **Product cost:** integrators: the Go key store checks it, if it doesn't yet.

### C. Three texts still say an unreadable `team-state` always stops the team

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** `src/records/team-state.ts:50` ("A state that doesn't open is tampering, never ignored (§4.4)"); `learning/course/03-the-team/03-anchors.md:43` ("stops the team with `state_unreadable` … undone by a support restore, not by the library"); `learning/course/02-the-account/answers.md:51` (every device stops; a support restore reopens it). The ledger's TH-46 residual ("garbage … until support acts") now holds for wraps, malformed states and keys with no floor only.
- **Fix:** the comment: "fails `state_unreadable`; the caller decides whether that is absent (D-62)"; the course through [maintain-course](../skills/maintain-course/SKILL.md); the residual row narrowed (done with this review).

## Not found

- `advanceAnchor` replaces an unreadable state only when the newest bundle's account, version and keys hash are in the tip's roster, and returns without writing otherwise; the conflict path re-reads and skips the hash check only for an unreadable state.
- `loadChain` reads the floor from `bundles[0]`, the newest bundle, as §6.1 step 1 says; with no floor, an unreadable state is still `state_unreadable` before any root is used.
- The clean-up keeps deleting older wraps when the state is unreadable; the advance that follows holds the newest bundle, which the clean-up already found in the roster, so it replaces the state.
- The writer's `revision + 1` stays within the parser's cap whenever the server numbers by one (B).
- The kit's `archive` refuses public records; TH-20, D-58, the integration guide and the ledger residual say the same.
- TH-41 and §5.11 say what review 022 C and D asked.

## Edits ready now (no decision)

B and C (text and a comment; the course through maintain-course).

## Needs a decision

A: amend D-62 so a malformed `team-state` is absent with a floor (recommended), or narrow the claim to well-formed records.

## Stop rule

A is a small fix the action rule takes for an availability finding: **0 of 2**. If A is fixed or the user accepts it as text, the next `adversarial` review (025) counts.
