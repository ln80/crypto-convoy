# Review 022: adversarial, sixth round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `2b27be7` (after plan 018 and review 021's items). Read only.

## Checked

- **Baseline.** `check:spec` passes; ledger 1 of 2 (review 021 clean); nothing open to fix.
- **Fresh-context reviewer** with the adversarial brief and the recent changes named (D-55 to D-61). It found nothing critical or high; three tests (`scratchpad/repro4/`, outside the repository), rerun and read by this session, reproduce A and B. Its "checked and holding" list covers §8, the chain rules, keys-hash approvals, D-47, D-59 and D-61's credential paths.
- **This session's pass** on D-59 to D-61: nothing new.
- **Not checked:** the suite internals, most of the content drafts and streams, the link client, timing, races between devices.

## Findings

### A. A mismatched bundle planted with the account key blocks every repair of its team

- **Kind:** wrong premise. **Severity:** medium (availability; for a sole owner, the whole team). **Actors:** an account-key holder with the session (A7, or A9 in the vault). **Disposition:** accept and document; the action rule fixes availability only with a small change, and here the change would turn a trust failure into silence.
- **Where:** `src/account/rotation.ts:31-38` (a rotation re-wraps what opens, unchecked, D-58); `src/account/member-custody.ts:56-57` (`openBundles` throws `key_mismatch`); `recovery.ts` (`rekeyTeam`), `vault.ts` (`joinTeam`, `leaveTeam`). Plan 017 accepted this residual "until it re-joins", but a re-join fails the same way.
- **Evidence (reproduced):** the planted wrap moves to the new account key version, then `rekey` with an owner's anchor, `joinTeam` and `leaveTeam` all fail on it; every open is `unverified`.
- **Fix proposed:** correct the residual: the team stays failed for the account until support archives the planted wrap, which the integration's support process must be able to do for a live private record (an archive, not a restore); the kit gains that action. TH-20 and the integration guide say so.
- **Needs:** an edit.

### B. The documented repair after a deleted wrap leaves the member `state_unreadable`

- **Kind:** spec → code. **Severity:** medium (availability: the repair D-59 and D-60 document doesn't restore access). **Actors:** a session (A11) alone. **Disposition:** fix (a small change).
- **Where:** `src/team/anchors.ts:26-33` (`readServerState` opens `team-state` with the bundles held now, else `state_unreadable`); §6.1 step 1 ("a `team-state` that fails to decrypt stops here"); `member-custody.ts` (only `maintainBundles` rewrites it, after reading it). The tests of plan 018 assert the approval, not the open after it.
- **Evidence (reproduced):** a session deletes the wrap; `secureAccount` with `teamIds` reports the team; `rekey` with an owner's anchor and `reconcile` approve the new keys; every device of the member, a fresh one included, opens the team `unverified` (`state_unreadable`): the server's `team-state` is under the deleted bundle's `teamStateKey`.
- **Fix proposed:** D-58's rule applied to `team-state`: when the keys hold a floor (where `team-state` is not a root, D-52), a `team-state` that doesn't open is absent, and the next anchor advance replaces it (compare-and-set on its revision). It deletes a failure mode instead of adding one: TH-46's garbage `team-state` stops a team only for keys with no floor. Budget: small.
- **Needs:** a decision (it revisits D-42's rejected "repair an unreadable team state", whose reason, a stale overwrite moving the anchor back, no longer matters once `team-state` is neither a root nor a report bound).

### C. TH-41's race doesn't end against the server

- **Kind:** overclaim. **Severity:** medium. **Actors:** a holder of the old phrase (A8) with the server (A2). **Disposition:** accept and document.
- **Where:** TH-41 ("ends when an owner … approves one set of keys by hand"); the server isn't bound by rule 8, so it can publish a newer proven re-key after each of the user's, or a newer unproven one after an owner's review (`STALE_VERSION`).
- **Fix proposed:** TH-41 says the race ends only once the server stops publishing for the thief, as TH-47 says of sessions. An edit.

### D. The same-PIN check can be skipped by refusing one evaluation

- **Kind:** overclaim. **Severity:** low (needs the OPRF front end, a leaked PIN and the user reusing it). **Disposition:** correct the text.
- **Where:** §5.11 ("the old PIN is never set again unchecked"); `vault.ts` (`#refuseCurrentPin` skips on `PIN_RATE_LIMITED`).
- **Fix proposed:** "unless that evaluation is refused and the next one answered". An edit.

## Already accepted, not new

As the reviewer listed: older wraps or floors on new devices, first contact and owners' anchors (TH-04), forged transfers (TH-39, TH-49), planted floors on a device with no vault anchor (TH-20), a rewritten recovery key (TH-12), forged member keys at a join, deleted credentials (TH-36), duplicate or garbage records (TH-28), lost reports without an anchor store (a duty).

## Stop rule

B is for the action rule to fix (availability with a small change): **0 of 2**. If B were accepted instead, as availability, this review would be the second clean one in a row.
