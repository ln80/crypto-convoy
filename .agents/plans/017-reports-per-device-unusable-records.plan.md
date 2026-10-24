# Plan 017: change reports per device; a record that fails its own checks stops nothing else (review 016 A, B, C, D, E)

## Context

Review 016 (`.agents/reviews/016-adversarial.md`), all reproduced, all one actor:

- **A (high).** Reports cover records newer than the highest root (§6.1 step 3, `chain.ts`). The floor and `team-state` are account-wide, so only the first device or context to open after a change reports it; a split layout never does, since the export moves the floor to the tip before sealing it. A stolen owner key (A6) admits and removes members unseen (TH-17's only mitigation is detection).
- **B (high).** A session (A11) creates a garbage `member-keys-wrap` under a new identity at the current account key version: every account-wide operation fails (`secureAccount`, `rotate`, `warnings`), `openTeam` fails for that team, and no restore removes a record with no archived generation. A garbage wrap at version a+1 blocks rotations the same way.
- **C (low, team-wide).** Any joiner publishes a `member-keys` record with a bad signature: every member's team becomes `unverified`, and since review 013 F nobody may delete it.
- **D, E (low, text).** Resetting other devices after `secureAccount` removes the vault anchors that would catch a planted floor; a planted bundle carried by a rotation can be self-approved if a team's re-key fails and isn't retried first.

## Gate (hardening direction)

All fixes answer one-actor findings. Reviewed in design mode by review 017 (`.agents/reviews/017-design-plan-017.md`), whose A–G are folded in below; after it, D-57 is **free** (it deletes a branch) and D-58 is **small** (two "absent" rules that replace failure paths, one server condition, and two deletions).

| Fix | Delta | Product cost |
| --- | --- | --- |
| D-57 (A) | Reports bound by the lowest root instead of the highest: deletes the "highest anchor" branch; a session adds new reports to its list instead of replacing it | Integrators: every context that opens a team shows its reports, and keeps a persistent sessions' anchor store if it wants reports from its second open on. Users: each change shown once per device or context. API: none |
| D-58 (B, C) | Absent: a private record in a list that doesn't parse or open, a `member-keys` record that fails its checks. Server: a `member-keys-wrap` is created only with its `member-keys` record, or in a rotation's batch. Deleted: the rotation's published-keys check, `held` in numbering | Integrators: one server condition. Users: no failure added; two lockouts removed. API: none |

## Design

### D-57: change reports cover every record above the lowest root

Reports (§6.1 step 3, D-44) cover every record of the verified chain above the lowest root, the version the chain is fetched from (review 017 E). The roots are as before: the floor, this device's local anchor, the vault's anchor in its context, and `team-state` only for keys with no floor. So a device or context with its own anchor reports everything since it last verified, whatever another device did to the floor or `team-state`; a fresh one reports nothing older than its roots; a first contact reports the whole history, as before. A session adds the reports of each reload to those it holds (review 017 D), so a reload never drops reports not yet read. Hiding reports on a device now takes raising every root, the floor included (which needs the account key), not one value another device or a `teamStateKey` holder can write (review 017, positive finding).

### D-58: a record that fails its own checks is absent

1. **Private records in a list.** A `member-keys-wrap` that doesn't parse, or whose `wrappedKeys` doesn't open under the account key, was never the account's (only the account key makes one): the vault treats it as absent, as if the server withheld it, wherever it lists wraps (opening a team, the teams of an account, a rotation, `secureAccount`, the warnings). The skip happens at the parse, before filtering by team (review 017 F). A device `account-key-wrap` that doesn't parse is left out of `listDevices` the same way. A wrap that opens but doesn't match its published keys stays `TRUST_FAILURE` (`key_mismatch`) when the team is opened.
2. **A rotation re-wraps every wrap that opens**, without fetching or checking its published record (review 017 A): the check runs when the team is opened, and a rotation then can't be blocked by a mismatched or unpublished bundle, nor made to drop a real one by a server withholding records. An account's teams are those with at least one wrap that opens (review 017 C).
3. **Member keys records in a team's list.** A `member-keys` record that fails its checks (§4.2) is left out wherever the team's records are listed for verification, overviews, `reconcile` and approvals, before the duplicate check of D-55. A roster entry naming it fails as one naming an unpublished record (`key_mismatch`). Numbering new keys and `foreign-member-keys` keep reading every published version, so the server's newest-plus-one rule still holds (review 017 F).
4. **Server rule.** A `member-keys-wrap` is created only in the batch that creates its `member-keys` record, or in a rotation's batch, at the version it switches to; an `account-key-wrap` only at the current version or in that batch (review 017 B, G). A session can then no longer take the user's next wrap identity. Numbering new keys uses the published records only: the vault's held bundles are always published, and `held` goes.

Rejected:
- A support action that archives a live record with no generation: every device fails until support acts, and the client rules make it unnecessary.
- Leaving mismatched wraps behind in a rotation: a server forging or withholding `member-keys` records could then make a rotation drop real bundles (review 017 A).
- Bounding reports by this device's local anchor, with a fallback to the highest root (the first design): a fallback, and a context without an anchor store still reported nothing (review 017 E).

Accepted (TH-20, TH-46): an account-key holder can plant a wrap that opens with keys its published record doesn't match, which fails that team for the account until it re-joins; a session replacing a live wrap with garbage now looks like a deletion (an older bundle, or not joined), restorable from the archive, rather than `DECRYPTION_FAILED` (review 017 H).

### D, E (text)

- TH-20 and the integration guide: after `secureAccount`, open or re-key each team on the securing device before resetting the others, so its vault anchor is current.
- §5.11 step 3 and the using guide: retry a failed team before the owner's next `reconcile` (D-47 would approve keys the vault holds).

## Ripple

- D-57: §6.1 step 3; D-44 (status amended); SP-15; TH-17 if it states where reports appear; using guide (`memberChanges`).
- D-58: §4.2 and §4.3 reader checks; §5.5 (`listDevices`); §5.7 (rotation re-wraps what opens); §5.9 (numbering from published records); §11 (`account-key-wrap`, `member-keys-wrap` rows); scope rules 3 and 7; TH-25 (a joiner), TH-46 and SP-26 (a created garbage wrap); integration guide Writes table and Duties.
- D-57 also: the integration guide's Duties (show reports in every context that opens a team).

## Phases (one commit each)

1. **Spec:** D-57, D-58, D, E; `check:spec`. Design review 017 done.
2. **Code and tests:** `chain.ts` (the report bound), `session.ts` (reports added); `member-keys-wrap.ts` (unwrap apart from the match), `member-custody.ts`, `rotation.ts`, `recovery.ts`, `vault.ts` (absent wraps, `listDevices`, numbering); `load.ts`, `owner.ts` (absent member keys); the kit's create rules. Tests for each, with guards.
3. **Notes:** execution notes, ledger.

## Execution notes

- **D-57, as built:** `verifyChain` reports every record above the first one fetched when there are roots (the lowest root), everything at first contact; the "highest anchor" computation and the `team-state` "followed" list are gone (the `team-state` check itself stays). `TeamSession.#verify` adds new reports to those it holds, by version.
- **D-58, as built:** `member-keys-wrap.ts` splits `unwrapMemberKeys` and `checkBundle` out of `openMemberKeysWrap` (kept for the vectors); `openedWraps` in `member-custody.ts` lists the wraps that parse and open, used by `openBundles`, `accountTeams` and the rotation; the rotation no longer reads published records; `nextMemberKeysVersion` drops `held`; `listDevices` skips device wraps that don't parse; `parseListedMemberKeys` serves `verifiedChain`, `#allKeys` and `#publishedKeys` (before D-55's duplicate check). A record of an unknown version in a team's list is left out too: a reader that hasn't updated sees a roster entry naming it as `key_mismatch` rather than `UNSUPPORTED_VERSION`, the price of a joiner not being able to stop the team with `v: 99`.
- **Kit:** `MemoryRecordStore` refuses an `account-key-wrap` or `member-keys-wrap` at another version than the current one or the batch's switch, and a `member-keys-wrap` without its `member-keys` record in the batch (outside a switch). Kit unit tests now switch a first version with their first wraps.
- **SP-19's Limit test** (`recovery.test.ts`) models the retired version with `restoreVersion`: an honest server now refuses the fresh device's registration at a retired version, which narrows that residual in practice; a server that kept the version still serves and accepts it.
- **Tests:** `change-visibility.test.ts` (a second device, a split layout, a reload in a split layout); `record-archive.test.ts` (garbage wraps for a team, outside it and unparsable; the server's two refusals; a mismatched wrap that opens); `key-substitution.test.ts` (a joiner's bad `member-keys` record, SP-18).
- **Guards:** reports from the highest root (2 failures), a reload replacing reports, garbage wraps throwing, the rotation checking published keys, the kit's version rule, the kit's keys rule, bad member keys throwing, teams from parsed wraps: each fails a test. Three guards passed at first; their tests were strengthened (a split-layout reload, well-formed refused records, an unparsable wrap).
- **Checks:** `typecheck`, `npm test` (752), `test:browser` (10), `check:spec`, `build`, `test:package` pass.
- **Integration (doconvoy e2eev2):** the backend refuses wraps outside their batch; show `ownerChanges` and `memberChanges` in every context, with a persistent anchor store per context; nothing in the public API changed.
