# Review 018: change, plan 017 (D-57, D-58)

Mode: `change`. Scope: the `docs/` changes of plan 017 (`511b0d1`) and everything they ripple into, against the code at `f2347a1`. Read only. Chosen over `residuals` because the protocol-change workflow requires a `change` review after every plan that edits `docs/`; `residuals` is kept for just before the freeze.

## Checked

- **Baseline.** `npm run check:spec` passes, no `known` entries. Ledger: 0 of 2; nothing open to fix; open, low: 011-A.
- **Properties → protocol.** SP-15 (reports per device or context, its new assumption), SP-18 (records left out of a list), SP-26's new verification: each sentence traced to §4.2, §4.3, §5.5, §5.7, §6.1 step 3 or §11, and to the code (`chain.ts` `reportedFrom`, `session.ts` report merge, `openedWraps`, `parseListedMemberKeys`, `listDevices`, the kit's create rules).
- **Threats → mechanism.** TH-25 (a joiner's bad record is left out), TH-46 (a created wrap stops nothing; the server's create rule), TH-20 (the vault anchor before resetting devices), TH-17 (detection on every member's client): each claim traced to code and to plan 017's tests.
- **Decisions → text.** D-57 and D-58 searched across `docs/`, `README.md` and the comments in `src/` (the terms "highest anchor", "last verified state", "counts as an anchor", "bundles the vault holds", numbering, `listDevices`, the wrap creation rule).
- **Spec → code.** The kit's create rule against §11 and scope rule 5; the absent-record rules against `member-custody.ts`, `rotation.ts`, `recovery.ts`, `owner.ts`, `load.ts`.
- **Plan notes.** Plan 017's execution notes, for a risk accepted there and not in the spec.
- **Not checked:** the local course (`learning/`).

## Findings

### A. "This account's last verified state" still describes the reports

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** §12 (`team.ownerChanges // owner list changes since this account's last verified state`); `src/team/session.ts:127, 132` (the two getters' comments).
- **Evidence (read):** since D-57, reports cover every record above the lowest root of this device or context, not the account's last state.
- **Fix:** "since this device or context last verified the team (D-57)" in §12 and both comments; add "this account's last verified state" to the retired wording.

### B. §6.1 step 2 says a consistent `team-state` "counts as an anchor"

- **Kind:** stale text. **Severity:** low. **Disposition:** correct the text.
- **Where:** §6.1 step 2 ("otherwise it counts as an anchor"); `src/team/chain.ts` (the `team-state` block now only checks it).
- **Evidence (read):** before D-57 a consistent `team-state` raised the report bound; now it is checked and nothing else uses it there. It is a root only for keys with no floor (step 1).
- **Fix:** "otherwise it is consistent with the chain"; retired wording for "counts as an anchor" (D-52 keeps the history in D-50's text).

### C. "At the current version or in the batch that switches" is ambiguous inside a switching batch

- **Kind:** spec → code. **Severity:** low. **Disposition:** correct the text.
- **Where:** §11 (`account-key-wrap` row), scope rule 5; `src/testing/memory-record-store.ts` (inside a batch that switches the version, a wrap must be at the new version; one at the old version is refused).
- **Evidence (read):** the integration guide's Writes table says it the kit's way ("at the new version"); §11 and scope rule 5 can be read as allowing the old version in that batch. The kit is right: a wrap at the version being retired would be archived at once.
- **Fix:** "only at the version current once the batch applies" in §11 and scope rule 5.

### D. Records of an unknown version are left out of a team's list, but §4.2 doesn't say so

- **Kind:** spec → code. **Severity:** low. **Disposition:** correct the text, and record the residual.
- **Where:** `src/records/member-keys.ts` (`parseListedMemberKeys` leaves out any record that fails to parse, an unknown `v` included); §4.2's bullet ("a record that fails these checks"), whose checks are the shape, keys and signature; plan 017's execution notes accepted it.
- **Evidence (read):** a reader that hasn't updated sees a roster entry naming a newer-format record as `key_mismatch` instead of `UNSUPPORTED_VERSION`; that is the price of a joiner not stopping the team with `v: 99`. The two-release rollout (readers first) makes it rare.
- **Fix:** §4.2's bullet and D-58 say "including a record of an unknown version"; a ledger residual for the weaker error.

## Not found

- SP-15's new sentence and assumption match `reportedFrom` and the session's merge; the "reported once" test still holds on the device that saw it.
- §4.3's skip "before filtering by team" is `openedWraps`, used by `openBundles`, `accountTeams` and the rotation; `foreign-member-keys` and the `rekey-needed` warning go through them.
- Numbering reads every published version (§5.9, `nextMemberKeysVersion`), so the server's newest-plus-one rule holds.
- §5.11 step 3's retry advice (016-E) matches D-47's approval of keys the session holds.
- TH-25 and SP-18 claim only the three lists the code covers; a bad `team-key-version` record is still a trust failure, rightly.

## Edits ready now (no decision)

A, B, C, D.

## Stop rule

Nothing here is for the action rule to fix: four text corrections. With review 016's findings fixed or accepted, this is **1 of 2**; a fresh `adversarial` review that finds nothing to fix makes the freeze candidate.

## Applied

A to D, with this review: §12 and the session comments, §6.1 step 2, §11 and scope rule 5, §4.2 and D-58; retired wording added for A and B; the residual of D in the ledger.
