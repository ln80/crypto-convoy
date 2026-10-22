# Plan 008: close the review 001 gaps (A, B, G, D, C)

## Context

Spec review 001 (`.agents/reviews/001-spec-divergence.md`) found five open gaps after plans 005–007. The user decided each one:

- **A (High):** an unlocked vault, which a stolen device gives without any credential (`vault.unlock()`), can replace the recovery phrase, change the PIN and rotate with a PIN of its choice. The thief then owns the account, and `secureAccount` (TH-10's remedy) no longer works. **Decision:** changing a credential needs a current credential, not just an open vault; `rotate` always needs the phrase. Accepted costs: a device alone can't change credentials; a PIN thief can still replace the phrase (the remedy is B); a PIN change costs two OPRF evaluations; device revocation stays open-vault only.
- **B (High):** a support restore after a rotation is unspecified. §11 says retired `member-keys-wrap` records are deleted, the testing store archives them, and nothing moves the current version back. **Decision:** the server never destroys private records (archive everything, including `team-state` revisions), plus a support action "restore an account key version".
- **G (Medium):** a session thief can write a garbage `team-state` (every device then fails with `state_unreadable`) or delete `member-keys-wrap` records. **Decision:** covered by B's archive, with a new threat entry; no self-repair.
- **D (Medium):** new member keys take the newest *held* version + 1, so a session thief who publishes under the victim's account first blocks joins and re-keys forever with `STALE_VERSION`, including `secureAccount`'s re-keys. TH-37's `key_mismatch` detection doesn't exist. **Decision:** new keys take the newest *published* version + 1; a vault warning `foreign-member-keys`; the integration ends other sessions *before* `secureAccount`.
- **C (Medium):** SP-15 claims every admission is reported; only owner changes are. **Decision:** add `team.memberChanges`, computed like `ownerChanges`.

There is no record layout, label, vector or error code change. Only operation rules, the server contract, one warning code, one session getter and API signatures change. That is allowed before the freeze.

## Execution

- **Phase 0, on the current branch `plan-006-receiver-anchor`:** commit the pending work in two commits:
  1. `docs(spec): align stale text and threat ↔ property links (review 001)`;
  2. `chore: spec checks, retired terms, spec-review workflow and hook`.
- **Then branch `plan-008-review-gaps`.** Copy this plan to `.agents/plans/008-review-gaps.plan.md`.
- **One commit per phase.** Gates as in `.agents/guides/workflow.md`: `typecheck`, `npm test`, `check:spec`, plus `build` and `test:package` when the API changes.

## Phase A: Spec (protocol-change workflow, ripple step included)

**Decisions** (`docs/decisions.md`):
- **D-41 "Changing a credential needs a current credential"** (gap A):
  - `changePin` needs the current PIN (one evaluation, purpose `unlock`) or the phrase; with no PIN set, it needs the phrase.
  - Replacing the phrase needs the current phrase or the current PIN. The first setup on a new account is unchanged.
  - `rotate` needs the current phrase; a new PIN is optional.
  - Rejected: accepting the gap; allowing only the phrase to replace the phrase (lost phrases are common).
  - Update D-10 (credentials gate rotation), D-35 (remove "rotation without the phrase drops recovery") and D-40 (the phrase is now always required).
- **D-42 "The server never destroys an account's private records; a version can be restored"** (gaps B and G):
  - Extends D-39 to `member-keys-wrap` and `team-state`: every `team-state` write archives the previous revision.
  - The support action "restore account key version v": v becomes current, records of later versions are archived, v's records come back.
  - Consequences: devices that accepted the later version refuse v (`rollback`) and must be reset; owner approvals of a thief's keys stay, and the user re-keys with a human approval.
- **D-43 "New member keys follow the newest published version"** (gap D): number from the published versions, add the `foreign-member-keys` warning, and the integration ends other sessions before `secureAccount`.
- **D-44 "Membership changes are reported like owner changes"** (gap C).

**Threats** (`docs/threat-model.md`):
- **New TH-45, "An unlocked vault replaces the account's credentials"** (A7, A9): mitigated by SP-25.
- **New TH-46, "Session thief corrupts private team records"** (A11): mitigated by SP-26, the residual accepted as availability.
- **New TH-47, "Session thief takes a member's key version numbers"** (A11): mitigated by SP-12.
- **TH-10:** a device alone can't change credentials (D-41).
- **TH-11:** a PIN thief can replace the phrase; the remedy is a support restore (SP-26).
- **TH-36:** also cites SP-26; restores after a rotation.
- **TH-37:** detection is the `foreign-member-keys` warning, no longer `key_mismatch`.
- **TH-17:** member changes are reported (SP-15).

**Properties** (`docs/security-properties.md`):
- **New SP-25, "An open vault alone can't change the account's credentials."** Verification: `test/security/credential-rotation.test.ts`, `test/security/account-rotation.test.ts`.
- **New SP-26, "A session can't destroy an account's private records."** Archive and version restore. Verification: new `test/security/record-archive.test.ts`.
- **SP-12:** keys published under the account by someone else don't block the member's own re-key, and are reported. Verification adds cases to `member-rekey.test.ts` and `secure-account.test.ts`.
- **SP-15:** "every change in the chain since this client's last verified state", owners and members. Verification: `change-visibility.test.ts`.
- **SP-09 and SP-11:** the wording follows D-41 (rotation keeps the phrase).

**Key hierarchy:** the PIN-change, phrase-replacement, lost-phrase (replace with the PIN, then rotate), rotation and losing-a-device scenarios, plus a new "restoring an account" scenario.

**Protocol** (`docs/protocol.md`):
- §5.4: `recover` passes the phrase to the PIN setting.
- §5.6: the credential rules.
- §5.7 step 2: the phrase is required, and the "without the phrase" paragraph is removed.
- §5.9 / §6.4 / §6.8 step 1: the version is the newest published + 1.
- §5.11: end other sessions before securing.
- §6.1 step 3: member changes.
- §11 and scope rule 7: private records are archived; `team-state` revisions too; the version restore.
- §12 API:
  - `changePin(newPin, { currentPin } | { phrase })`;
  - `confirmRecoveryPhrase(phrase, { currentPhrase } | { currentPin })`;
  - `rotate({ phrase, newPin? })`;
  - the `foreign-member-keys` warning;
  - `team.memberChanges`;
  - the `RecordStore` `compareAndSet` contract archives the previous revision.

**Retired terms** (`scripts/retired-terms.json`):
- Remove the three gap-B `known` entries once §11 and `integration.md` change.
- Add "the current one or a new one", "drops the recovery wrap", `rotate({ pin` and TH-37's "`key_mismatch`" detection wording.

**Also:**
- `docs/integration.md`: end sessions before `secureAccount`; the support restore; product removal archives.
- `docs/using.md`.
- `.agents/reviews/001`: record the decisions.

**Gate:** `npm run check:spec` passes.

## Phase B: Code for gap A (credentials)

- **`src/account/unlock-methods.ts`:**
  - new `verifyPin(ports, account, pin)`: fetch the live PIN wrap (`fetchWrap`), `openWithPin(…, "unlock")`, compare with `account.key` using `suite.equal`, else `WRONG_CREDENTIAL`; no PIN wrap is `PIN_NOT_SET_UP`.
  - new `verifyPhrase(ports, account, phrase)`: reuse the check in `rotateAccount` (open the current recovery wrap) or `recoverySigner` in `src/account/recovery.ts`.
- **`src/account/vault.ts`:**
  - `changePin(newPin, proof)` verifies first; `recover` passes `{ phrase }`.
  - `confirmRecoveryPhrase` requires `currentPhrase` or `currentPin` when a recovery wrap exists.
  - `rotate({ phrase, newPin? })`.
  - The upgrade-on-unlock in `unlockWithPin` stays internal (the PIN was just verified).
- **`src/account/rotation.ts` `rotateAccount`:** the phrase is required (`RECOVERY_NOT_SET_UP` without a recovery wrap); `pin` is renamed `newPin`.
- **Tests:**
  - `test/security/credential-rotation.test.ts` (SP-25, SP-09): an open vault alone can't change the PIN, replace the phrase or rotate; the current PIN works and spends exactly one extra evaluation; the no-PIN state needs the phrase; a wrong current credential gives `WRONG_CREDENTIAL` and writes nothing.
  - `account-rotation.test.ts`: `rotate` without the phrase is refused.
  - Adjust the existing callers in tests and README examples.

## Phase C: Code for gap D (key version numbers and the warning)

- **`src/account/member-custody.ts` (or `recovery.ts`):** a helper `nextMemberKeysVersion(ports, accountId, teamId)` = max of the published `member-keys` (`store.list({ type: "member-keys", teamId, accountId })`) and the held bundles, + 1. Used by `joinTeam`, `rekeyTeam` and the team creation path.
- **`src/account/vault.ts` `warnings()`:** add `foreign-member-keys` with `teamIds` (a published version newer than the newest held bundle), action `rekey`. Extend the `VaultWarning` union.
- **Tests:**
  - `member-rekey.test.ts`: a session thief publishes v(n+1); the member's re-key goes to v(n+2) and is approved; the warning is raised before and cleared after.
  - A first join preempted at v1 still joins, at v2.
  - `secure-account.test.ts`: keys pre-published by the thief don't block `secureAccount`'s re-keys or `reconcile`'s approval.

## Phase D: Code for gap C (membership changes)

- **`src/team/chain.ts`:** next to the `ownerChanges` loop (lines 85–103), compute `memberChanges` (version, signer, and the accounts added, removed or re-keyed, by `keysHash`) for records above the highest anchor, by the same rule as `ownerChanges`.
- **`src/team/session.ts`:** a `memberChanges` getter next to `ownerChanges`.
- **`src/index.ts`:** export the `MemberChange` type.
- **Tests:** `change-visibility.test.ts`: a member admitted at v5 and removed at v6 is reported to a member whose anchor is v4; a re-key is reported; nothing is reported below the anchor.

## Phase E: Testing kit for gaps B and G (archive and version restore)

- **`src/testing/memory-record-store.ts`:**
  - `compare-and-set` archives the previous `team-state` revision (`archiveLive`).
  - New support helper `restoreVersion(accountId, version)`: sets the version, archives the live records of later versions, brings back the archived `account-key-wrap` and `member-keys-wrap` records of that version.
  - The existing `restore(key, index)` covers `team-state` and single records.
- **New `test/security/record-archive.test.ts` (SP-26, TH-36, TH-46):**
  - A garbage `team-state` gives `state_unreadable`; after restoring the previous revision the team opens.
  - A deleted `member-keys-wrap` is restored.
  - A PIN thief replaces the phrase and rotates; `restoreVersion` brings back the user's PIN, phrase and teams.
  - A device that accepted the thief's version reports `rollback`.
- **`test/unit/memory-store.test.ts`:** the store-rule cases.

## Phase F: Integration docs, build and review

- README, `docs/using.md`, `docs/integration.md`: the new signatures, the warning, `memberChanges`, the support restore recipe, ending sessions before `secureAccount`.
- `npm run build`, `npm run test:package`. The public API report changes (`changePin`, `confirmRecoveryPhrase`, `rotate`, `VaultWarning`, `MemberChange`).
- Run the `spec-review` skill. Write `.agents/reviews/002-…`; it must find no new divergence from this plan.
- Append execution notes to the plan file.

## Phase G (separate, last): reorganise the threat model by actor

- Group the entries by actor or asset (with a section on the unlocked vault: A7, A9), shorten dispositions to cite instead of restate, and move the dormant threats (TH-33, TH-42, TH-43) to their own table.
- Ids and content don't change; `check:spec` (threat index ↔ entries) guards it.

## Verification

- `npm run check:spec` after Phase A and every later docs edit (the hook also runs it).
- `npm run typecheck && npm test` after each code phase. The security project covers SP-09, SP-11, SP-12, SP-15, SP-25 and SP-26; the traceability test confirms that the new properties' test files exist and cite them.
- `npm run build && npm run test:package` after Phase F.
- The `spec-review` skill (review 002) as the final check that threats, properties, protocol and code agree.
