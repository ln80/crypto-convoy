# 004 — Team access management: autopilot, recovery root, invites, rosters

## Context

A review of team access management found that the library hands integrators *procedures* instead of *operations*:
- **Compromise remedy:** revoke the device, rotate the account key, re-key in every team, then a human owner approves in each team (D-21).
- **Out-of-band checks** on every join and re-key (AS-06).
- **Rotations are many writes**, so they can be half done (`completeRotation`).

That is where integrations go wrong. doconvoy will expose all of the account and team admin flows (rotations, revocations, approvals, recovery), so developer experience is a goal in its own right.

A double-check of the review confirmed two bugs and one doconvoy blocker:
- **Unpinned re-key approval.** `approveRekeys` seals to whatever keys are newest at rotation time, not the keys the owner reviewed (`#recipients`, `src/team/session.ts:479`). For the caller's own account, that can also replace their owner key (`versionOp`, `src/team/rotation.ts:76`).
- **`grant()` accepts any published key version**, including keys a re-key replaced (`src/team/session.ts:183`).
- **Rotations fail above about 100 members on doconvoy.** A rotation commits every grant in one batch, and doconvoy's DynamoDB transactions hold at most 100 items.

Agreed changes (decisions already taken):
- **P1 — Owner autopilot** (`reconcile`) and an owner-only API.
  - Rule: **automatic actions only reduce access; any increase needs a cryptographic proof or a human.**
- **P2 — Invite proofs.** The invite link carries a join secret, and the joiner's keys carry a MAC over it.
  - Invites are emailed by the server, so the default is a **hint** for the owner.
  - The integration can opt in to auto-approval with `autoApproveInvites`, documented as trusting the server for that join.
- **P3 — The recovery phrase as offline root of trust.**
  - A signing key derived from the phrase vouches for re-keys.
  - An owner's `reconcile` auto-approves recovery-signed re-keys for **members only**; owners' re-keys stay human-approved.
  - One call fixes a compromised account: `vault.secureAccount`.
- **P4 — Roster in the team key version record.** A rotation becomes one signed record, inline (no separate roster record).
  - Cap: 1,000 members per roster.
  - Chain loading starts from the lowest anchor.
- **P5 — Recovery phrase confirmation.** Setting up the recovery phrase becomes two steps: show it, then confirm it.

**Format policy.** v1 isn't frozen yet; plan 003 regenerated unreleased vectors the same way. So v1 records change in place and vectors are regenerated with `VECTORS_OVERWRITE_UNRELEASED=1`. There is no two-release reader/writer rollout.

## Execution mode (as plan 003)

- **Autopilot**, phase after phase. Stop only on a spec gap that would change a guarantee.
- **One commit per step.**
- **Gate before each commit:** `typecheck`, `npm test`.
  - Also `check:spec` when `docs/` changes, `test:fuzz` when a parser changes, and `build` + `test:package` when exports change.
- **Prove the guard** for every new security check: remove the check, watch its test fail, restore it.
- Save this plan as `.agents/plans/004-team-access-autopilot.plan.md` in B1.

---

## Phase A — Bug fixes, no format change

**A1. Pinned approvals.**
- `RotationOptions.approveRekeys` becomes `readonly { accountId; memberKeysVersion }[]`.
- `#recipients` refuses with `STALE_VERSION` if the account's newest published keys aren't the pinned version.
- §6.6 and §6.8 text: "an approval names the keys the owner reviewed".

**A2. `grant()` takes only the newest keys.** It refuses a `memberKeysVersion` older than the account's newest published one (§6.5 text).

**A3. Chain loading from the lowest anchor.** `loadChain` (`src/team/load.ts:28`) fetches `fromVersion: lowest anchor` instead of `1`. At first contact (no anchor), it still starts at 1. Make sure `verifyChain` (`src/team/chain.ts`) and the owner-key rule 4 still have what they need.

**Tests:**
- `test/security/member-rekey.test.ts`: a session thief publishes newer keys between `memberRequest` and `rotate` → refused. The same case for the caller's own account → the owner list is untouched.
- `key-substitution.test.ts`: granting replaced keys → refused.
- `rollback.test.ts`: a client with an anchor never fetches below it, and rollback/conflict detection still holds.

## Phase B — Spec change (docs only, protocol-change workflow)

**B1. Decisions** (`docs/decisions.md`):
- **D-31 — Owner autopilot.** `reconcile` covers what needs no judgement. Automatic actions may only narrow access. There is an owner-only API object.
  - Rejected: auto-regranting `outdated` accounts. A server could otherwise undo a removal by listing the member as active again.
- **D-32 — Invite proofs.** Hint by default; `autoApproveInvites` opt-in. Single use.
  - Rejected: always auto-approving, because the server delivers the secret.
- **D-33 — Recovery signing key.**
  - A phrase-derived Ed25519 key, pinned when the owner approves the account.
  - It proves re-keys; members' re-keys are auto-approved, owners' are not.
  - Replacing the phrase means a re-key in every team: proven by the old phrase if the user still has it, human-approved otherwise.
- **D-34 — Roster in the version record.**
  - A rotation is one signed record. Grants exist only for admissions between rotations.
  - Removes the server's "version with its signer's grant" batch, `completeRotation` and the `rotation-interrupted` warning.
- **D-35 — Recovery setup in two steps.** `beginRecoverySetup` shows the phrase; `confirmRecoveryPhrase` stores its wrap. No wrap means "recovery not set up".
- **D-36 — `secureAccount`.** One resumable call for a misused device or leaked credential: revoke other devices, rotate the account key, re-key every team with a recovery proof.
- **Updates:**
  - D-18: add the 1,000-member roster cap.
  - D-21: point to D-36.
  - D-10: rotation without the phrase drops the recovery wrap (D-35).
  - D-13 and D-19: owner changes now carry a roster.

**B2. Threats and properties.**
- **Updated threats:**
  - TH-02, TH-04: a server-delivered invite plus `autoApproveInvites` admits whoever the server chooses.
  - TH-37: mitigated by invite proofs and recovery proofs.
  - TH-10, TH-12, TH-13: the remedy is `secureAccount`.
  - TH-17: owner re-keys are never auto-approved.
  - TH-14: rotation-needed now comes from the signed roster.
- **New threats:**
  - TH-41: a leaked recovery phrase lets the thief replace a member's keys in every team (a race only a human ends). Owners are excluded from automatic approval.
  - TH-42: the server hides grants to suppress the rotation-needed signal. Mitigated by rosters; the residual is grants made between rotations.
  - TH-43: the invite link leaks through email, logs or the in-app view. The integration keeps it out of its own UI and logs.
- **Updated properties:**
  - SP-12: a recovery-signed re-key is approval; the old member keys still never are.
  - SP-15: the roster is the signed list of who received each version.
- **New properties:**
  - SP-22: automatic actions never widen access.
  - SP-23: a recovery-proven re-key, with Limits TH-41 and owners excluded.
  - SP-24: invite proof, with Limit: server-delivered invites.
- Every property gets its Verification paths, and the threat index is updated.

**B3. Key hierarchy** (`docs/key-hierarchy.md`):
- New key tables: recovery signing key, invite join secret.
- The tree diagram and the "who can open what" table.
- **Lifecycle scenarios rewritten:**
  - setup (two-step recovery);
  - losing a device (`secureAccount`);
  - replacing a phrase (with or without the old one);
  - joining with an invite;
  - rotation (one record);
  - removal through `reconcile`.

**B4. Protocol** (`docs/protocol.md`):
- **§1 labels:** `recovery-signing-key`, `member-keys-recovery`, `recovery-public-key`, `invite`, `invite-secret`, `invite-proof`. The roster's sealed keys reuse `grant-seal`, which means the same thing.
- **§3.5:** an invite link value carrying the anchor and the join secret, with a prefix.
- **§4.1:** the recovery `account-key-wrap` gains `recoveryPublicKey`, authenticated under the account key (label `recovery-public-key`), so a vault unlocked by PIN or device reads it authenticated.
- **§4.2 `member-keys`:**
  - adds `recoveryPublicKey` (optional: absent until recovery is set up), covered by the self-signature;
  - adds an optional `recoverySignature`, made by the recovery key the account's currently approved keys carry;
  - adds an optional `inviteProof { inviteId, mac }`.
- **§4.5 `team-key-version`:**
  - adds a `roster` list, sorted by `accountId`, 1–1,000 entries;
  - each entry is `{ accountId, u32 memberKeysVersion, bytes keysHash, bytes sealedTeamKey }`;
  - `keysHash` = BLAKE2b-256 over the signing, encryption and recovery public keys;
  - the payload hash covers the roster;
  - the signer must be in the roster;
  - version 1's roster is the creator.
- **§4.6 `grant`:**
  - only for admissions between rotations;
  - adds an optional `inviteId` (single use);
  - pins `keysHash`.
- **§4.x new `invite` record:**
  - fields: `teamId`, `inviteId`, `teamKeyVersion`, `wrappedSecret` (under that team key), an optional opaque `inviteeRef`, `createdAt`;
  - signed by an owner of that version.
- **§5:**
  - 5.2: derive the recovery signing key.
  - 5.3: setup no longer creates the recovery wrap.
  - New 5.3a: begin and confirm recovery setup.
  - 5.6: replacing the phrase, with an optional current phrase → a re-key in every team.
  - 5.7: rotation without the phrase drops the recovery wrap.
  - New 5.10: `secureAccount`, with steps, resume and the batch per team.
- **§6:**
  - 6.1 step 5: own key from the roster entry or the newest grant.
  - 6.4: join with an invite proof.
  - 6.5: grant the newest keys only, pinned.
  - 6.6: rotation = one record with a roster; resume removed.
  - 6.7: owner changes.
  - 6.8: approval names the reviewed version; recovery proof versus continuity hint.
  - New 6.9: `reconcile` — inputs, actions, the "only narrows" rule, `autoApproveInvites`, dry run.
- **§9:** new error `NOT_AN_OWNER`, replacing `TRUST_FAILURE not_an_owner` for a caller who is simply not an owner. `not_an_owner` stays for bad records.
- **§11:** `invite` rules (write-once, current version). `team-key-version` no longer needs a grant in the same batch. Size limit per record (about 250 KB).
- **§12:** the new API shape (phase F).
- **§13:** vectors.
- **§14:** remove the done items.

**B5. Integration and gates.**
- `docs/integration.md` server checklist:
  - the invite record;
  - the recovery wrap field;
  - the roster size, which fits DynamoDB's 400 KB item limit;
  - no more "version + signer's grant" batch rule;
  - never store or log invite links.
- `test/unit/traceability.test.ts`: a `PENDING` list for the new verification files (as in plan 003 A1).
- Property count updated; `npm run check:spec` passes.

## Phase C — Labels, records, vectors

- **C1.** `src/encoding/labels.ts` gets the new labels; the label test syncs with §1.
  - `src/encoding/link.ts` gets the invite link value, reusing `encodeAnchor`/`decodeAnchor`.
- **C2. Records:**
  - `src/records/member-keys.ts`: new fields, `hasValidRecoveryProof`, next to `hasValidContinuity`.
  - `src/records/team-key-version.ts`: the roster, its limits, `rosterEntryFor(accountId)`, opening one's own entry.
  - `src/records/grant.ts`: `inviteId`, `keysHash`.
  - New `src/records/invite.ts`.
  - `src/records/account-key-wrap.ts`: the recovery public key.
  - All validated before any crypto (§8), with fixed bounds.
- **C3. Vectors** (`test/vectors/generate/`):
  - regenerate `team-key.mjs` (roster, size limit, signer missing from the roster), `member-keys` cases, and `recovery-key.mjs` (signing key derivation);
  - new `invite.mjs`;
  - replay in `test/compatibility/`;
  - fuzz the new parsers in `test/fuzz/records.fuzz.test.ts`.

## Phase D — Account side (vault)

- **D1. Recovery signing key.**
  - `src/account/recovery-key.ts`: `deriveRecoverySigningKey(suite, accountId, phrase)`, wiped after use and never stored.
- **D2. Recovery setup in two steps.**
  - `vault.setup(pin)` no longer returns a phrase.
  - `vault.beginRecoverySetup()` → `{ recoveryPhrase }`, held in the vault's memory only.
  - `vault.confirmRecoveryPhrase(phrase)` stores the recovery wrap with its authenticated `recoveryPublicKey`.
  - `vault.status()` adds `recovery: "not-set-up" | "set-up"`.
- **D3. Member keys carry `recoveryPublicKey`.** `newMemberKeys` (`src/account/member-custody.ts`) takes it from the authenticated recovery wrap, and takes an optional recovery signing key to sign a re-key.
- **D4. Replacing the phrase.** `vault.replaceRecoveryPhrase({ currentPhrase? })`: two steps as in D2, then a re-key in every team. Proven if `currentPhrase` is given; hint only otherwise.
- **D5. `vault.secureAccount({ pin, phrase })`.**
  1. Revoke every other device.
  2. `rotateAccount` (`src/account/rotation.ts`), keeping the phrase.
  3. One commit per team for a recovery-signed re-key, which keeps DynamoDB batches small.
  4. Return a per-team report.
  - Rerunning resumes: a team is skipped once its newest keys carry a valid recovery proof from this phrase.
- **D6. `vault.warnings()`:** `recovery-not-set-up`, `secure-account-incomplete` (teams not yet re-keyed), `rekey-unproven` (re-keys that will need a human).
  - Every result is plain data, so it crosses the vault bridge (§12).

## Phase E — Team core: roster, invites

- **E1. Rotation as one record.**
  - `versionOp` (`src/team/rotation.ts`) builds the roster from the recipients.
  - `#rotate` commits **one** record.
  - Remove the second batch, the self grant, `completeRotation`, and the `rotation-interrupted` warning.
  - `MemoryRecordStore` (`src/testing/memory-record-store.ts`): drop the "version without its signer's grant" rule; add the invite rules and the size limit.
- **E2. Opening one's own key.** `openOwnGrant` (`src/team/grants.ts`) becomes `openOwnAccess`: the roster entry of the newest version that lists this account, or a newer grant; the newest wins.
- **E3. Membership views from roster ∪ current grants.**
  - Pure functions in new `src/team/membership.ts`: members, statuses, warnings, rotation-needed.
  - They reuse `checkOwnerRule` and `continuityOf`, and add proof kinds: `invite`, `recovery`, `continuity`, `none`.
  - This also fixes the N per-account round trips: list member keys once per team (`store.list({ type: "member-keys", teamId })`, as `loadChain` already does).
- **E4. Invites.**
  - Owner side: `createInvite({ inviteeRef? })` → link value.
  - Joiner side: `vault.joinTeam(teamId, { invite })` uses the anchor and adds `inviteProof`.
  - Verification lives in `membership.ts`.

## Phase F — Owner API, `reconcile`, DX, session split

**F1. Split `TeamSession`** (`src/team/session.ts`, 512 lines):
- `session.ts`: state, load, keys, content facade.
- `owner.ts`: `TeamOwner`.
- `membership.ts`: the pure views from E3.
- `reconcile.ts`: a pure planner plus an executor.
- `team.owner()` returns `TeamOwner` or throws `NOT_AN_OWNER`, so non-owner code can't reach admin operations.

**F2. `TeamOwner` API.** Plain data in and out; one entry point per admin intent:
- `overview(activeAccountIds)` → a snapshot:
  - version, owners;
  - each account with its status and proof kind, plus pinned `{ accountId, memberKeysVersion }` handles;
  - warnings, each naming its action.
- `approve(handles)`: grants new joiners, or rotates for re-keys; the library picks the operation. Handles are pinned (A1).
- `remove(accountIds)`: a rotation without them.
- `setOwners(owners)`.
- `createInvite(…)`.
- `reconcile(activeAccountIds, { autoApproveInvites?, dryRun? })` → a report:
  - `{ rotated?, granted[], approvedRekeys[], needsHuman[] }`.
  - The planner only ever narrows access, except for proven re-keys and opted-in invite joins.
  - On a store conflict (another owner acted), it reloads and replans once.
  - `dryRun` returns the plan, so an admin UI can show a preview.
- Keep `rotate`/`grant` as the low-level calls under `TeamOwner`; update `src/index.ts` exports.

**F3. Errors and DX.**
- Every admin result says what changed and what remains.
- Error codes are stable (§9), and every error is documented with the next action, matching the `Warning.action` style already used in `session.ts`.

## Phase G — Security and property tests

- **New files:**
  - `test/security/reconcile.test.ts` (SP-22): a server lists a removed member as active → no regrant. Unproven re-keys and owners' re-keys → `needsHuman`.
  - `recovery-proof.test.ts` (SP-23): a session thief without the phrase → hint only; a leaked-phrase race → reported; an owner's proven re-key → not auto-approved.
  - `invite-proof.test.ts` (SP-24): a wrong MAC, reuse, flag off or on.
  - `secure-account.test.ts`: a misused device → after `secureAccount` and an owner's `reconcile`, the old keys open nothing new; resume after interruption.
- **Updated files:** `member-removal`, `change-visibility` (roster reports, hidden grants → TH-42), `owner-continuity`, `member-rekey`, `recovery`, `account-rotation`.
- **Property test:** for random snapshots, the `reconcile` plan never adds a recipient without a proof or an opt-in (`test/properties/`).
- Remove the `PENDING` list from traceability.

## Phase H — Docs for integrators

- **README "Admin recipes":**
  - onboarding (setup → recovery confirmation → join with an invite);
  - a member leaves;
  - lost device versus misused device;
  - lost phrase;
  - owner handover;
  - what to call on every owner session (`reconcile`).
- **Update `.agents/plans/002-doconvoy-fit-review.md`** with the doconvoy items:
  - keep invite links out of the UI and logs;
  - DynamoDB: one roster record per rotation, under 400 KB;
  - map the `overview`/`reconcile` reports to the admin screens;
  - the Go server rules from B5.

---

## Verification

- **Each phase:** `npm run typecheck`, `npm test`. Also `npm run check:spec` (B onward), `npm run test:fuzz` (C), `npm run build && npm run test:package` (F, H).
- **Guard proofs:** A1, A2, and each new check in D, E and F (delete it → its test fails → restore).
- **End to end:** `test/compatibility/scenario.test.ts` extended:
  1. two owners, about 30 members;
  2. invite join, auto-approved by the flag;
  3. member removal through `reconcile`;
  4. a misused device fixed by `secureAccount` plus `reconcile`;
  5. a phrase replaced without the old one → `needsHuman`.
- **Size check:** a roster of 1,000 entries serializes under 250 KB (a unit test in C2).

---

## Design notes settled in phase B

Refinements found while writing the spec; the spec is the reference.

- **Recovery is required before team work.** `createTeam` and `joinTeam` throw `RECOVERY_NOT_SET_UP` until the phrase is confirmed (D-35), so every `member-keys` record carries a `recoveryPublicKey` (required, no optional case).
- **Grants and roster entries pin `keysHash`** (a labelled hash of the member's public keys, recovery key included) instead of carrying the public keys; readers resolve the keys from the `member-keys` record and check the hash.
- **The recovery public key is read authenticated** from `wrappedRecoveryPublicKey` (under the account key) in the recovery `account-key-wrap`.
- **`secureAccount({ phrase, newPin })`**: rotates the account key first (which already cuts every other device, D-10), then re-keys each team in its own commit with a recovery signature. It reports `{ rekeyed, failed }`; a failed team is retried with `vault.rekey(teamId, { phrase })`. No resume marker, no `secure-account-incomplete` warning.
- **Invite proofs auto-approve only for invites of the current version** with no current-version grant naming them (single use without a server rule). A rotation turns older invites into hints.
- **Errors:** `NOT_AN_OWNER` and `RECOVERY_NOT_SET_UP` are new codes.
- **Owner API defaults:** `setOwners` and `remove` keep every current holder unless told otherwise, so callers don't build keep lists.
