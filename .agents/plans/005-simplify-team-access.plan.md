# 005 — Simplify team access: roster-only, no invite proofs, no continuity hint

## Context

Plan 004 (branch `plan-004-team-access`) added an owner autopilot, a recovery-phrase root of trust, rosters in version records, invite proofs and two-step recovery. An external review, and our own evaluation, found that some of this is a second way to do the same job:

- **Grants beside rosters.** Readers, `reconcile` and the overview all accept "roster or grant". Grants leave a residual (TH-42: a server can hide them) and carry TH-33. Doconvoy teams are workspace-sized, so a roster write per join is affordable.
- **Invite proofs (D-32).** Doconvoy emails invites from its own server, so a proof only protects against attackers who can't read that email. Meanwhile it costs a record type, a link format, three labels, single-use logic and the risky `autoApproveInvites` flag.
- **The continuity signature** is only a hint. Now that recovery proofs exist, it adds little.

The user favours a smaller protocol. Decisions:
- **Remove:** grants (roster-only), invite proofs (D-32 → Deferred), the continuity signature.
- **Keep:** the recovery-phrase approver (D-33) with its owner brake, `secureAccount`, `reconcile`, two-step recovery, rosters and the keys hash, and the invite **anchor** (it predates plan 004).
- **Also fix** the protocol gaps found in the last review: §6.9 `inactive-owner` and the warnings list, the §13 over-1,000 claim, the §6.4 anchor wording, §5.10 phrase normalisation, and §12 omissions.

**Outcome:** docs and code aligned, with a protocol smaller than before plan 004 that keeps its main gains. v1 isn't released, so formats change in place and vectors are regenerated with `VECTORS_OVERWRITE_UNRELEASED=1`.

## Execution mode (as plans 003/004)

- **Branch:** `plan-005-simplify`, from `plan-004-team-access`.
- **One commit per phase.**
- **Gate before each commit:** `typecheck`, `npm test`.
  - Also `check:spec` when `docs/` changes, `test:fuzz` when a parser changes, and `build` + `test:package` when exports change.
- **Prove the guard** for each changed security check (remove it → its test fails → restore).
- Save this plan as `.agents/plans/005-simplify-team-access.plan.md` in phase A.

---

## Phase A — Spec (docs only, protocol-change workflow)

**A1. Decisions** (`docs/decisions.md`). Ids are never reused; removed items keep a status.
- **D-32** → Status **Deferred** (like D-11).
  - Keep the design as "recorded for a later version".
  - Add the reason: server-delivered invites make the proof a hint; the `autoApproveInvites` flag hands admission to mail delivery.
- **New D-37 — Roster-only: every access change is a rotation.**
  - Joins, re-keys and removals all append a version whose roster lists the recipients. No grant record.
  - Rejected: grants between rotations (a second way to hold a version, TH-42 residual, TH-33).
  - Consequence: a new team key per join; writers retry once on a version change; first-contact download grows with the number of joins.
- **New D-38 — No continuity signature.** Re-keys are proven by the recovery key or approved by a human. Rejected: a hint that the attacker's copied keys can also produce.
- **Updates:**
  - **D-34:** grants removed by D-37.
  - **D-31:** no invite admission step.
  - **D-33:** proofs are `recovery` or `none`.
  - **D-13, D-19:** wording ("grant" becomes "roster entry").
  - **D-07 consequence:** unchanged.

**A2. Threats and properties.**
- **TH-02, TH-04:** drop the invite-proof sentences; keep the invite anchor.
- **TH-33:** "No grants in v1 (D-37): a removed owner can't sign any later version record (SP-05)". Keep the id.
- **TH-37:** mitigations are the recovery proof, pinned approvals and `key_mismatch` detection; residual: a human approves an unproven request.
- **TH-42:** Mitigated: SP-15. The roster is the only way to hold a version; no residual.
- **TH-43:** Superseded, no invite secret in v1 (D-32 deferred). Keep the entry and its index row.
- **SP-04:** "from its roster entry".
- **SP-12:** remove the continuity hint; the recovery signature is the only proof.
- **SP-15:** no grants between rotations.
- **SP-22:** no invite rule; inactive owners → human.
- **SP-24:** mark deferred (D-32), as SP-13 and SP-20 are; its Verification moves to "when D-32 lands".
- Update the index rows.

**A3. Key hierarchy:**
- Remove the invite join secret key table and the grant rows in "Signed records".
- Owner rule: "A version record n is valid only if…"; no grant rule.
- Scenarios:
  - joining = owner approves → rotation with the joiner in the roster;
  - re-key = recovery-proven or human, no continuity;
  - removal and rotation unchanged.
- Remove the invite-link row in "Who can open what".

**A4. Protocol** (`docs/protocol.md`):
- **§1:**
  - drop the labels `grant`, `grant-seal`, `invite`, `invite-secret`, `invite-proof`, `member-keys-continuity`;
  - drop `inviteId` from Identifiers;
  - drop "an invite" from link values.
- **§2:** keep the roster and 384 KiB bounds.
- **§3.5:** remove `encodeInvite`; keep `encodeAnchor`.
- **§4 catalogue:** remove the `grant` and `invite` rows.
- **§4.2 `member-keys`:** remove `continuitySignature` and `inviteProof`.
  - Proofs: `recoverySignature` only.
  - Keep `keysPayload` and `keysHash`.
  - Reader checks: recovery proof against the held keys' recovery key.
- **§4.5 `team-key-version`:**
  - rule 5 unchanged;
  - the owner rule loses the grant clause;
  - wording: "a reader opening its own roster entry" is the only way to hold a version.
- **§4.6 `grant` and §4.11 `invite`:** keep the section numbers with a one-line "Removed before release (D-37 / D-32 deferred)", so § references stay stable.
- **§5.9:** proofs on member keys: the recovery signature when the phrase is entered.
- **§5.10:** state the comparison: Unicode NFKD, case and whitespace ignored.
- **§5.7, §5.11:** a phrase given without recovery set up is `RECOVERY_NOT_SET_UP`.
- **§6.1 step 5:** own access = the newest version whose roster lists one of this account's keys.
- **§6.4:**
  - invite = the bare anchor (`team.inviteAnchor()`);
  - the joiner passes it to `openTeam(teamId, { anchor })` on the first open: that's where it becomes the first anchor.
- **§6.5** becomes "Approving members (owner)": approval is a rotation (§6.6) adding the approved keys to the roster; several approvals share one rotation.
- **§6.6:**
  - recipients = kept holders (roster of n), plus approved handles;
  - an approved handle either replaces a holder's keys or adds a new account;
  - pinned to the reviewed `memberKeysVersion`, else `STALE_VERSION`.
- **§6.7:** "current access signed by the removed owner" = the roster of a version they signed.
- **§6.8:** classes become `proven` (recovery) or `unproven`.
- **§6.9:**
  - statuses unchanged;
  - proof = `recovery` | `none`;
  - warnings = `single-owner`, `members-awaiting-approval` (includes `outdated`), `rekeys-awaiting-approval`, `rotation-needed` (action `reconcile`);
  - reconcile steps: remove inactive holders **except owners** (`inactive-owner`), approve proven re-keys of non-owners, one rotation;
  - reasons: `awaiting-approval`, `outdated`, `rekey-unproven`, `owner-rekey`, `inactive-owner`.
- **§7.1 / §7.4:** writers whose write is refused because the version changed reload, re-wrap at the new current version, and retry once; a second refusal, or an id already used, is `STALE_VERSION`.
- **§9:** unchanged codes; note `team.owner()` throws `NOT_GRANTED` without current access, `NOT_AN_OWNER` otherwise.
- **§11:** remove the `grant` and `invite` rows; the item and inbox current-version rule stays.
- **§12:**
  - owner API: `overview`, `reconcile(active, { dryRun? })`, `approve(handles)`, `remove`, `setOwners(owners, { keep? })`, `grantedBy`, low-level `rotate({ keep, approve? })`, `version`;
  - vault: `joinTeam(teamId)`, `openTeam(teamId, { anchor? })`, `rekey(teamId, { phrase? })`;
  - overview fields as implemented; the report's `dryRun` field.
- **§13:**
  - drop `invite.v1.json`;
  - `team-key.v1.json` without grant cases or the over-1,000 claim (the cap is covered by a unit test);
  - `link.v1.json` without invites.
- **§14:** add D-32 to "Later, not in v1".

**A5. Scope and integration:**
- **`docs/scope.md`:** remove invite proofs from "What the library does" items 4 and 5 and from the policy list; remove the invite-link delivery duty (keep "carrying invite anchors").
- **`docs/integration.md`:**
  - remove the `grant` and `invite` storage keys and write conditions;
  - the "Invites and team administration" section keeps `reconcile`, `secureAccount` and approvals;
  - drop the `invite.v1.json` row.
- **`test/unit/traceability.test.ts`:** the property count goes 22 → 21 non-deferred (SP-24 deferred).

## Phase B — Records, labels, vectors

- **Delete** `src/records/grant.ts` and `src/records/invite.ts`.
  - `src/encoding/link.ts`: remove `encodeInvite`/`decodeInvite`/`InviteLink`.
  - `src/encoding/labels.ts`: remove the six labels.
- **`src/records/member-keys.ts`:**
  - remove `continuitySignature`, `inviteProof`, `hasValidContinuity`, `hasValidInviteProof`, `inviteMac`;
  - `MemberKeysProofs` keeps `recoverySigningSecretKey`;
  - keep `keysHash`, `hasValidRecoveryProof`.
- **`src/ports.ts`:** remove the `grant` and `invite` RecordKey/RecordQuery variants.
- **`src/testing/memory-record-store.ts`:** remove the grant and invite identities and rules (items and inboxes keep the current-version rule).
- **Vectors** (`test/vectors/generate/`):
  - `team-key.mjs`: remove `grantRecord` and grant cases; member keys without continuity.
  - `link.mjs`: remove the invite cases.
  - Delete `invite.mjs` and `invite.v1.json`.
  - Regenerate `team-key.v1.json` and `link.v1.json`.
  - `recovery-key.mjs` unchanged.
- **Replays:**
  - `test/compatibility/team-chain.vectors.test.ts`: drop the grant cases.
  - `encoding.vectors.test.ts`: drop invites.
  - Delete `test/compatibility/invite.vectors.test.ts`.
- **Fuzz:**
  - `test/fuzz/records.fuzz.test.ts`: remove the invite link; the OPTIONAL list = `recoverySignature`.
  - `test/support/records.ts` and `parsers.ts`: drop grant and invite samples.

## Phase C — Team and vault (roster-only)

- **`src/team/grants.ts` → `src/team/access.ts`** (rename; it holds no grants):
  - `checkOwnerRule` (for invites) and `listGrants` go;
  - `Holder` = a roster entry plus the version's signer;
  - `holdersOf(record)` reads the roster only;
  - `openOwnAccess` scans rosters only. It reuses the existing fallback to `chainFrom(1)` when nothing recent is found.
- **`src/team/rotation.ts`:** remove `grantOp`; keep `versionOp`, `recipientFromKeys`.
- **`src/team/owner.ts`:**
  - `RotationOptions` becomes `{ keep, approve? }`: approved handles replace a holder's keys or add a new account (pinned through `#reviewedKeys`). This merges `approveRekeys` and grants.
  - `approve(handles)` = one rotation keeping every holder plus the handles.
  - `grant` and `createInvite` are removed.
  - `#snapshot`: `heldBefore` from rosters only (loaded chain, then `chainFrom(1)` if unresolved); no invites.
  - `reconcile` options: `{ dryRun? }`.
- **`src/team/membership.ts`:**
  - `ProofKind` = `"recovery" | "none"`;
  - remove `OpenedInvite`, `InvitePolicy`, the admit step and `invite-not-accepted`;
  - keep `inactive-owner` and `owner-rekey`.
- **`src/team/session.ts`:**
  - `#holdersOf` reads the roster;
  - **writer retry:** in `beginItem`'s seal and `createInbox`, on `STALE_VERSION`, reload (`#load`). If the current version moved, re-wrap with the new version's key and commit once more; otherwise rethrow (id taken).
- **`src/account/`:**
  - `member-custody.ts` `NewMemberKeysOptions` loses `previous` and `invite`;
  - `recovery.ts` `rekeyTeam` drops continuity;
  - `vault.ts`: `joinTeam(teamId)` and `openTeam(teamId, { anchor? })`.
- **`src/index.ts`:** remove `InvitePolicy`; keep the other owner and membership types.

## Phase D — Tests

- **Delete** `test/security/invite-proof.test.ts`.
- **Convert grant-based tests:**
  - `test/support/teams.ts` `team()` admits with `owner.approve([keys])`;
  - `test/support/forge.ts`: `forgeGrant` and `forgeMemberKeys` lose the grant and continuity options; `accessOf` reads rosters only;
  - `key-substitution`: a forged grant becomes a forged roster entry or version (refused);
  - `owner-chain`: TH-33 → a removed owner's version record is refused (already covered);
  - `member-rekey`: continuity cases become `proof: "none"`;
  - `change-visibility`, `member-removal`, `owner-continuity`, `scenario`: approvals are rotations, so version numbers shift (assert on state and access rather than exact numbers where possible).
- **New tests:**
  - `test/security/member-removal.test.ts` (or `change-visibility`): every join appears in the roster that every member sees (TH-42 closed).
  - A writer-retry test: a draft sealed after a concurrent approval lands at the new version and opens.
  - A unit test: a roster of 1,001 entries is refused, and a 1,000-entry record stays under 384 KiB.
- **`test/properties/reconcile.properties.test.ts`:** remove the invite cases.
- **Guard proofs:** pinned approvals in the merged `approve`, the roster-only own access, the writer retry's "rethrow if the version didn't move".

## Phase E — Integrator docs and notes

- **README:**
  - admin recipe table: invite = the bare anchor link; approve = a rotation;
  - remove `autoApproveInvites` and `createInvite`;
  - writers retry automatically.
- **`.agents/plans/002-doconvoy-fit-review.md`:**
  - replace the invite bullets with "the invite link carries `team.inviteAnchor()`";
  - Go server: no `grant`/`invite` records; one version record per access change (≤ 384 KiB).
- **`.agents/plans/005-…`:** execution notes.
- **`.learning/`** (local):
  - `join-secret-proof.md` → note it was deferred and why (server-delivered secret);
  - `signed-roster.md` → roster-only;
  - new lesson `second-path-tax.md` ("a second way to do the same job costs every reader").

---

## Verification

- **Each phase:** `npm run typecheck`, `npm test`; `npm run check:spec` (A onward); `npm run test:fuzz` (B); `npm run build && npm run test:package` (C, E).
- **Spec-code alignment check** (end of D):
  - grep `docs/` and `src/` for `grant`, `invite`, `continuity`, `completeRotation`, `autoApproveInvites`: only deferred or historical mentions remain;
  - re-run the protocol-vs-code review of plan 004 (records §4.1/§4.2/§4.5, §6.6, §6.9, §12) against the code.
- **End to end:** `test/compatibility/scenario.test.ts`:
  1. setup with recovery;
  2. create a team; invite with the anchor; join; approve (rotation);
  3. content creation during an approval (writer retry);
  4. removal through `reconcile`;
  5. `secureAccount` and a proven re-key approved by `reconcile`;
  6. the split-context transfer.
