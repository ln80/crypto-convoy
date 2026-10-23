# Plan 009: anchor floor in the member keys (review 003 A), with I and J

## Context

Review 003 (`.agents/reviews/003-round-3.md`) finding **A (high)**: a new device of an existing member has no local anchor. If the server doesn't serve the account's `team-state`, or a session thief deletes it, `loadChain` (`src/team/load.ts`) verifies from version 1 with no anchor: first contact. A malicious server can then present a forged team whose roster seals a team key of its own to the member's public keys; the member is `ready` and writes new items to the server. `docs/key-hierarchy.md:153` claims the opposite.

**Decision (user):** an **anchor floor** inside the member keys bundle (`member-keys-wrap`), the one private record the vault can't do without and the server can't forge or alter. It is set at team creation (version 1) and at join (the invite anchor, which moves from `openTeam` to `joinTeam`), carried forward by re-keys and account rotations, and carried in transfers to other contexts.

Small items from the same review:
- **I (low, unconfirmed):** `advanceAnchor` (`src/team/anchors.ts`) rereads `team-state` after a compare-and-set conflict with `[bundle]` only, while the first read uses every bundle: a state written under another bundle's `teamStateKey` fails with `state_unreadable` where §6.1 step 7 expects a reload.
- **J (low):** after a phrase replacement (`confirmRecoveryPhrase`, or `secureAccount` with `newPhrase`), a failed team's retry `rekey(teamId, { phrase })` must use the new phrase, whose proof doesn't verify against the keys the team holds; the old phrase, which would, is refused.

Formats change (`member-keys-wrap` plaintext, transfer body): allowed, v1 is unreleased. Vectors are regenerated and noted in §13.

## Design

**Floor semantics** (one rule each, kept small):
- **What it is:** an optional `(version, recordHash)` in the bundle, always an anchor the vault verified or built: the chain is write-once, so it stays in the honest chain forever.
- **When it is used:** §6.1 step 1 adds it **only when no local anchor and no readable `team-state` exist**. Any real `team-state` anchor is at or above the floor in the same chain, so the normal path keeps fetching from the newest anchor (no download regression, D-34's "old rosters only at first contact" holds). A withheld or deleted `team-state` on a new device now starts from the floor, not from first contact.
- **Set at creation:** `newTeamOps` builds version 1 first, then wraps the bundle with floor `(1, recordHash(v1))`. Needs `newMemberKeys` split so the wrap is built after the record (`src/account/member-custody.ts`).
- **Set at join:** `vault.joinTeam(teamId, { anchor? })` decodes the anchor (`MALFORMED_RECORD`, `UNSUPPORTED_VERSION`), then verifies that the served chain contains it (`loadChain` with no bundles and the invite anchor; `TRUST_FAILURE` `rollback`/`chain_conflict`), **before writing anything**. Otherwise a bad link would be baked into the keys for good. Without an anchor: no floor (first contact on the first open, as today).
- **Carried:** a re-key (`rekeyTeam`, `rekeyTeams`) copies the newest bundle's floor. If it has none, the vault fills it from an anchor it already trusts: its local anchor if it has `anchors`, else the server's `team-state` anchor opened with its own bundles (`readServerState`). Account rotation re-wraps the opened bundle, floor included (`src/account/rotation.ts`). Clean-up (§6.8 step 4) keeps the newest bundle and its floor.
- **Transfers:** each transfer entry carries its bundle's floor; the receiver needs no anchor option.
- **API:** `openTeam(teamId, { anchor })` and the receiver's `openTeam(ports, transfer, { anchor })` lose the `anchor` option; `joinTeam(teamId, { anchor })` gains it. `team.inviteAnchor()` is unchanged.

**Layouts:**
- `member-keys-wrap` plaintext: `signingSeed (32) ‖ encryptionSecretKey (32) ‖ teamStateKey (32) ‖ enc(optional<u32 version, bytes recordHash>)`: 97 or 137 bytes. Readers check one of the two exact lengths and a 32-byte hash.
- Transfer body (§3.8 step 2): each entry gains `optional<u32 version, bytes recordHash>` after `teamStateKey`.

**I:** confirm with a test that injects a concurrent `team-state` write under the older bundle's key between the read and the compare-and-set (`TamperingStore.onCommit`, `test/support/fake-store.ts`); fix by rereading with every bundle the session holds.

**J (recommended fix):** `vault.rekey(teamId, { phrase })` accepts the current phrase **or** a phrase whose recovery key one of the vault's bundles for that team carries; the proof is signed with that phrase's key, and the new keys carry the current recovery key. The proof means what it already means (D-33, TH-41's race unchanged). The retry after `confirmRecoveryPhrase` or `secureAccount` with `newPhrase` then uses the **old** phrase and stays proven. Update D-45's Consequence and §5.6 / §5.11 step 3.

## Execution

- Branch `plan-009-anchor-floor` from `plan-008-review-gaps` (it holds review 003's commits). Copy this plan to `.agents/plans/009-anchor-floor.plan.md`.
- One commit per phase. Gates (`.agents/guides/workflow.md`): `npm run typecheck`, `npm test`, `npm run check:spec`, then `npm run build` and `npm run test:package` (the API changes).

## Phase A: spec (protocol-change workflow, ripple included)

- **Decisions:** D-48 "Member keys carry an anchor floor" (problem, decision as above, rejected: anchor in the public `member-keys` record, which changes a signed public format; requiring `team-state` to exist, which the server can serve at an older, anchorless revision; using the floor on every open, which downloads the chain from the join version each time). D-49 for J. Update D-29/plan-006 wording on the receiver anchor, D-34's fetch note if needed, and D-45's retry sentence.
- **Threats:** TH-04 (an existing member's new device starts from the floor; first contact remains for a joiner without an invite anchor until a re-key), TH-05 (withholding `team-state` no longer means first contact), TH-46 (a deleted `team-state` falls back to the floor).
- **Properties:** SP-07: the floor counts as an anchor when the device has none; Verification adds `rollback.test.ts` cases. SP-02 if the transfer text mentions its body.
- **Key hierarchy:** line 153 (team state key purpose), "Adding a device", "Creating a team", joining scenario.
- **Protocol:** §3.8 steps 2–4 (body, no receiver anchor), §4.3 (plaintext layout, reader checks), §4.4 (no record now falls back to the floor), §5.9 (create member keys: floor rules), §6.1 step 1, §6.3 step 5, §6.4 (anchor at join, verified before writing), §6.8 (re-key carries the floor), §12 (API lines), §13 (wrap and transfer vectors regenerated for D-48).
- **Guides:** `docs/using.md` (invite row, receiver example lines 83–84), `docs/integration.md:118`, README if it shows `openTeam({ anchor })`.
- **Retired wording** (`scripts/retired-terms.json`): `openTeam(teamId, { anchor` and the receiver's `{ anchor }` option, allowed only in D-48's history.

## Phase B: records and vectors

- `src/records/member-keys-wrap.ts`: `MemberKeyBundle` gains `floor?: Anchor`; `createMemberKeysWrap` appends the optional encoding; `parseMemberKeysWrap` accepts the two exact sizes; `openMemberKeysWrap` decodes it with the canonical `Reader` (`src/encoding/canonical.ts`), refusing trailing bytes (`DECRYPTION_FAILED` like other malformed plaintexts).
- `src/records/transfer.ts`: entry encoding and `openTransfer` read the optional floor; `checkBundles` checks the hash length.
- Vectors: `test/vectors/generate/wrap.mjs` adds a member keys bundle case with and without a floor (fixed nonces: regenerate and check the existing cases are byte-identical); `test/vectors/generate/transfer.mjs` adds floors (sealing is randomised: the whole file changes, nothing else depends on it). Replay in `test/compatibility/`.

## Phase C: vault, sessions, receiver

- `src/team/context.ts`: `MemberBundle` gains `floor?: Anchor`.
- `src/account/member-custody.ts`: `openBundles` returns floors; `newMemberKeys` takes the floor; `newTeamOps` sets `(1, hash)`; `exportBundles` passes floors.
- `src/account/vault.ts`: `joinTeam(teamId, { anchor? })` with verification before writing; `openTeam(teamId)` without the anchor option; `rekey` (and J's phrase rule).
- `src/account/recovery.ts`: `rekeyTeam` carries or fills the floor (newest bundle, else local anchor, else `readServerState`).
- `src/team/load.ts`: `loadChain` takes floors from the bundles and uses the lowest floor (version, hash of the newest bundle's floor) only when `local` and `server` are both absent; drop the `invite` parameter.
- `src/team/session.ts`, `src/team/receiver.ts`: drop the invite anchor path (`TeamSession.open` loses `invite`, the receiver's `options.anchor` goes).
- `src/team/anchors.ts`: I's fix once the test confirms it.

## Phase D: tests

- `test/security/rollback.test.ts`: an existing member's new device with the server withholding `team-state`, and with a session thief deleting it, refuses a forged chain (`chain_conflict`/`rollback`) instead of trusting it; same in a receiving context (§3.8); a joiner with a wrong invite anchor is refused at `joinTeam` and nothing is written; the existing invite-anchor tests move from `openTeam` to `joinTeam`.
- `test/security/account-rotation.test.ts` or `secure-account.test.ts`: the floor survives a rotation and a re-key; a member who joined without an anchor gains one at the next re-key.
- `test/security/key-transfer.test.ts`: lines 57–58 move to `joinTeam`; transfers carry the floor.
- `test/compatibility/scenario.test.ts`: the invite flow uses `joinTeam(teamId, { anchor })`.
- I: a test in `rollback.test.ts` or `record-archive.test.ts` reproducing the conflict; confirm it fails before the fix.
- J: `recovery-proof.test.ts`: after `confirmRecoveryPhrase` with the current phrase and a failed team, `rekey(teamId, { phrase: oldPhrase })` is proven and `reconcile` approves it; a phrase no bundle or wrap carries is `WRONG_CREDENTIAL`.
- For each new rule, prove the test guards it (remove the floor fallback, skip join verification, carry no floor on rotation: each must fail a test).

## Phase E: review and notes

- Run the spec-review workflow on the changed sections; record findings in review 003 or a new 004.
- Plan 009 execution notes in `.agents/plans/009-anchor-floor.plan.md`.
- Integration note (doconvoy e2eev2): pass the invite anchor to `joinTeam`, not `openTeam` or the receiver; update the course in `learning/` with the maintain-course workflow if the user wants it.

## Verification

- `npm run typecheck`, `npm test` (unit, properties, security, compatibility), `npm run check:spec`, `npm run build`, `npm run test:package`, `npm run test:browser` (the IndexedDB adapter is untouched but stores anchors).
- End-to-end in the security suite: a member with two devices; the second device opens while the store withholds `team-state` and serves a forged chain: `unverified` with `rollback`/`chain_conflict`; with `team-state` served, the chain is fetched from the `team-state` anchor (assert the fetched `fromVersion`).

## Execution notes

- **Commits:** plan (`3010c2a`), A spec (`88410f5`), B layouts and vectors (`5e9d978`), C and D together (`4218ca8`), because C's API change can't be green without D's test migration. B was committed with the traceability test red: Phase A's SP-07 entry named `account-rotation.test.ts` before D added its floor tests.
- **Vectors:** `wrap.v1.json` gains a `bundles` section; its existing cases regenerated byte-identical (fixed nonces). `transfer.v1.json` is regenerated whole (sealing is randomised); nothing else depends on it.
- **I confirmed** before the fix: a concurrent `team-state` under the older bundle's key made the session `unverified` with `state_unreadable`. The test is now in `rollback.test.ts`.
- **Spec review of the changed sections:** one divergence, fixed: §6.4 said the join check fetches from version 1; it fetches from the anchor's version, like every anchored load, since records below are pinned by hash. Noted, not changed: a floor filled at a re-key from the current `team-state` can be above an older revision the server later serves; the device then starts from that real, older anchor, which is TH-05's accepted rollback window, not a forged team.
- **Guards:** removing the floor fallback, the join check, the floor on rotation or re-key, D-49's phrase rule, or I's fix each fails a test.
- **Integration (doconvoy e2eev2):** pass the invite anchor to `joinTeam(teamId, { anchor })`; `openTeam` and the receiver no longer take one. The local course in `learning/` isn't updated.
