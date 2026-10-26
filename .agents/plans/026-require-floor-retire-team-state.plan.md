# Plan 026: every bundle holds a floor; `team-state` is retired (review 039 A, B; merges 011-A, 026-F, 028-C)

## Context

Review 039 (`complexity`) found that, once member keys hold an anchor floor, the `team-state` record bounds nothing against the only actor who can roll back or fork a chain, the server (A2): it can withhold the record or serve an archived older revision, which turns its checks off. Meanwhile whoever holds a `teamStateKey` (A7, A9, a receiving context) or the session (A11) can write or delete it, which is what D-62, D-63 and four residuals exist to contain. Without a floor it is worse: a root anyone holding a key or the session writes (011-A).

Every bundle written since D-48 has a floor. Floorless bundles exist only in data written before it; v1 is unreleased and doconvoy resets its v1 data.

The user decided (review 039): **require the floor and retire `team-state`**. This plan also does 039-B (D-58's current rule), after the deletion.

## Gate (hardening direction)

| Change | Class | Delta | Product cost |
| --- | --- | --- | --- |
| D-66 (039-A) | Free | Deletes: one record type, its label, one key per bundle, one write op, two server rules, two `TRUST_FAILURE` reasons, one root of trust (6 → 5), the floor / no-floor branches of §4.3, §4.4 and §6.1, two decisions (D-62, D-63), four residual rows. Adds nothing | Integrators: the store drops a record type, its compare-and-set and its revision rule (doconvoy Go store and mock: remove); v1 data reset. Users: two failure states fewer, no `team-state` support restores. Reach: see below. API: breaking, before release (two reasons, `TeamStateKey`, the `compare-and-set` op) |
| 039-B | Free (text) | D-58 gains a current-rule paragraph; amendments kept as history | None |

**Reach.** A receiving context's advances no longer reach the account's other devices through the server. Each context keeps its local anchor, and the vault advances the floor at every open and export (§5.8); rollback protection already rests on these, since the server could always serve an old `team-state`. A new device starts from the floor, with the TH-05 window it already had.

**What is lost.** `state_conflict` between an account's own devices when the server forks the chain but serves the newest `team-state`: already needs key transparency (TH-38, server-controlled history group).

**Design review.** None: the change adds no input, state, fallback or branch; it removes them, and review 039's retirement test is its analysis. The `change` review (040) checks that nothing still cites the record.

## Design

### D-66: Every bundle holds a floor; there is no team state on the server

Status: Accepted. Supersedes D-62 and D-63; retires D-52's `team-state` checks, D-48's floorless bundles and D-42's `team-state` archive; amends D-58.

Problem: with a floor, `team-state` counts only on the chain the roots verify, so it can only detect a server that rolls back or forks the chain while serving the newest `team-state`; the server switches that off by withholding it or serving an archived revision. What it does add is surface: holders of a `teamStateKey` or the session forge, garble or delete it, and three decisions (D-52's checks, D-62, D-63) and four residuals exist to limit what that costs. Without a floor, it is a root anyone holding a key or the session can write (review 011 A). Review 039 A.

Decision:
- A member keys bundle is `signingSeed (32) ‖ encryptionSecretKey (32) ‖ enc(u32 version, bytes recordHash)`: 104 bytes, the floor required. The transfer entry is `enc(u32 memberKeysVersion, bytes signingSeed, bytes encryptionSecretKey, u32 floorVersion, bytes floorHash)`. Both change in place: v1 is unreleased, and the first release freezes them (§13).
- A bundle of another length doesn't open: `DECRYPTION_FAILED`, and in a list it is absent (D-58).
- There is no `team-state` record, `teamStateKey`, `compare-and-set` write or revision rule. A team's roots are the newest bundle's floor, this context's local anchor and, in the vault, the vault's anchor (D-54). Step 7 of §6.1 advances the local anchor only.
- `TRUST_FAILURE` reasons `state_conflict` and `state_unreadable` are retired.

Rejected:
- Keeping `team-state` as a report only (review 026 F): detection its only target switches off, for one more record, key and server rule.
- Keeping the floorless layout readable: a root anyone with a key writes, for data v1 doesn't have to read.

Consequence: rollback protection rests on the floor, the vault's anchor and the local anchors, as before for every case the server couldn't switch off. Integrators drop the `team-state` record, its compare-and-set and its revision rule from the store, and reset v1 data. Accepted: a fork the server shows to one device of an account and not another is no longer detected through the account's own records; it needs key transparency (TH-38).

### Protocol

- **§1 labels:** `team-state` removed (unreleased).
- **§3.8 transfer:** the body as in D-66; the receiver refuses a floor hash that isn't 32 bytes (unchanged) and an entry without a floor (`MALFORMED_RECORD`).
- **§4.3:** the bundle as in D-66; reader check "104 bytes".
- **§4.4:** "Removed before release (D-66): every bundle holds a floor, and a team's roots are local (§6.1). The section number is kept so references stay stable", like §4.6 and §4.11.
- **§5.9 leave / delete account:** no `team-state` delete.
- **§6.1:** step 1 roots: the floor, the local anchor, the vault's anchor in the vault, extra roots (an invite or owner's anchor); step 2 without the `team-state` checks; step 7: the local anchor only.
- **§6.8 step 4 (clean-up):** no `team-state` note.
- **§8:** the `team-state` row goes.
- **§9:** `state_conflict`, `state_unreadable` leave the reasons.
- **§11:** the `team-state` row goes; "Deletes" lists `account-key-wrap` and `member-keys-wrap`.
- **§12 Interface contracts:** `RecordStore` without `TeamStateKey` or `compare-and-set`; `LocalKeyStore` unchanged.
- **§13:** `wrap.v1.json` (member-keys-wrap cases) and `transfer.v1.json` regenerated; the `team-state` cases go.
- **§14:** the open point naming `team-state`, if any, resolved.

### Scope (server contract)

- **Rule 4** (compare-and-set and current revision + 1): "Removed before release (D-66)", the number kept.
- **Rule 7** (archives): private records are `account-key-wrap` and `member-keys-wrap`.

### Threats, properties, hierarchy

- **TH-05:** "the server can serve an older `team-state`" goes; the window between the floor and newer state stays.
- **TH-20:** the `team-state` sentence (a copied bundle writes a forged anchor, D-63) goes; "or, with a planted bundle that has no floor, the chain the server serves" goes (no floorless bundle opens).
- **TH-39, TH-49:** the transfer no longer carries a `teamStateKey`.
- **TH-46:** about `member-keys-wrap` and `account-key-wrap` only; the index row's D-62, D-63 citations go.
- **SP-07:** roots without `team-state`; Limits and Verification updated (`rollback.test.ts`).
- **SP-12, SP-26:** the `team-state` mentions go.
- **Key hierarchy:** the `teamStateKey` section and its place in the tree go; the bundle's contents updated.
- **Decisions:** D-62 and D-63 "Superseded by D-66"; D-42, D-48, D-50, D-51, D-52, D-54, D-57 and D-58 get a pointer where they describe `team-state` (history kept, current rule in D-66).

### 039-B: D-58's current rule

After the slices go, D-58 opens with a current-rule paragraph: in a list, a `member-keys-wrap` or device wrap that doesn't parse or doesn't open is absent; a `member-keys` record that fails its checks is left out of every list; a wrap read by identity (PIN, recovery, this device's) is absent, readable or unreadable, and an unreadable one, a PIN wrap whose `kdf` is refused, and this device's wrap that doesn't open cost only their method; a team whose bundles fail stops only that team. The four amendments stay below as history.

### Retired wording (`scripts/retired-terms.json`)

`team-state`, `teamStateKey`, `state_conflict`, `state_unreadable`, `compare-and-set`, "with no floor" / "for keys with no floor", "97 or 137". Each with `allow` for the history sections: D-42, D-48, D-50, D-51, D-52, D-54, D-57, D-58, D-62, D-63, D-66, §4.4. The prose "team state" (a team's state, as in SP-07's title) is not retired; only the record names are.

### Ledger

- Residual rows removed: TH-46's `team-state` part (row 1, shortened), TH-46 (A9, A7 forged anchor), TH-28 (A2 replaying a forged `team-state`).
- 011-A, 026-F, 028-C, 039-A, 039-B: fixed by plan 026.

## Ripple

- **Protocol:** §1, §3.8, §4.3, §4.4, §5.9, §6.1, §6.8, §8, §9, §11, §12, §13, §14.
- **Scope:** server contract rules 4 and 7, the Deletes paragraph.
- **Decisions:** D-66 new; D-42, D-48, D-50, D-51, D-52, D-54, D-57, D-58, D-62, D-63.
- **Threats:** TH-05, TH-20, TH-39, TH-46, TH-49, and their index rows.
- **Properties:** SP-07, SP-12, SP-26.
- **Key hierarchy:** the tree, `teamStateKey`, the bundle.
- **Guides:** the integration guide (Storage keys, Reads, Writes, Leaving), the using guide (checked).
- **Code:** `records/team-state.ts` (deleted), `records/member-keys-wrap.ts`, `records/transfer.ts`, `encoding/labels.ts`, `ports.ts`, `errors.ts`, `index.ts`, `team/anchors.ts`, `team/load.ts`, `team/chain.ts`, `account/vault.ts` (leave), `account/member-custody.ts`, `account/rotation.ts`, `testing/memory-record-store.ts`.
- **Tests:** `rollback.test.ts`, `record-archive.test.ts`, `secure-account.test.ts`, `account-rotation.test.ts`, `server-view.test.ts`, `member-removal.test.ts`, `test/unit/records.test.ts`, `test/unit/memory-store.test.ts`, `test/support/records.ts`, `test/support/parsers.ts`, the compatibility tests, the vector generators.
- **Course and notes** (`learning/`): `03-the-team/03-anchors.md`, answers, `02-the-account/06-same-pin-rewraps.md`, `08-replace-and-archive.md`, `patterns/anchors-against-rollback.md`, `concepts/toctou.md`, `lessons/adversarial-review-loop.md`.

## Phases (one commit each)

1. **Spec.** D-66, the ripple, 039-B, retired wording, ledger rows; `check:spec`.
2. **Code and tests.**
   - **Records:** the bundle and transfer layouts of D-66; `team-state.ts` and its label deleted.
   - **Team:** `loadChain`'s roots without `team-state`; `verifiedChain` and `verifyChain` without `state`; `advanceAnchor` writes the local anchor only; `readServerState` deleted.
   - **Account:** `leaveTeam` and account deletion without the `team-state` delete; the clean-up and rotation without `teamStateKey`.
   - **Ports and errors:** `TeamStateKey`, the `compare-and-set` op, `state_conflict`, `state_unreadable` removed; `index.ts` exports updated.
   - **Testing kit:** the store without the `team-state` type, its compare-and-set and revision rule.
   - **Tests:** `team-state` tests deleted or rewritten onto the floor and local anchor. New, in `rollback.test.ts`: a bundle in the old 97- or 137-byte layout, planted with the account key, is absent (the team reads `not-joined` if it is the only one), and a transfer entry without a floor is `MALFORMED_RECORD`; a new device starts from the floor and refuses a chain below it (`rollback`); SP-07's existing floor and local-anchor tests unchanged.
   - **Guards:** accepting the 137-byte layout, and a transfer entry without a floor, each fail their test.
3. **Vectors.** Update the independent generators (`test/vectors/generate/wrap.mjs`, `transfer.mjs`); remove the affected files, regenerate with `vectors:generate`, and check that the cases this plan doesn't touch are byte-identical; compatibility tests pass.
4. **Course and notes.** [maintain-course](../skills/maintain-course/SKILL.md): correct the lessons that teach `team-state` (anchors, replace and archive, same-PIN re-wraps), then the pattern and concept notes.
5. **Notes.** Execution notes; the `change` review (040); the doconvoy integration note (drop the `team-state` record, its compare-and-set and revision rule from the Go store and the mock; reset v1 data).

## Execution notes
