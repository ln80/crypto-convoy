# Review ledger

Every review finding and every accepted residual, kept by the [protocol-review](../skills/protocol-review/SKILL.md) workflow. Reviews cite this file instead of repeating old findings. Severities before review 004 were set by hand, before the rubric.

## Stop rule

Freeze candidate when two reviews in a row, in different modes, at least one `adversarial` with a fresh-context reviewer, find nothing the [action rule](../guides/direction.md#the-action-rule) says to fix beyond availability, and no such finding is open. Availability-only fixes are still done, before the first release, but don't count. (Until review 013 the rule was "nothing medium or above"; from 013, findings accepted and documented, or text corrected, no longer counted; from review 037, availability-only fixes no longer count either.)

**Now:** 2 of 2: freeze candidate, covering D-66 (reviews 040 `change`, 041 `adversarial`). Formal models done (plan 027), every lemma as expected and every mutation caught, no attack beyond the accepted ones (`npm run check:formal`, `formal/README.md`). Review 042 (`change`, the models) found no protocol fix; its model and text edits (042-A to E) are done. Open findings: none. Next: the external audit, before the vectors freeze (§13); not yet funded. Its brief, kept up to date by every review, is [audit-brief.md](audit-brief.md).

## Findings

| Id | Kind | Severity | Status | Resolved by |
| --- | --- | --- | --- | --- |
| 001-A | Missing threat | High | Fixed | D-41, SP-25, TH-45 (plan 008) |
| 001-B | Unspecified | High | Fixed | D-42, SP-26 (plan 008) |
| 001-C | Overclaim | Medium | Fixed | D-44, `team.memberChanges` (plan 008) |
| 001-D | Wrong claim | Medium | Fixed | D-43, TH-47 (plan 008) |
| 001-E | Wrong claim | Low | Fixed | TH-44 actor (edit) |
| 001-F | Overclaim | Low | Fixed | SP-10 Limits (edit) |
| 001-G | Missing threat | Medium | Fixed | D-42, TH-46 (plan 008) |
| 002-A | Spec → code | Medium | Fixed | D-43 writer rules, §11 (plan 008 C) |
| 003-A | Overclaim | High | Fixed | D-48 (plan 009) |
| 003-B | Wrong claim | High | Fixed | D-45 |
| 003-C | Overclaim | Medium | Fixed | D-46 |
| 003-D | Overclaim | Medium | Fixed | TH-47, SP-12 Limit, D-43 (edit) |
| 003-E | Wrong claim | Medium | Fixed | D-47 |
| 003-F | Missing threat | Medium | Fixed | TH-48 |
| 003-G | Overclaim | Low | Fixed | TH-14, D-31 (edit) |
| 003-H | Wrong claim | Low | Fixed | TH-36 (edit) |
| 003-I | Spec → code | Low | Fixed | `advanceAnchor` (plan 009) |
| 003-J | Spec → code | Low | Fixed | D-49 (plan 009) |
| 004-A | Hardening | Low | Fixed | D-50 (plan 010) |
| 004-B | Hardening, simplification | Medium | Fixed | D-50 (plan 010) |
| 004-C | Combined attack | Medium | Accepted | TH-49 (integration duty) |
| 004-D | Overclaim | Low | Fixed | Guides (edit, plan 010) |
| 004-E | Spec → code | Low | Fixed | D-50 (plan 010) |
| 004-F | Spec → code | Low | Fixed | D-50 (plan 010) |
| 005-A | Forgeable input, combined attack | Medium | Fixed | D-51 (plan 011); incomplete, see 006-B, 006-C |
| 005-B | Stale text | Low | Fixed | Guides, §3.8 (edit, plan 011) |
| 005-C | Stale text | Low | Fixed | Course (maintain-course) |
| 006-A | Combined attack | Medium | Accepted | TH-50, SP-03 Limit |
| 006-B | Forgeable input, combined attack | High | Fixed | D-52 (plan 012) |
| 006-C | Forgeable input, wrong claim | High | Fixed | D-52 (plan 012) |
| 006-D | Overclaim | Low | Fixed | §7.3, TH-23 (edit, plan 012) |
| 006-E | Missing threat | Medium | Fixed | D-53, TH-51 (plan 013) |
| 007-A | Spec cost | High (cost) | Fixed | D-52 advance (plan 012) |
| 007-B | Forgeable input | Medium | Fixed | D-52, §5.11 (plan 012) |
| 007-C | Missing threat | Medium | Fixed | `state_conflict`, TH-46 (plan 012) |
| 007-D | Spec gap | Low | Fixed | D-52 (plan 012) |
| 007-E | Stale text | Low | Fixed | SP-07, §4.3, §5.7 (plan 012) |
| 007-F | Residual | Low | Accepted | SP-07 assumptions, TH-05 |
| 008-A | Forgeable input | High | Fixed | D-53 `writeKeyId` (plan 013) |
| 008-B | Hardening | Medium | Accepted | Scope rule 2, integration guide (plan 013) |
| 008-C | Spec gap | Medium | Fixed | Scope rule 2 (plan 013) |
| 008-D | Spec gap | Medium | Fixed | §5.1, §5.4 (plan 013) |
| 008-E | Spec choice | Low | Fixed | cc1 in place (plan 013) |
| 008-F | Missing threat | Low | Fixed | TH-51, AS-05 (plan 013) |
| 009-A | Forgeable input, spec → code | High | Fixed | Owner snapshot pins held keys (plan 014) |
| 009-B | Combined attack, wrong premise | High | Fixed | D-54 (plan 015) |
| 009-C | Combined attack | Medium | Accepted | SP-11, SP-19, TH-12 limits; D-54 mitigations (plan 015) |
| 009-D | Hardening | Low | Fixed | `pin-upgrade-failed` (plan 014) |
| 009-E | Missing threat | Low | Fixed | TH-50, integration guide (plan 014) |
| 009-F | Hardening | Low | Accepted | TH-46 |
| 010-A | Forgeable input | High | Fixed | D-54 (plan 015) |
| 010-B | Forgeable input | High | Fixed | D-54: re-key fails, reported (plan 015) |
| 010-C | Wrong claim, combined attack | Medium | Accepted | Limits corrected (plan 015) |
| 010-D | Forgeable input | Medium | Fixed | D-54 roots agree (plan 015) |
| 010-E | Forgeable input | Medium | Fixed | D-54 (plan 015) |
| 010-F | Forgeable input | Medium | Fixed | Export refuses (plan 015) |
| 010-G | Residual | Medium | Accepted | Owner's anchor repair (plan 015) |
| 010-H | Hardening | Low | Fixed | §5.5 (plan 015) |
| 011-A | Simplification | Low | Fixed | D-66: every bundle holds a floor (plan 026, via 039-A) |
| 011-B | Stale text | Low | Fixed | Forgeability rows (with review 012) |
| 011-C | Stale text, simplification | Low | Fixed | D-54 restates the rules; D-48, D-50, D-52 point to it (with review 012) |
| 012-A | Stale text | Low | Fixed | Scope interface table (edit, with review 015) |
| 012-B | Stale text | Low | Fixed | Integration sizing table (edit, with review 015) |
| 012-C | Spec → code | Low | Fixed | §5.11, with 013-G (edit) |
| 012-D | Spec → code | Low | Fixed | §5.8 step 3 (edit, with review 015) |
| 012-E | Stale text | Low | Fixed | Integration guide, OprfService (edit, with review 015) |
| 012-F | Stale text | Low | Fixed | §5.4 (edit, with review 015) |
| 013-A | Forgeable input, overclaim | High | Fixed | D-55 (plan 016) |
| 013-B | Forgeable input, combined attack | High | Fixed | D-56 (plan 016) |
| 013-C | Combined attack, missing threat | Medium | Accepted | TH-04, SP-07, §6.8, guides (hardening direction: integration duty) |
| 013-D | Overclaim, combined attack | Medium | Accepted | Claim corrected: TH-45, TH-10, SP-25, SP-26; hardening declined (hardening direction); integration guide |
| 013-E | Missing threat | Medium | Accepted | TH-39 (integration duty, edit) |
| 013-F | Spec → code, spec gap | Medium | Fixed | Scope rule 3, §11, §12; kit refuses public deletes (edit) |
| 013-G | Hardening | Low | Fixed | §5.11: the check draws on the `enroll` share (edit) |
| 014-A | Forgeable input | High | Fixed | D-55 duplicate refusal (plan 016) |
| 014-B | Hardening | Medium | Fixed | D-56 reports, never refuses (plan 016) |
| 014-C | Wrong claim | Medium | Accepted | TH-12 Limit, D-56 consequence (plan 016) |
| 014-D | Hardening | Low | Fixed | D-55 `TRUST_FAILURE` for another hash (plan 016) |
| 014-E | Hardening | Low | Fixed | D-56 typed key (plan 016) |
| 015-A | Simplification | Low | Fixed | Integration guide Duties table; the `delete` row follows scope rule 3 (edit) |
| 016-A | Overclaim, spec → code | High | Fixed | D-57 (plan 017) |
| 016-B | Missing threat, wrong claim | High | Fixed | D-58 (plan 017) |
| 016-C | Missing threat | Low | Fixed | D-58 (plan 017) |
| 016-D | Stale text | Low | Fixed | TH-20, integration guide (plan 017) |
| 016-E | Combined attack | Low | Accepted | §5.11 step 3, using guide (plan 017) |
| 017-A | Forgeable input | High | Fixed | D-58: rotation re-wraps what opens (plan 017) |
| 017-B | Forgeable input | Medium | Fixed | D-58 server rule; numbering from published records (plan 017) |
| 017-C | Spec gap | Medium | Fixed | D-58: teams with a wrap that opens (plan 017) |
| 017-D | Spec gap | Medium | Fixed | D-57: reports added on reload (plan 017) |
| 017-E | Simplification | Medium | Fixed | D-57: the lowest root (plan 017) |
| 017-F | Spec gap | Medium | Fixed | D-58 paths (plan 017) |
| 017-G | Spec gap | Low | Fixed | Kit batch rule; `listDevices` (plan 017) |
| 017-H | Hardening | Low | Accepted | D-58 consequence, TH-46 |
| 018-A | Stale text | Low | Fixed | §12, `session.ts` comments (edit) |
| 018-B | Stale text | Low | Fixed | §6.1 step 2 (edit) |
| 018-C | Spec → code | Low | Fixed | §11, scope rule 5 (edit) |
| 018-D | Spec → code | Low | Fixed | §4.2, D-58; residual recorded (edit) |
| 019-A | Forgeable input, wrong claim | High | Fixed | D-59 (plan 018) |
| 019-B | Missing threat | High | Fixed | D-60 (plan 018) |
| 019-C | Overclaim | Medium | Accepted | TH-04, AS-06 (plan 018; server-controlled history) |
| 019-D | Combined attack, wrong premise | Medium | Fixed | D-61 (plan 018) |
| 019-E | Stale text | Low | Fixed | §5.5, Duties, TH-05 (plan 018) |
| 020-1 | Forgeable input | Medium | Accepted | TH-04: a re-join on a device with no vault anchor is a first contact; Duty (plan 018) |
| 020-2 | Spec gap | Medium | Fixed | D-59: `rekey` with an owner's anchor and no bundle |
| 020-3 | Forgeable input | Low | Accepted | D-60 consequence: `teamIds` only adds reports |
| 020-4 | Missing path | Low | Accepted | D-60 consequence: warnings read the wraps |
| 020-5 | Hardening | Medium | Fixed | D-60: the proven repair |
| 020-6 | Forgeable input | High | Fixed | D-61: every setup needs a credential |
| 020-7 | Wrong claim | Low | Fixed | D-61; `recover` |
| 021-A | Stale text | Low | Fixed | Key hierarchy (edit) |
| 021-B | Stale text | Low | Fixed | §12, TH-04 index row (edit) |
| 021-C | Stale text | Low | Fixed | §9 (edit) |
| 021-D | Spec → code | Low | Fixed | `joinTeam` checks the held floor, with a test |
| 022-A | Wrong premise | Medium | Accepted | TH-20, D-58, integration guide: support archives a planted wrap; kit `archive` (plan 019) |
| 022-B | Spec → code | Medium | Fixed | D-62 (plan 019) |
| 022-C | Overclaim | Medium | Accepted | TH-41 (plan 019) |
| 022-D | Overclaim | Low | Fixed | §5.11 (plan 019) |
| 023-A | Wrong premise | Low | Fixed | D-62 consequence |
| 023-B | Spec gap | Medium | Fixed | D-62: the revision kept |
| 023-C | Hardening | Medium | Fixed | D-62: roster-held writers only |
| 023-D | Simplification | — | Dropped | Rejected in D-62 |
| 023-E | Spec gap | Low | Fixed | §6.1 step 1, D-62 |
| 023-F | Spec gap | Low | Fixed | Clean-up; revision cap |
| 024-A | Overclaim, spec → code | Medium (025-A) | Fixed | D-62 amended (plan 020) |
| 024-B | Spec → code | Low | Fixed | Scope rule 4, §11 (plan 020) |
| 024-C | Stale text | Low | Fixed | `team-state.ts` comment, course (plan 020); ledger residual narrowed |
| 025-A | Overclaim, spec → code | Medium | Fixed | D-62 amended (plan 020) |
| 025-B | Wrong premise | Medium | Fixed | D-63: with a floor, `team-state` counts only under the newest keys (plan 020) |
| 025-C | Overclaim, missing threat | Medium | Accepted | TH-25, SP-18 Limit, integration guide (plan 020) |
| 025-D | Overclaim | Low | Fixed | TH-20, §5.11 (plan 020) |
| 025-E | Spec → code | Low | Fixed | §6.1 step 7 (plan 020) |
| 026-A | Simplification | Medium | Fixed | D-63 (plan 020) |
| 026-B | Forgeable input, spec gap | Medium | Fixed | D-62 amended: an unknown version is never replaced (plan 020) |
| 026-C | Spec gap | Low | Dropped | Moot: plan 020 has no write |
| 026-D | Hardening | Low | Dropped | Moot: plan 020 has no write |
| 026-E | Spec gap | Low | Fixed | Scope rule 4: revision + 1, relied on (plan 020) |
| 026-F | Simplification | — | Fixed | D-66: `team-state` retired (plan 026, via 039-A) |
| 027-A | Hardening (test coverage) | Low | Fixed | Fuzz parser reads the revision (plan 021) |
| 028-A | Spec → code, overclaim | Medium | Fixed | D-58 amended: a team whose bundles fail stops only that team (plan 021) |
| 028-B | Missing threat | Low | Accepted | D-63 accepted risk (plan 021) |
| 028-C | Simplification | — | Fixed | D-66: `team-state` retired (plan 026, via 039-A) |
| 028-D | Stale text | Low | Fixed | `member-custody.ts` comment (plan 021) |
| 028-E | Overclaim | Low | Fixed | TH-20 (plan 021) |
| 029-A | Spec → code | Low | Fixed | `warnings()` (plan 022) |
| 030-A | Spec → code | Medium | Fixed | List before writing (plan 022) |
| 030-B | Spec → code | Low | Fixed | `createTeam`'s roster version; §6.3 (plan 022) |
| 030-C | Overclaim | Medium | Accepted | TH-37, TH-47, SP-12 Limit (plan 022) |
| 030-D | Spec → code | Low | Fixed | `advanceAnchor` conflict path (plan 022) |
| 030-E | Wrong claim | Low | Fixed | Using guide, `VaultWarning` (plan 022) |
| 030-F | Wrong claim | Low | Fixed | Using guide, `VaultWarning` (plan 022) |
| 030-G | Spec gap | Low | Fixed | Scope rule 3 (plan 022) |
| 031-A | Stale text | Low | Fixed | §12 (plan 023) |
| 032-A | Wrong claim, spec → code | Medium | Fixed | D-56 amended (plan 023) |
| 032-B | Missing threat | Medium | Fixed | D-64 (plan 023) |
| 032-C | Wrong claim | Medium | Fixed | D-65; SP-16 Limit (plan 023) |
| 032-D | Spec → code | Low | Fixed | `createTeam` (plan 023) |
| 032-E | Wrong claim | Low | Fixed | Owner refusals, §9 (plan 023) |
| 032-F | Missing threat | Low | Accepted | D-58, TH-28 (plan 023) |
| 032-G | Note | Low | Fixed | TH-25 (plan 023) |
| 033-1 to 7 | Design | — | Fixed | Taken in plan 023's spec (D-56 amended, D-64, D-65) |
| 034-A | Stale text | Low | Fixed | Scope, §5.9 (plan 024) |
| 034-B | Stale text | Low | Fixed | §6.7, §12, `owner.ts` comments (plan 024) |
| 035-A | Spec → code, wrong claim | Medium | Fixed | D-54 amended: the repair replaces the local anchor (plan 024) |
| 035-B | Spec → code | Medium | Fixed | D-58 amended: a wrap read by identity that doesn't parse costs only its method (plan 024) |
| 035-C | Wrong claim | Low | Fixed | Recovery warning action; `UNSUPPORTED_VERSION` (plan 024) |
| 035-D | Spec → code | Low | Fixed | §6.7, §12 (plan 024) |
| 035-E | Wrong premise | Low | Fixed | §4.1 (plan 024) |
| 036-A | Stale text | Low | Fixed | §5.4 (plan 025) |
| 036-B | Stale text | Low | Fixed | Using guide, `status()` (plan 025) |
| 037-A | Missing threat | Low | Accepted | TH-17 (owner compromise group) |
| 037-B | Spec → code, wrong claim | Low | Fixed | D-58 amended: the same-PIN check skips a PIN wrap whose `kdf` is refused (plan 025) |
| 037-C | Spec → code | Low | Fixed | D-58 amended, §4.1, §5.4: this device's wrap that doesn't open is unreadable (plan 025) |
| 037-D | Wrong claim | Medium | Accepted | TH-20, SP-07, D-54 consequence (plan 025) |
| 037-E | Wrong premise, combined attack | Medium | Accepted | TH-20, SP-07, D-54 consequence (plan 025) |
| 038-A | Wrong claim | Low | Fixed | §5.5, using guide: `listDevices()`'s `current` (edit after review 038) |
| 038-B | Stale text | Low | Fixed | SP-26 Verification (edit after review 038) |
| 039-A | Simplification | Low | Fixed | D-66 (plan 026) |
| 039-B | Simplification | — | Fixed | D-58's current rule (plan 026) |
| 040-A | Stale text | Low | Fixed | §3.8 step 3: an entry that doesn't decode (edit after review 040) |
| 040-B | Spec → code, wrong claim | Low | Fixed | §4.3, D-66: a ciphertext above the bound is `MALFORMED_RECORD` (edit after review 040) |
| 041-A | Wrong claim | Medium | Accepted | TH-20, SP-07, D-54 text: a script in the vault deletes the vault's anchor (edit after review 041) |
| 041-B | Wrong claim | Low | Fixed | D-54, integration guide: clear a receiving context's anchor after a repair (edit after review 041) |
| 041-C | Wrong claim | Low | Fixed | D-54: a forged vault anchor also fails opens and `leaveTeam` (edit after review 041) |
| 041-D | Missing threat | Low | Accepted | TH-46: a session replays an older wrap revision (edit after review 041) |
| 042-A | Model abstraction | Low | Fixed | `chain.spthy`: seal with the team alone, looser than §4.5 (edit after review 042) |
| 042-B | Model lemma | Low | Fixed | `chain.spthy`: the anchored join and no-fork lemmas compare the key held (edit after review 042) |
| 042-C | Overclaim | Low | Fixed | SP-07's formal line, README: rollback and roots not modelled (edit after review 042) |
| 042-D | Wrong claim | Low | Fixed | `recovery.spthy`, README: the version orders re-keys; freshness not modelled (edit after review 042) |
| 042-E | Stale text | Low | Fixed | README, model headers: readers in one slot, owner key replacement, the request's team (edit after review 042) |

## Residuals

Accepted or partly mitigated risks, from the threat model's dispositions and the plans' notes. "Revisit" says what would make the reason stop holding; the `residuals` mode checks it.

| Threat | Actor | Residual | Why accepted | Revisit |
| --- | --- | --- | --- | --- |
| TH-04 | A2 | The join without an invite anchor, or with a link the server delivered, trusts the chain served | Fingerprints deferred (D-11) | D-11 or D-32 returns; a product delivers invites only through its server |
| TH-05 | A2 | A device can't see newer state the server withholds, between its floor and that state | A server controlling delivery can always delay news | Key transparency (TH-38) |
| TH-09 | A2 | The OPRF key holder can brute-force a PIN | The server holds its OPRF key by design (AS-05) | A threshold OPRF |
| TH-11 | A8 | A PIN or phrase thief with a session can take over until support restores | Credentials are the account's proof | Restore authentication changes (TH-48) |
| TH-12, TH-13 | A7, A9 | Access copied before `secureAccount` and the re-key approvals | Past access can't be revoked (AS-07) | — |
| TH-14 | A4 with A2 | A server listing a removed member as active keeps them in, with no report | The active list is the integration's (D-31) | An owner-signed membership list |
| TH-15 | A5 | Any member can claim any author | Author signatures deferred (D-09) | D-09 |
| TH-17 | A6 | One stolen owner key is enough for a takeover; detection only | Owners are equals (D-06) | Multi-owner approval |
| TH-18 | — | A single-owner team freezes if the owner loses every credential | No server-side recovery (SP-19) | — |
| TH-20 | A9 | Injected script in the vault opens every bundle until detected | Isolating the vault is the integration's; the remedy is `secureAccount` | — |
| TH-21, TH-23 | A2, A10 | Links the server delivers or rewrites expose their key | An anonymous recipient can't authenticate the server | Signed inbox keys (D-20) |
| TH-30 | A4 with A1 | A removed member opens new submissions to an old inbox | Inbox keys live as long as their link (D-20) | D-20 |
| TH-32 | A1, A2 | Recorded ciphertexts and a future quantum computer | No post-quantum suite in v1 | A hybrid suite |
| TH-36 | A1 | Archived wraps in a data theft still open with the old PIN and a server evaluation, or the old phrase | The archive makes restores possible (D-39) | Restore window length |
| TH-37 | A11 | An owner approving an unproven request without the out-of-band check | Needs a human (AS-06); invite proofs deferred (D-32) | D-32 |
| TH-38 | A6 with A2 | Two records for one version, shown to different members | Needs key transparency | Key transparency |
| TH-41 | A8 | A phrase thief proves re-keys and races the member, until an owner removes the account or approves one set by hand | The phrase is the proof (D-33); securing with a new phrase ends it (D-45) | — |
| TH-46 | A11 | Garbage or deleted wraps make a team unavailable until support acts (`team-state` retired by D-66) | Availability, like TH-28 | — |
| TH-47 | A11 | Bait keys keep a member's keys unapprovable while the thief keeps the session | Only the newest keys are approved | — |
| TH-48 | A8, A7, A2 | A support restore brings back what an attacker can open | Restores are the integration's to authenticate | — |
| TH-49 | A2, A9 | A forged transfer opens a forged team in a receiving context | The two contexts share no secret; the channel is the integration's (D-29) | A shared secret between contexts |
| TH-50 | A4 or A5 with A2 | A holder of an older team key version and the server rewrite or add items | Readers can't order writes; the server's write-once rule is the barrier | D-09 with key transparency or an owner-signed item index |
| TH-12, SP-19 | A2 or a support restore, with the old account key | A retired account key version, served to a stateless or stale device or restored, opens with unchanged credentials; keys made there are the attacker's | No client rule tells a retired version from the current one without state (D-54) | Key transparency for account versions |
| TH-09, TH-51 | A2, A10 | One POPRF key per key id serves every account: a repeated proof nonce or one exported tweaked key reveals it; queries concentrate on it | Per-account public keys can't be pinned in client code (D-53) | Key ids rotated, or a cap per key id, in the integration |
| TH-20 | A9, A7 (account key), A2 | A planted floor on a device whose vault never verified the team, with a server serving a matching forged chain, is trusted until an owner's anchor is given | The vault has no other root there (D-54) | Owner fingerprints (D-11) |
| TH-12, SP-23 | A7 or A9 with the session, with A2 | Keys made without the phrase (`createTeam`, `joinTeam`, an unproven `rekey`) while the recovery wrap names the attacker's key carry it: its re-keys stay proven there, and a colluding server can publish them after `secureAccount`, until an owner approves the user's re-key by hand | No phrase-free source of the current recovery key that an account-key holder can't rewrite (D-56) | A locally pinned recovery key, or key transparency |
| TH-39 | A2 or A3 on the channel | A substituted transfer request receives the member's private keys, the owner key included | The two contexts share no secret; the channel is the integration's (D-29), as in TH-49 | A shared secret between contexts |
| TH-04 | A2, or someone posing as an owner | An owner's repair anchor replaces every root: a relayed, stale or forged one roots the account's devices on the chain it names, a forged team or a version below a verified removal (review 013 C) | Nothing authenticates who sends it; the integration carries it outside the server, like invite links (hardening direction: server-controlled history) | Owner fingerprints (D-11) or key transparency |
| TH-45 | A7 or A9 with the session | An open vault with the session deletes the recovery wrap, sets up its own phrase as a first setup, and rotates; or writes wraps with the account key | Seen (the user is locked out) and undone by a support restore (SP-26); refusing the API route wouldn't stop raw writes (hardening direction: combined attack) | Server-side credential checks |
| TH-20 | A7 or A9 (account key) with the session | A planted wrap that opens with keys its published record doesn't match fails that team for the account, re-joins and repairs included, until support archives it (review 022 A) | Only the account key makes a wrap; telling a planted one from a server's forged record would need trusting the server (D-58) | Key transparency for member keys |
| SP-18, §10 | — (a reader that hasn't updated) | A roster entry naming a `member-keys` record of a newer format reads as `key_mismatch`, not `UNSUPPORTED_VERSION`, because a team's list leaves out records it can't read (D-58) | Otherwise a joiner stops the team by declaring an unknown version; readers ship before writers (§10) | A version check on roster entries |
| TH-04 | A2 | An existing member re-joining without an anchor, on a device with no vault anchor, while the server withholds its wraps, is a first contact (review 019 A, review 020) | The vault has no root there; the integration re-joins members only with an owner's anchor (D-59) | Owner fingerprints (D-11) or key transparency |

| TH-25 | A11 on an owner's account, or a holder of the owner capability | A team key version that fails its checks, at the next version, stops the team for every member, for good (review 025 C) | Availability; a chain can't leave a version out, and both fixes are costly (a server signature check, or support freeing a version identity) | A server-side signature check, or support freeing a version identity |


| TH-37 | A11 | Keys published, or a team created, under the account in a team where the vault holds no keys go unreported; members joining such a team see the account as its owner (review 030 C) | A session acts as the user in the product; listing an account's keys across teams needs a new store query; `secureAccount` with `teamIds` reports a listed team with no keys (D-60) | A store query for an account's published keys across teams |

| TH-28 | A2 | A wrap withheld while the account rotates stays with the retired version: the team reads `not-joined` after `rotate()` until support restores it (review 032 F) | Withholding is the server's; the archive restores it (SP-26) | — |
| TH-46 | A11 | A recovery wrap that doesn't parse, or whose `wrappedAccountKey` is garbled, disables the phrase until a setup with the PIN or a support restore; with no PIN, support only (review 033 1) | A garbled `wrappedAccountKey` can't be told from a wrong phrase; the mismatch is reported where it can be (D-56) | — |
| SP-16 | Another owner, A2, A11 | A team can end with listed owners and no keys: a departed account named owner again, a chain served from before an account became owner, wraps a session deletes (review 033 2) | Nothing in the chain says who deleted their wraps (D-65) | Owners' key custody in the chain |
| TH-17 | A6 | An owner key signs a version whose previous-key link wraps the wrong key: older items stop opening for every member, with no change reported, for good (review 037 A) | Write-once records; detection would only stop the team (TH-25); owner compromise group | Multi-owner approval |
| TH-20 | A7 or A9 with the open vault, with A2 | `rekey({ anchor })` through the open vault replaces the vault's anchor, the local anchor and the floor with no credential; a later `secureAccount` there carries the forged root (review 037 D) | A credential check stops nothing: the holder of the open vault writes the store directly (TH-45); server-controlled history | Owner fingerprints (D-11) or key transparency |
| TH-20 | A7 or A9 once, then A2 | A planted wrap survives `secureAccount` and the owner's-anchor repair (re-wrapped, then archived); a new device served it, with the repaired wrap withheld, opens the forged team `ready` (review 037 E) | Dropping a failed team's wraps at rotation is a new failure needing a human, for a combined attack; server-controlled history | Owner fingerprints (D-11) or key transparency |
| TH-20 | A9 in the vault, with A2 | A script that plants a floor and deletes the vault's anchor makes the vault read as one that never verified the team: `secureAccount` carries the planted floor (review 041 A) | Same outcome as 037-D by another route; telling a deleted anchor from none needs state the same script could delete; server-controlled history | Owner fingerprints (D-11) or key transparency |
| SP-07, TH-46 | A11, harmful with A2 | A replayed older wrap revision lowers the floor for new devices until the vault's next open (review 041 D) | The server could serve that older wrap itself (SP-07) | Key transparency |

Out of scope or by design, not revisited: TH-16, TH-26, TH-27, TH-28, TH-31, TH-35.
