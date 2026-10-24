# Review ledger

Every review finding and every accepted residual, kept by the [protocol-review](../skills/protocol-review/SKILL.md) workflow. Reviews cite this file instead of repeating old findings. Severities before review 004 were set by hand, before the rubric.

## Stop rule

Freeze candidate when two reviews in a row, in different modes, at least one `adversarial` with a fresh-context reviewer, find nothing the [action rule](../guides/direction.md#the-action-rule) says to fix, and no finding to fix is open. (Until review 013 the rule was "nothing medium or above"; findings accepted and documented, or text corrected, no longer count.)

**Now:** 0 of 2. Last reviews: 016 (`adversarial`) and 017 (`design`); plan 017 fixed 016-A, B, C (D-57, D-58) and D, accepted E. Open findings to fix: none. Still open, low: 011-A. Next: a review in another mode (`change` on plan 017, or `residuals`), then a fresh `adversarial` review; two clean in a row make the freeze candidate.

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
| 011-A | Simplification | Low | Open | |
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
| TH-46 | A11 | Garbage or deleted private records make a team unavailable until support acts | Availability, like TH-28 | — |
| TH-47 | A11 | Bait keys keep a member's keys unapprovable while the thief keeps the session | Only the newest keys are approved | — |
| TH-48 | A8, A7, A2 | A support restore brings back what an attacker can open | Restores are the integration's to authenticate | — |
| TH-49 | A2, A9 | A forged transfer opens a forged team in a receiving context | The two contexts share no secret; the channel is the integration's (D-29) | A shared secret between contexts |
| TH-50 | A4 or A5 with A2 | A holder of an older team key version and the server rewrite or add items | Readers can't order writes; the server's write-once rule is the barrier | D-09 with key transparency or an owner-signed item index |
| TH-12, SP-19 | A2 or a support restore, with the old account key | A retired account key version, served to a stateless or stale device or restored, opens with unchanged credentials; keys made there are the attacker's | No client rule tells a retired version from the current one without state (D-54) | Key transparency for account versions |
| TH-09, TH-51 | A2, A10 | One POPRF key per key id serves every account: a repeated proof nonce or one exported tweaked key reveals it; queries concentrate on it | Per-account public keys can't be pinned in client code (D-53) | Key ids rotated, or a cap per key id, in the integration |
| TH-46 | A9, A7 (`teamStateKey`) | A readable `team-state` with a forged anchor stops the account's devices (`state_conflict`, `rollback`) until support restores | Overwriting it would discard evidence of a split view (D-52) | — |
| TH-20 | A9, A7 (account key), A2 | A planted floor on a device whose vault never verified the team, with a server serving a matching forged chain, is trusted until an owner's anchor is given | The vault has no other root there (D-54) | Owner fingerprints (D-11) |
| TH-12, SP-23 | A7 or A9 with the session, with A2 | Keys made without the phrase (`createTeam`, `joinTeam`, an unproven `rekey`) while the recovery wrap names the attacker's key carry it: its re-keys stay proven there, and a colluding server can publish them after `secureAccount`, until an owner approves the user's re-key by hand | No phrase-free source of the current recovery key that an account-key holder can't rewrite (D-56) | A locally pinned recovery key, or key transparency |
| TH-39 | A2 or A3 on the channel | A substituted transfer request receives the member's private keys, the owner key included | The two contexts share no secret; the channel is the integration's (D-29), as in TH-49 | A shared secret between contexts |
| TH-04 | A2, or someone posing as an owner | An owner's repair anchor replaces every root: a relayed, stale or forged one roots the account's devices on the chain it names, a forged team or a version below a verified removal (review 013 C) | Nothing authenticates who sends it; the integration carries it outside the server, like invite links (hardening direction: server-controlled history) | Owner fingerprints (D-11) or key transparency |
| TH-45 | A7 or A9 with the session | An open vault with the session deletes the recovery wrap, sets up its own phrase as a first setup, and rotates; or writes wraps with the account key | Seen (the user is locked out) and undone by a support restore (SP-26); refusing the API route wouldn't stop raw writes (hardening direction: combined attack) | Server-side credential checks |
| TH-20 | A7 or A9 (account key) with the session | A planted wrap that opens with keys its published record doesn't match fails that team for the account until it re-joins | Only the account key makes a wrap; telling a planted one from a server's forged record would need trusting the server (D-58) | Key transparency for member keys |

Out of scope or by design, not revisited: TH-16, TH-26, TH-27, TH-28, TH-31, TH-35.
