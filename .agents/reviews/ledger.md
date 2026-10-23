# Review ledger

Every review finding and every accepted residual, kept by the [protocol-review](../skills/protocol-review/SKILL.md) workflow. Reviews cite this file instead of repeating old findings. Severities before review 004 were set by hand, before the rubric.

## Stop rule

Freeze candidate when two reviews in a row, in different modes, at least one `adversarial` with a fresh-context reviewer, find nothing medium or above, and no medium-or-above finding is open.

**Now:** 0 of 2. Last review: 005 (`change`), with a medium finding. Open findings medium or above: none. No `adversarial` review with a fresh-context reviewer yet.

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
| 005-A | Forgeable input, combined attack | Medium | Fixed | D-51 (plan 011) |
| 005-B | Stale text | Low | Fixed | Guides, §3.8 (edit, plan 011) |
| 005-C | Stale text | Low | Fixed | Course (maintain-course) |

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

Out of scope or by design, not revisited: TH-16, TH-26, TH-27, TH-28, TH-31, TH-35.
