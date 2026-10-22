# Review 001: threat model, properties and protocol after plans 005–007

Scope: `docs/` at commit 4093119 (plan 007), against `src/` on the same commit.

## Fixed by edits (no decision needed)

- Stale text after D-39 (archive, not delete), D-40 (PIN optional) and rule 8 (signer only), in decisions D-05, D-10, D-30, D-36, TH-10, SP-10, SP-11, protocol §2, §4, §5.5, §5.7, §9, key-hierarchy, libsodium-map and using.
- Threat ↔ property citations aligned in both directions; TH-42 marked not applicable; threat-model and properties headers.
- E: TH-44's actor needs the power to change the PIN (A7, A8 or A9) besides the session.
- F: SP-10 Limits: a revoked wrap may be served for a short delay and can be restored from the archive.
- `check:spec` gained checks 7–11 (threat index, threats ↔ properties, errors, tables, retired wording) so these don't drift again.

## Open: each needs a decision

| Id | Kind | Severity | Finding |
| --- | --- | --- | --- |
| A | Missing threat | High | Whoever holds an unlocked vault (A7, A9) can replace the recovery phrase without the old one (`confirmRecoveryPhrase`, §5.6) and rotate with a PIN of their choice and no phrase (§5.7 step 2 accepts "the current one or a new one"), which drops the recovery wrap. The user's `secureAccount` remedy (TH-10) then fails; only the support restore remains. D-33 calls the phrase the offline root of trust. Options: require the current phrase (or the current PIN, with one evaluation) to rotate or replace the phrase; or accept and document. |
| B | Unspecified | High | Restoring an account after a rotation: rule 7 and §11 say `member-keys-wrap` records are deleted with their account key version, the testing store archives them; restoring also needs the current account key version moved back, which SP-07 makes devices refuse. TH-36 covers garbage wraps only. Kept as `known` in `scripts/retired-terms.json`. |
| C | Overclaim | Medium | SP-15 and TH-17 say every newly approved member is reported with its signer; §6.1 step 3 reports owner changes only, and `team.members()` shows the current roster. A member admitted and removed between two opens is never seen. |
| D | Wrong claim | Medium | TH-37 says a preempted first join is detected as `key_mismatch`. `joinTeam` always writes `memberKeysVersion` 1 (`src/account/vault.ts`), so the write-once conflict surfaces as `STALE_VERSION`, which §9 calls retryable: the member is stuck with a misleading error. Read from the code, not run. |
| G | Missing threat | Medium | A session thief can write a garbage `team-state` (the server can't check it), giving `state_unreadable` and `unverified` on every device with no documented way out, or delete a `member-keys-wrap`. TH-36 covers account wraps only. Kept as `known` (integration.md) for the deletion part. |

## Structure (no decision on content)

The threat model is broad enough; its form causes drift. Proposed: group threats by actor or asset instead of review pass, with a section on the unlocked vault (A7, A9); keep dispositions to one to three sentences plus ids (now in the spec-docs guide); move dormant threats (TH-33, TH-42, TH-43, returning with D-32) to their own table.
