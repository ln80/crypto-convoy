# Plan 014: held keys pinned by the roster (review 009 A), with D and E

## Context

Review 009 (`.agents/reviews/009-adversarial.md`):
- **A (high):** `reconcile` and `overview` checked a re-key's recovery proof against the recovery key of the record the server served for the held version, without comparing it with the roster's `keysHash`. The server alone could get its own keys approved as a member's proven re-key. Reproduced.
- **D (low):** a failed upgrade at a PIN unlock was swallowed: no report, and one more evaluation at every unlock.
- **E (low):** TH-50 named items only; `inbox` records can be rewritten the same way.

**Decisions (user):** fix A, D and E now (edits; A is spec → code, §4.2 and §6.8 already say it). B and C (protocol changes) go to plan 015 with a design review.

## Design

- **A:** when an owner builds its membership snapshot, every published record at a holder's version must have the holder's roster `keysHash`, else `TRUST_FAILURE` (`key_mismatch`), as `#recipients` already does. SP-23's text says so.
- **D:** the unlock stands with the old wrap, as D-53 says; the vault keeps the failure, reports it in `warnings()` (`pin-upgrade-failed`, action `report` for a failed proof, else `changePin`) and doesn't try the upgrade again in that vault. §5.4, §12, the using guide.
- **E:** TH-50 covers `inbox` records; the integration guide says to build inbox links only from `createInbox` or `replaceInbox`.

## Phases (one commit each)

1. **Spec:** SP-23, §5.4, §12, TH-50 and its index row, the integration and using guides. Review 009, the ledger, the forgeability table.
2. **Code and tests:** `src/team/owner.ts` (`#snapshot`), `src/account/vault.ts` (upgrade failure and warning); `recovery-proof.test.ts` (A, in `reconcile` and `overview`), `pin-hardening.test.ts` (D).
3. **Notes:** execution notes, review 009 and the ledger.

## Execution notes
