# Plan 007: rotation and securing with the recovery phrase alone (D-40), and server rule 8 wording

Part of doconvoy plan 123 (`docs/plans/123-e2eev2-lifecycle-fixes.plan.md` in doconvoy), which holds the review and the doconvoy phases.

## Context

A session thief can spend an account's PIN budget (doconvoy: 10 a day, 60 per 30 days). Every rotation derives a PIN key through the OPRF, so `secureAccount` and `rotate` are blocked until the budget resets, and `recover` unlocks but can't replace the PIN: the thief's PIN stays valid for up to 30 days. Making the PIN optional when the recovery phrase is given lets the user cut the thief out at once (the rotation retires every old wrap) and set a PIN later. Separately, doconvoy dropped the server check of owners a version adds; rule 8's text follows.

## Steps

Spec first (`protocol-change` workflow), then code, then build.

**Spec**
- `docs/decisions.md` **D-40** "The PIN is optional when rotating with the recovery phrase":
  - Problem: claim A.
  - Decision:
    - `rotate({ pin?, phrase? })` needs at least one of the two;
    - without a `pin`, version a+1 has no PIN wrap;
    - `secureAccount({ phrase, newPin? })`;
    - `changePin` creates the PIN wrap when there is none.
  - Rejected: a PIN wrap without the OPRF (weakens SP-08); support-only (the thief's PIN stays valid while waiting).
- `docs/threat-model.md` **TH-44** "Session thief spends the PIN budget": mitigated by D-40 (phrase-only securing) and the integration's budget reset.
- `docs/protocol.md`:
  - §5.4: PIN unlock with no PIN wrap → `PIN_NOT_SET_UP` before any evaluation.
  - §5.6: `changePin` creates or replaces.
  - §5.7 step 2: the PIN is optional.
  - §5.11: input = phrase + optional new PIN.
  - §9: new code `PIN_NOT_SET_UP`.
  - §12: `rotate({ pin?, phrase? })`, `secureAccount({ phrase, newPin? })`, status `pin`, warning `pin-not-set-up` (action `changePin`).
  - Note on `recover`: it unlocks and registers the device before setting the PIN; on `PIN_RATE_LIMITED` the vault stays unlocked.
- **Rule 8, scope and §11:** the server checks that the signer is the caller and holds the owner capability. The owners a version lists aren't checked: clients verify, SP-15 reports changes. Update the `integration.md` text accordingly.
- `docs/security-properties.md`: SP-11 Verification adds the phrase-only rotation test.

**Code**
- `src/account/rotation.ts` `rotateAccount`: `pin` optional; refuse when neither pin nor phrase is given (`MALFORMED_RECORD`).
- `src/account/vault.ts`:
  - `rotate`, `secureAccount` (`newPin?`).
  - `unlockWithPin`: missing wrap → `PIN_NOT_SET_UP`, instead of today's `STORE_ERROR`.
  - `changePin`: `createWrap` when no live PIN wrap, `replaceWrap` otherwise (helpers in `src/account/context.ts`).
  - `status()` gains `pin`.
  - `warnings()` gains `pin-not-set-up`.
- `src/errors.ts`: the code and its message.
- **Tests:**
  - `test/security/secure-account.test.ts`: the budget is spent, then `secureAccount({ phrase })` cuts the thief's PIN (old PIN → `PIN_NOT_SET_UP`) and other devices; then `changePin` restores PIN unlock.
  - `pin-hardening.test.ts`: `PIN_NOT_SET_UP` spends no evaluation.
  - Unit tests for status and warnings.
- Run `npm run check:spec`, `typecheck`, `test`, `build`, `test:package`.
- **Commits:** (1) D-40 spec + code; (2) rule-8 spec wording.

