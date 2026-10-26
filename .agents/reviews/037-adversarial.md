# Review 037: adversarial, twelfth round

Mode: `adversarial`, with a fresh-context reviewer. Scope: `docs/`, `src/` and `test/` at `093bd1e` (after plan 024 and review 036). Read only.

## Checked

- **Baseline.** `check:spec` passes. The ledger stood at 1 of 2: review 036 (`change`, plan 024) found nothing to fix. Open, low: 011-A, 036-A, 036-B.
- **Fresh-context reviewer.** A `general-purpose` subagent got the adversarial brief and `docs/`, `src/`, `test/`, with no access to `.agents/`. The brief named the newest rules (D-54 and D-58 as amended by plan 024, D-56, D-62 to D-65, list before writing). It reported six candidates and reproduced all six with throwaway tests (`test/security/zz-adv-*.test.ts`, 7 tests); this session re-ran them (all pass, so every attack works as described), read each one, and deleted them after the review.
- **This session's checks.** Plan 024's code (`readWrap`, `rekeyTeam` setting the local anchor): it matches §4.1 and D-54, D-58 as amended. A context mismatch in a wrap read by identity now reads as unreadable, not `TRUST_FAILURE` (`context_mismatch`): specified (§4.1), and a server that can withhold the wrap gains nothing from it. No candidate of its own.
- **Dropped:** the reviewer's "an owner leaves the owner list behind them" (A2 serves the chain from before the account became owner, `leaveTeam` passes `LAST_OWNER`). It is the residual accepted in review 033 (2), D-65 and SP-16's Limit: "a chain served from before an account became owner".
- **Found sound by the reviewer:** floor rollback by a replayed wrap (D-52, TH-05); a replayed recovery key after a phrase replacement (§4.1); self-approval after a re-key through the open vault (§5.11, D-47); bait keys (TH-47); D-58's list filtering; list before writing in `confirmRecoveryPhrase` and `secureAccount`; D-62, D-63; link and transfer bounds; content records (TH-23, TH-50).
- **Pairs checked:** A2 + A11 (B, C need only A11); A2 + A9 and A7 + A2 (D, E); A2 + A6 (A is A6 alone); A2 + A4 (TH-05, TH-50); A7 + A11 (TH-45); A8 + A11 (TH-11, TH-41); A2 with a relayed link or transfer (TH-04, TH-21, TH-23, TH-49).
- **Not checked:** stream internals; canonical encoding beyond spot checks; the cc1 suite, Ed25519 strictness and the OPRF math; the browser adapter beyond a skim; drafts; races between devices (compare-and-set retries, `reconcile` racing a re-key); `test:package`; fuzzing.

## Findings

### A. One owner key breaks the previous-key link: the team's history stops opening, with nothing reported

- **Kind:** missing threat.
- **Severity:** low (availability only, though for every member and for good).
- **Actors:** A6 alone, or a malicious owner.
- **Disposition:** accept and document, in the **owner compromise** group (TH-17). No small change fixes it: the record is write-once, and a member holding its own entry at version n − 1 could only detect it, which would then stop the team as TH-25's residual does.
- **Where:** a reader opening version n opens `wrappedPreviousKey` only to confirm that `teamKey_n` is right (`access.ts:71`, §4.5 "additionally confirms that `teamKey_n` is the key this record was made with"); nothing checks that it yields `teamKey_{n−1}`. The session keeps its newest access and walks down the links (`session.ts`), so members who held n − 1 lose it too.
- **Evidence:** reproduced (`zz-adv-broken-link`): the owner signs version 3 with the same owners and roster and a random previous key; bob opens it `ready`, no owner or member change is reported, and an item at version 2 is `DECRYPTION_FAILED`.
- **Unconfirmed variant:** the same owner seals garbage `sealedTeamKey` entries to co-owners; they get `DECRYPTION_FAILED` when they open and can't rotate the owner out. Seen by them, and within TH-17's takeover.
- **Text to add:** TH-17 (or TH-25's disposition): an owner key can also sign a version whose previous-key link is wrong; older items then fail to open for every member, with no change reported; the record is write-once; accepted with TH-17.

### B. A PIN wrap that parses but can't be used costs more than the PIN

- **Kind:** spec → code, wrong claim (D-58 amended, SP-26: a session's garbage "costs that method only").
- **Severity:** low (availability; workarounds exist).
- **Actors:** A11 alone.
- **Disposition:** fix (small).
- **Where:** `readWrap` reads the record as readable when only its `kdf` is unusable: an `oprfKeyId` the settings don't pin, or a cost under the reader minimum and above the hard floor. `#refuseCurrentPin` (`vault.ts:435`) then rethrows `UNSUPPORTED_VERSION` or `MALFORMED_RECORD`, so `secureAccount({ newPin })` refuses; `warnings()` says nothing; `unlockWithPin` says `UNSUPPORTED_VERSION`. `secureAccount` without a new PIN, then `changePin` with the phrase, still work.
- **Evidence:** reproduced (`zz-adv-pin-wrap`, both cases).
- **Fix:** the same-PIN check is skipped when the live wrap can't be opened for any reason, as it already is for `WRONG_CREDENTIAL` and a spent share (D-40). `unlockWithPin`'s `UNSUPPORTED_VERSION` stays: an unpinned key id is also the honest sign that the settings lag.
  - **Budget:** small (one branch widened; no state, no new failure). Edit only, under D-58's amendment.
  - **Product cost:** none for integrators, users or API.

### C. A device wrap that parses but doesn't open breaks this device's unlock for good

- **Kind:** spec → code (D-58 amended: "for this device's wrap, registers the device again under a new id").
- **Severity:** low (availability on one device).
- **Actors:** A11 alone.
- **Disposition:** fix (small).
- **Where:** `unlock()` (`vault.ts:242`) rethrows `DECRYPTION_FAILED` from `openAccountKeyWrap`; `#registration` (`vault.ts:612`) counts a parseable wrap as a registration, so a PIN or phrase unlock never registers the device again; `status().deviceRegistered` is true. Only a device revocation or a support restore recovers it.
- **Evidence:** reproduced (`zz-adv-device-wrap`).
- **Fix:** a device wrap that doesn't open under this device's key is unreadable too: `unlock()` gives `DEVICE_NOT_REGISTERED`, and `#registration` and `status()` open it with the local device key before counting it. A random device key never fails honestly, so this reads nothing the server could choose.
  - **Budget:** small (one check in the existing unreadable branch). Edit to D-58's amendment and §4.1 ("doesn't parse, fails its checks, or, for this device's wrap, doesn't open").
  - **Product cost:** none.

### D. An open vault replaces the vault's own anchor with no credential, so TH-20's "a vault that has opened the team refuses it" doesn't hold against the planter

- **Kind:** wrong claim.
- **Severity:** medium (two actors; a guarantee the integration relies on is overclaimed).
- **Actors:** A7 or A9 with the open vault, together with A2 serving a forged chain.
- **Disposition:** correct the text, and accept; **server-controlled history** group. Requiring a credential for `rekey({ anchor })` would stop nothing: whoever holds the open vault can write the vault's anchor in `LocalKeyStore` and the wraps directly (as TH-45 already says of credentials).
- **Where:** `vault.rekey(teamId, { anchor })` needs no PIN or phrase (`vault.ts`, `recovery.ts` `rekeyTeam`); it replaces the vault's anchor (`recordVaultAnchor(…, true)`), the local anchor (plan 024) and the floor. TH-20's disposition and SP-07's assumptions say a vault holding its own anchor refuses a planted floor.
- **Evidence:** reproduced (`zz-adv-open-vault-anchor`): after the open vault calls `rekey` with a forged anchor the server serves, `secureAccount` on that device reports `{ rekeyed: ["team-1"], failed: [] }` and the team opens on the forged version 9.
- **Text:** TH-20 and SP-07 Assumptions: the vault's anchor refuses a floor planted by raw writes, not one set through the vault: whoever holds the open vault can also give an owner's anchor (§6.8), so the anchor stops a planter only together with the user re-keying from an anchor an owner gave them. Residual row: TH-20, A7 or A9 with A2.

### E. A planted floor survives the documented remedy on the account's new devices

- **Kind:** wrong premise (of the TH-20 residual "trusted until an owner's anchor is given", D-54's consequence, SP-07's "an anchor from an owner repairs it, also on a device with no anchor"), combined attack.
- **Severity:** medium (two actors; a new device opens a forged team `ready`, what it writes is readable by the attacker).
- **Actors:** A7 or A9 with the account key and the session, once (plants the floor), then A2, any time later.
- **Disposition:** accept and document, **server-controlled history** group; correct the text.
- **Where:** `secureAccount`'s rotation re-wraps every wrap that opens under the new account key, a failed team's included (`rotation.ts:31-38`, D-58); the owner's-anchor repair adds a new keys version; the clean-up archives the planted wrap (`member-custody.ts`), and A2 can serve an archived record as live. A new device of the user has no vault anchor and roots on the floor of the wrap it is served.
- **Evidence:** reproduced (`zz-adv-planted-floor`): plant, `secureAccount` (team fails), `rekey` with the owner's anchor, owner approval, clean-up; then a new device with the new PIN, served the archived planted wrap and the forged version 9 with the repaired wrap withheld, opens it `ready` with owners `["mallory"]`.
- **Considered, not proposed:** leaving a failed team's wraps out of the rotation would end the planted bundle at the old account key version. But a team fails for reasons a server chooses too, so the user would lose that team's keys until an owner approves a re-key: a new failure needing a human (costly), for a combined attack. For the user's decision only.
- **Text:** TH-20 disposition, D-54's consequence and SP-07's assumptions: the repair roots the devices that run it; a new device of the account still trusts the floor of the wrap the server serves, so a server that kept a planted wrap (archived or not) roots it on the planted chain, until the device is given an owner's anchor itself. Residual row: TH-20, A7 or A9 then A2.

## Edit-only findings

B and C (code to D-58's amendment, with §4.1 wording for C); A, D and E (text: TH-17 or TH-25, TH-20, SP-07 Assumptions, D-54's consequence). None needs a decision; E's alternative does, if wanted.

## Forgeability

- `account-key-wrap`: a session can write one that parses but whose `kdf` can't be used, or a device wrap that doesn't open (B, C).
- `team-key-version` chain: an owner key can sign a valid version whose `wrappedPreviousKey` wraps the wrong key (A).
- Owner's repair anchor: also given by whoever holds the open vault, no credential (D).
- `member-keys-wrap`: an archived planted wrap, served by A2 to a new device, is its root (E).

## Stop rule

Clean under the stop rule as changed after this review: B and C are availability-only fixes, which no longer count; A, D and E are text and acceptances. With review 036, 2 of 2: freeze candidate.
