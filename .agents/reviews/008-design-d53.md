# Review 008: design, D-53 (verifiable PIN hardening)

Mode: `design`, with a fresh-context reviewer. Input: the proposal for review 006 E, before code, at `df9bcb9`. Read only.

## The proposal

PIN hardening moves from RFC 9497 base mode to POPRF (mode 0x02, ristretto255-SHA512): one server key pair per `oprfKeyId`, public info `enc(label("pin-oprf"), accountId)`; the server returns the evaluated element with a DLEQ proof, which the client verifies against a public key the integration ships in its client code (AS-02), never from the server. Rotation: the client upgrades only to key ids it has a public key for. Unchanged: one evaluation per attempt, never retried, one budget per account, Argon2id, the `pinKey` formula.

## Checked

- The reviewer got the proposal, `docs/`, `src/`, `test/` and `@noble/curves` only. It confirmed POPRF with a pinned public key is the smallest primitive that closes 006 E, and that noble implements it (`ristretto255_oprf.poprf`, proof verified in `finalize`).
- **Not checked:** circl's POPRF support in Go, RFC 9497's exact query bounds, whether doconvoy stored base-mode PIN wraps, rotation paths when a new PIN's evaluation fails mid-rotation.

## Findings

### A. The key id stays a server input, and every enrolment is exposed, not just the upgrade

- **Kind:** forgeable input. **Severity:** high (as a gap in the proposal).
- **Evidence (read):** every enrolment asks `currentKeyId` then evaluates with purpose `enroll` (`src/account/unlock-methods.ts:49-51`): setup, `changePin`, `recover`, `rotate` and `secureAccount` with a new PIN, and the upgrade (`vault.ts:238-241`); `purpose` even tells a front end which evaluation to fake. POPRF stops the faked evaluation, but a server that controls `currentKeyId` can still send writers back to an older pinned key (one retired because it leaked), or flip ids to force an extra evaluation per unlock (budget burn).
- **Fix proposed:** the key id writers use is a client setting, as D-17 does for the Argon2id cost: settings hold `{ oprfKeys: { id → publicKey }, writeKeyId }`; writers use `writeKeyId`; readers accept any pinned id; the upgrade on unlock runs when `wrap.oprfKeyId !== writeKeyId`. `OprfService.currentKeyId` is removed. Rotation follows §10's two releases: pin the new key for reading, then make it `writeKeyId`.
- **Needs:** a decision.

### B. One key for every account: proof nonces and query volume

- **Kind:** hardening, integration duty. **Severity:** medium.
- **Evidence (read):** DLEQ proofs use server randomness (`s = r − c·k`): a repeated or biased `r` reveals the key, and with one key per `oprfKeyId` that exposes every account (today a per-account key). The tweaked key `t = skS + m(info)` with public `m`: anyone who gets one account's `t` recovers `skS`. All accounts' queries hit one key (RFC 9497's static-DH consideration), and outsiders (A10) can open accounts with their own budgets. A key holder gains nothing over today's seed holder (TH-09).
- **Fix proposed:** accept the shared key (per-account public keys can't be pinned in client code) with integration duties: proof nonces from a CSPRNG, never deterministic (fixed-`r` vectors are test-only); never export a per-account tweaked key; rotate `oprfKeyId` periodically or cap evaluations per key id. Write POPRF's stronger assumption into D-53's Consequence.
- **Needs:** a decision (accept with duties).

### C. SP-08 holds only if the server builds `info`

- **Kind:** spec gap. **Severity:** medium.
- **Evidence (read):** a server that took `info` from the request would let a session for X (A11) guess against Y on X's budget. Scope rule 2 ("a separate OPRF key per account"), §11's "per-account key" and the `pin-oprf` label row change meaning.
- **Fix proposed:** rule 2: the server builds `info` from the account it charges, never from the request; the client builds it only to compute the key it verifies against.
- **Needs:** an edit.

### D. A bad proof: error, order, and the upgrade

- **Kind:** spec gap. **Severity:** medium.
- **Evidence (read):** `WRONG_CREDENTIAL` would make users retype and spend budget; `STORE_ERROR` is retried by integrations. Today a failed upgrade evaluation aborts `unlockWithPin` after the PIN was verified (`vault.ts:238-245`), `PIN_RATE_LIMITED` included; `recover` already keeps the vault open.
- **Fix proposed:** an unpinned key id is `UNSUPPORTED_VERSION` before Argon2id or any evaluation; sizes and canonical encodings checked before verification (§8 order); a failed proof is `TRUST_FAILURE` before anything is derived, never retried; settings refuse an invalid or identity public key (`MALFORMED_RECORD`). The unlock stands when only the upgrade fails, the old wrap kept (§5.4 widened from `PIN_RATE_LIMITED` to any failure). Reason for the proof: reuse `bad_signature`, or a new `bad_proof`.
- **Needs:** a decision (the reason), the rest an edit.

### E. Format: change cc1 in place while v1 is unreleased

- **Kind:** spec choice. **Severity:** low.
- **Evidence (read):** the wrap's associated data already binds `oprfKeyId` (§4.1); only `y` changes. `wrap.v1.json` has no PIN wrap; `pin-key.v1.json` and the RFC 9497 base-mode vectors change.
- **Fix proposed:** change cc1's PIN hardening row to POPRF, keep the wrap layout, replace the PIN vectors. POPRF key ids start above any id used before, so a base-mode wrap stored in a test deployment fails with `UNSUPPORTED_VERSION` (recover with the phrase), never with `WRONG_CREDENTIAL`.
- **Needs:** a decision.

### F. Where the guarantee applies

- **Kind:** missing threat. **Severity:** low.
- **Evidence (read):** it helps only where the OPRF key is isolated from the API front end, and only if client code isn't served by that front end (AS-02, TH-26).
- **Fix proposed:** a threat for the front end without the key (forged evaluations, downgraded key ids), mitigated by D-53; amend AS-05.
- **Needs:** an edit.

## Smallest rule (reviewer)

PIN evaluations are RFC 9497 POPRF with `info = enc(label("pin-oprf"), accountId)`, built by the server from the account it charges. The client verifies every proof against the public key its settings pin for the wrap's `oprfKeyId`, and writes only with the settings' `writeKeyId`, never a server value. An unpinned id is `UNSUPPORTED_VERSION` before any work; a failed proof is `TRUST_FAILURE` before anything is derived. Neither is retried, and the unlock stands if only the upgrade fails.
