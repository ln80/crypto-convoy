# Plan 013: verifiable PIN hardening (review 006 E, review 008)

## Context

Review 006 E (medium): the PIN's OPRF runs in RFC 9497 base mode, with no proof. A party that controls the server's answers for a while without holding the OPRF key (a compromised front end) answers with a key it chose; moving `currentKeyId` forces every account to re-enrol. Every PIN wrap enrolled in that window then depends on Argon2id(PIN) alone, and a later data thief guesses it offline. Reproduced.

Review 008 (`.agents/reviews/008-design-d53.md`, design mode, fresh-context reviewer) checked the POPRF proposal and found: the key id stays a server input, and every enrolment is exposed (A, high); one key per key id needs integration duties (B); SP-08 needs the server to build `info` (C); a bad proof's error, order and the upgrade's failure (D); the format (E); a missing threat (F).

**Decisions (user):** POPRF (006 E); 008-A: the key id writers use is a client setting, `currentKeyId` removed; 008-B: accept the shared key with integration duties; 008-D: a failed proof is `TRUST_FAILURE` (`bad_signature`); 008-E: change cc1 in place while v1 is unreleased. C, F and the rest of D are edits.

RFC 9497 Appendix A.1.3 (POPRF, ristretto255-SHA512) checked against `@noble/curves`: key pair, evaluated element and output from the RFC's proof match; a flipped proof is refused.

## Design (D-53)

1. **Primitive (§2, cc1):** RFC 9497 POPRF, ristretto255-SHA512, with public info `enc(label("pin-oprf"), accountId)`. One server key pair per `oprfKeyId`. `pinKey` unchanged.
2. **Settings:** `oprf: { keys: { [oprfKeyId]: publicKey }, writeKeyId }`, shipped in the integration's client code (AS-02). A key that isn't a valid non-identity element, or a `writeKeyId` with no key, is `MALFORMED_RECORD` at `createVault`.
3. **Derivation (§5.1):** the `kdf` bounds; then a key id with no pinned key is `UNSUPPORTED_VERSION`, before Argon2id or any evaluation; blind with the tweaked key; one evaluation, never retried; element and proof sizes (§8 order); then the proof is verified before anything is derived: a failure is `TRUST_FAILURE` (`bad_signature`).
4. **Key id (§5.3, §5.4, §5.6):** writers use `writeKeyId`, never a server value; readers accept any pinned id; the upgrade on unlock runs when the wrap's id isn't `writeKeyId` or its cost is below the writer's. The unlock stands when only the upgrade fails; the old wrap is kept.
5. **Port (§12):** `OprfService.evaluate` returns `{ evaluatedElement, proof }`; `currentKeyId` is removed.
6. **Server contract (rule 2):** one POPRF key pair per key id; `info` built by the server from the account it charges, never from the request; proof nonces from a CSPRNG; no per-account tweaked key ever exported; key ids rotated, or evaluations capped per key id. Rotation in two releases: pin the new key for reading, then make it `writeKeyId`.
7. **Threats and properties:** a new threat for a front end that forges evaluations or picks key ids, mitigated by SP-08 (D-53); TH-09, AS-05, SP-08 text and Verification; D-17's Consequence.
8. **Format:** cc1 changed in place (v1 unreleased): the wrap layout stays, `pin-key.v1.json` is replaced with the RFC's POPRF vectors and the composition. POPRF key ids start above any id used before.

## Phases (one commit each)

1. **Spec:** D-53; §1 label row, §2 suite row, §5.1, §5.3, §5.4, §5.6, §8, §9, §11, §12, §13; scope rule 2 and the interfaces; integration guide (OprfService, key rotation); using guide; key hierarchy; TH-09, the new threat, AS-05, SP-08; D-17. Review 008, ledger.
2. **Code, kit, tests, vectors:** `src/suites/suite.ts` and `cc1` (POPRF), `src/account/pin-key.ts`, `src/account/unlock-methods.ts`, `src/account/vault.ts` (upgrade), `src/ports.ts` (port, settings), `src/testing/fake-oprf-server.ts`; `pin-key.v1.json` and its generator; `pin-hardening.test.ts` (forged and replayed proofs, an unpinned id, no server-chosen key id, an upgrade that fails); fixtures. Prove each guard.
3. **Notes:** execution notes, reviews and ledger.

## Execution notes
