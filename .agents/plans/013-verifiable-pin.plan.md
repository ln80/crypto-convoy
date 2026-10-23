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

- **Suite:** `oprfBlind(input, info, publicKey)` returns the tweaked key; `oprfFinalize(input, info, blind, blindedElement, { evaluatedElement, proof }, tweakedKey)` checks sizes (`MALFORMED_RECORD`), then lets noble's POPRF `finalize` verify the proof: any failure there is `TRUST_FAILURE` (`bad_signature`). `oprfPublicKeyValid` decodes the point and refuses the identity.
- **Settings:** `settings.oprf = { keys, writeKeyId }`, checked in `resolveSettings` (u32 ids, 32-byte keys, `writeKeyId` present) and in `createVault` (valid points). Without `settings.oprf`, every PIN operation is `UNSUPPORTED_VERSION`.
- **Pin key:** `derivePinKey` takes the pinned keys; an unpinned id stops before Argon2id. `pinWrap` writes with `writeKeyId`. `unlockWithPin` upgrades when the id isn't `writeKeyId`, and keeps the unlock when the upgrade throws a `ConvoyError`.
- **Kit:** `FakeOprfServer` holds one POPRF key pair per id (seeded from libsodium), builds `info` from the request's account, draws the proof nonce from libsodium, and offers `clientSettings(writeKeyId?)`; `currentKeyId` is gone. README, using guide and the package smoke test pass `settings.oprf`.
- **Vectors:** `pin-key.v1.json` regenerated (v1 unreleased): RFC 9497 Appendix A.1.3 copied from the RFC and checked against noble in the generator (key pair, evaluated element, output from the RFC's proof); the composition records the public key, tweaked key and proof. The replay also checks that a flipped proof byte is refused.
- **Tests:** `pin-hardening.test.ts`: another account's evaluation and another key are now `TRUST_FAILURE`; new: a front end's own key at enrolment (no wrap written), a replayed proof, an unpinned id (no evaluation spent), writers use `writeKeyId` while a newer key is pinned, an unlock that stands when its upgrade fails, invalid OPRF settings. `memory-store.test.ts` checks the kit.
- **Guards:** weakening each rule fails a test: no proof check, an unpinned id falling back to another key, writing with the newest pinned key instead of `writeKeyId`, an upgrade failure aborting the unlock, no point check on settings. The first guard run was invalid (zsh didn't split the file list, so backups failed and weakenings stacked); the weakenings were reverted by hand and each guard re-run on its own with backups.
- **Test timeout:** the `compatibility` project gets the 30 s timeout `security` and `properties` have: the scenario test, many Argon2id runs at 64 MiB plus proofs, crossed vitest's 5 s default under the full parallel run (alone it takes about 3 s).
- **Checks:** `typecheck`, `npm test` (723 tests, twice), `check:spec`, `build`, `test:package`, `test:browser` pass.
- **Integration (doconvoy e2eev2):** breaking. `OprfService.evaluate` returns `{ evaluatedElement, proof }` and `currentKeyId` is gone; the Go OPRF service moves to POPRF (one key pair per key id, `info` from the charged account, CSPRNG proof nonces), and the client ships `settings.oprf` in its code. Stored base-mode PIN wraps from test data fail as `UNSUPPORTED_VERSION` once their key id isn't pinned: reset or recover with the phrase.
- **Left:** the local course (D-52, D-53).

