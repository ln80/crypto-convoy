# 001 — crypto-convoy v1: library, browser adapter and test kit


## Context

The crypto-convoy specs are settled: scope, decisions D-01…D-22, threats TH-01…TH-38, properties SP-01…SP-20, the key hierarchy, and protocol v1 with suite `cc1`. The repo is still a scaffold: `src/index.ts` exports only a version, `test/*` holds only `.gitkeep` files, and no runtime dependency is installed.

This plan implements the whole protocol as a TypeScript library, plus:
- the `crypto-convoy/browser` adapter (D-08, D-22);
- a published `crypto-convoy/testing` kit.

It reuses what the doconvoy `frontend/app/src/e2ee` hardening proved useful:
- a suite registry;
- validation before crypto;
- checking the return value of secretstream `pull`;
- an honest fake server with tamper hooks;
- frozen vectors checked against raw libsodium;
- a boundary test;
- "prove the guard" tests, which break the rule on purpose and confirm the test fails.

It also fixes two gaps found in that module: keys are never zeroed, and the fragment key is never removed from history.

The library has to be easy to adopt in doconvoy later. That work, a separate plan in doconvoy, covers:
- a new TypeScript adapter implementing the four ports over HTTP;
- reworking `internal/core/e2ee` and `api/e2ee` in Go into a store that follows §11 of the protocol;
- a per-account OPRF.

The ports, the test kit and an integration guide are designed with that hand-off in mind.

**Decisions taken with the user:**
- Public operations throw one typed `ConvoyError`. Internal parsers stop at the first failure.
- `crypto-convoy/testing` is published: an honest in-memory store following the §11 server rules, a fake OPRF server, a memory `LocalKeyStore` and a fixed clock. Tamper hooks stay in `test/support/`.
- There is one master plan with phases.

## Execution mode

- **Autopilot.** Run the phases one after another without stopping for check-ins. Stop only for a real blocker that needs the user to decide, for example:
  - a spec gap whose fix would change a guarantee or a released format;
  - a dependency that can't be installed;
  - a conflict between documents that `protocol-change` can't settle without a decision.
- **Failing tests.** When a test fails:
  1. Read the error.
  2. Fix the root cause.
  3. Re-run only the affected project or file.
  4. Run the full gate once before the commit.
  
  Never weaken a test or a check to get green. Never re-run a check that already passed when nothing has changed since.
- **Care.** Before each commit, re-read the diff against the protocol §. At the end of each phase, append its execution notes.

## Ground rules for every step

Rules from `AGENTS.md` and `.agents/guides/*`:
- **Order of work:** spec first, then vectors, then code, then tests. Each step uses the `implement-from-spec` workflow; its security tests use `security-property-tests`.
- **Spec gaps:** never guess. A gap found during execution goes through `protocol-change`, then `npm run check:spec`, before any code.
- **One commit per step.** Commit messages carry no `Co-Authored-By` line.
- **Code docs stay lean.**
  - Exported operations and types get a short TSDoc: what the operation does, the protocol § it implements, and the `ConvoyError` codes it throws.
  - Inside the code, comment only what the code can't say: why a check exists (with its SP/TH id), and libsodium pitfalls.
  - No narrating comments, no repeating the spec, no prose blocks. The `docs/` files explain the design; the code points to them by §.
- **Gate before each commit:**
  - `npm run typecheck`
  - `npm test`
  - `npm run check:spec` when `docs/` changed
  - `npm run test:fuzz` when a parser changed
  - `npm run build` when exports or dependencies changed
- **Security tests:**
  - Each test asserts the exact `code` and `reason`.
  - Each attack test gets a "prove the guard" pass: remove the check, watch the test fail, restore it. Record this in the execution notes.
- **Every new test file:**
  - starts with an SP/TH header;
  - names its `describe` after the property;
  - is listed under the property's Verification line if it covers one.

## Target layout

This follows `.agents/guides/architecture.md`. Additions are marked with `+`.

```
src/
  index.ts            public API only (D-15)
  errors.ts           ConvoyError {code, reason?}; fixed messages per code (§9)
  ports.ts            RecordStore, OprfService, LocalKeyStore, Clock, Settings
  internal/bytes.ts + concat, constant-time equal (through the suite), best-effort wipe
  encoding/           canonical.ts (§1), base64url.ts (strict), labels.ts (§1 table), link.ts (§3.5), json.ts (+ strict record reader)
  suites/             suite.ts (interface), registry.ts (SUITES, CURRENT_SUITE, suiteFor), cc1/{sodium.ts, index.ts, ed25519-strict.ts, x25519.ts, stream.ts, oprf.ts, bip39.ts}
  blocks/           + wrap.ts, seal.ts, sign.ts, stream.ts (§3.1–3.4, label + context built here)
  records/            account-key-wrap, member-keys, member-keys-wrap, team-state, team-key-version, grant, item, inbox, submission (one module each)
  account/            vault.ts, pin-key.ts, recovery-key.ts, devices.ts, rotation.ts, member-custody.ts
  team/               session.ts, chain.ts, anchors.ts, grants.ts, rotation.ts, owners.ts, access-state.ts, reports.ts
  content/            items.ts, link-share.ts, inbox.ts, submissions.ts
  browser/            index.ts → crypto-convoy/browser: indexeddb-local-key-store.ts, take-link-key.ts
  testing/          + index.ts → crypto-convoy/testing: memory-record-store.ts, fake-oprf-server.ts, memory-local-key-store.ts, fixed-clock.ts
test/
  support/            fake-store.ts (tamper hooks over MemoryRecordStore), fixtures.ts (accounts, teams, low-cost Argon2 settings), recording-store.ts
  vectors/            *.v1.json (§13) + generate/ (independent generators, refuse to overwrite)
  unit/ properties/ security/ compatibility/ fuzz/
docs/
  libsodium-map.md  + the libsodium mapping the user asked for
  integration.md    + product-neutral guide for implementing the ports and the server contract
```

**Layer rule.** Imports go one way only: `suites` → `blocks` → `records` → `account` / `team` / `content` → `index`. The parts that never import the others:
- `encoding/` imports nothing from the library.
- The core never imports `browser/` or `testing/`.
- `testing/` imports core internals only, never `browser/`.

---

## Phase 0 — Close spec gaps and set up tooling

**0.1 Spec closure** (`protocol-change`, docs only). The current docs leave these points to the implementation; each one is written down before any code:
1. **Port contracts.**
   - Add an informative subsection to `scope.md` "Interfaces" and to protocol §12.
   - **`RecordStore`:**
     - `get(key)` and `list(query)`.
     - `commit(ops[])` applies ops atomically. Each op is `create` (write-once), `compareAndSet(expectedRevision)` or `delete`.
     - Record keys are the §11 identities.
     - `currentAccountKeyVersion` is served through an account pointer that changes only in the atomic switch.
     - Error mapping: `conflict` → `STALE_VERSION` (or a compare-and-set retry for `team-state`), `unavailable` → `STORE_ERROR`.
   - **`OprfService.evaluate(accountId, blinded, oprfKeyId, purpose)`**, plus `currentKeyId(accountId)`, needed for the upgrade on unlock (§5.4). Its rate-limit refusal maps to `PIN_RATE_LIMITED`.
   - **`LocalKeyStore`:** per account, `{ deviceId, deviceKey, highestAccountKeyVersion }`. Per account and team, the anchor `(version, hash)`.
   - **`Clock.now()`** returns Unix seconds.
   - **`Settings`:** `{ argon2: { write, min }, maxBufferedSize }`, with the D-17 floor applied.
2. **§2 strict checks**, written as an exact list so the Go side can match them:
   - Ed25519: `S < L`; the public key is canonical and not of small order; `R` is not of small order.
   - X25519: a low-order point blocklist, including the non-canonical encodings of those points.
   - Each check gets cases in `team-key.v1.json`, `seal.v1.json` and `link.v1.json`.
3. **§4.4:** the first `team-state` revision is 1, and "absent" means no anchor on the server.
4. **D-08 detail:** the browser adapter's at-rest format.
   - `deviceKey` and the anchors are encrypted with AES-GCM-256, under a non-extractable WebCrypto key stored by structured clone.
   - The associated data binds `label("local-device-key")` / `label("local-anchor")`, plus `accountId` and `teamId`.
   - Add these labels to the §1 table. Note that the adapter's AES-GCM is the one primitive not from libsodium, because only WebCrypto can make a key non-extractable.
5. **§3.6 note:** the OPRF `blind` and the BIP-39 entropy draw their randomness from `randombytes_buf`. `@noble/curves` `blind(input, rng)` receives it; the mnemonic comes from `entropyToMnemonic(randombytes_buf(16))`.

Exit: `npm run check:spec` passes.

**0.2 Dependencies and packaging.**
- Runtime dependencies, pinned exactly:
  - `libsodium-wrappers-sumo` 0.8.x (sumo is needed for `crypto_pwhash` and `crypto_core_ed25519_is_valid_point`);
  - `@noble/curves` 2.4.x (`ristretto255_oprf`);
  - `@scure/bip39` 2.x.
- Dev dependencies: `@types/libsodium-wrappers-sumo`, `fake-indexeddb`.
- `package.json` `exports`: `.`, `./browser`, `./testing`.
- Vite: a multi-entry library build, with one dts per entry.
- `api-extractor`: one API report per entry under `etc/`, so every public surface change is reviewed (D-15).

**0.3 Guard tests.** These run green on the empty skeleton.
- `test/unit/boundary.test.ts` checks:
  - the import allowlist in `src/`;
  - no `libsodium` import outside `src/suites/`;
  - no DOM globals outside `src/browser/`;
  - the core never imports `browser/` or `testing/`;
  - `exports` lists only the three entries.
- `test/unit/traceability.test.ts` parses `docs/security-properties.md`. Every non-deferred SP's Verification file must exist and mention its id.
  - It is **soft until Phase 6**: it lists the missing files as `todo`. After Phase 6 it becomes strict.
- `test/unit/libsodium-map.test.ts` greps `src/suites/**` for `sodium.<fn>` and fails if any function is missing from `docs/libsodium-map.md`, or if the doc lists one that is never used.

**0.4 `docs/libsodium-map.md` skeleton.**
- Columns: libsodium function | suite method | protocol task (§) | size and limit checks done before the call | source file.
- A second table covers primitives that don't come from libsodium: the OPRF (`@noble/curves`), BIP-39 (`@scure/bip39`) and the adapter's WebCrypto AES-GCM.
- Initial rows (finalised in Phase 1):

| libsodium | Task |
| --- | --- |
| `ready` | one memoized init in `cc1/sodium.ts`; `createConvoy` awaits it |
| `randombytes_buf` | every key, nonce, id, salt, OPRF blind, BIP-39 entropy (§3.6) |
| `crypto_aead_xchacha20poly1305_ietf_encrypt` / `_decrypt` | `wrap` / `unwrap` (§3.1): account-key, member-keys, team-state, team-key-link, item-key, item-manifest, inbox-key wraps |
| `crypto_box_seal` / `crypto_box_seal_open` | `seal` / `open` (§3.2): grant-seal, submission envelope |
| `crypto_box_keypair`, `crypto_scalarmult_base` | member encryption and inbox key pairs; recompute the public key in the post-checks of §4.3 and §4.9 |
| `crypto_sign_seed_keypair`, `crypto_sign_detached`, `crypto_sign_verify_detached`, `crypto_core_ed25519_is_valid_point` | member signing keys from the seed (§4.3); `sign` / strict `verify` (§2, §3.3) |
| `crypto_generichash` (unkeyed) | record hash (§4.5), hashes of wrapped values and sealed keys bound in signatures (§4.5–4.7) |
| `crypto_generichash` (keyed) | `pinKey` (§5.1), `recoveryKey` (§5.2) |
| `crypto_generichash_init` / `_update` / `_final` | incremental ciphertext hash of a stream (§3.4) |
| `crypto_secretstream_xchacha20poly1305_init_push` / `_push` / `_init_pull` / `_pull`, `TAG_MESSAGE` / `TAG_FINAL` | `stream` (§3.4): item parts, submission parts |
| `crypto_pwhash` (`ALG_ARGON2ID13`) | Argon2id over the PIN, with bounds (§2, §5.1) |
| `memcmp` | constant-time comparison of public keys, hashes and anchors |
| `memzero` | best-effort wiping of keys after use |

**0.5 Test support skeleton.**
- `test/support/fixtures.ts`: Argon2 at the floor, `opslimit` 2 and 64 MiB, the cheapest cost allowed (§2).
- `vitest.config.ts`: a `browser-adapter` project, still in Node, with `fake-indexeddb` and Node's `webcrypto`.

---

## Phase 1 — Encoding, suite `cc1` and building blocks (§1–§3)

**1.1** `errors.ts`:
- `ConvoyError` with the §9 codes and `TRUST_FAILURE` reasons;
- a fixed message per code, never built from input;
- `isConvoyError(e, code?)`.

Unit tests check that messages never contain input bytes.

**1.2** `encoding/canonical.ts`:
- a writer for `u8`, `u32`, `u64` (as `bigint`, refusing anything above 2^53 on the JSON side), `bytes`, `string`, `list`, `optional`;
- a reader that refuses trailing bytes and lengths past the end.

`labels.ts` holds the §1 table as a frozen `const` and `label(name)`. Only names in the table type-check.
- Vectors: `canonical.v1.json`, generated independently (hand-written hex).
- Properties: round trip, and "any truncation fails".

**1.3** `encoding/base64url.ts` is strict and decodes every byte value from the server or a link. It refuses:
- padding and the `+` and `/` characters;
- non-canonical trailing bits (decode, re-encode and compare);
- the wrong length for the field.

It is written in plain TypeScript with no libsodium, so the encoding layer stays independent.

**1.4** `suites/`:
- `Suite` interface as in the architecture guide;
- `registry.ts` with `suiteFor(id)`, which throws `UNSUPPORTED_VERSION` before any crypto;
- `cc1` implemented over sodium.

Rules inside `cc1`:
- exact sizes are checked before every call;
- every return value is checked; `pull` returning `false` gives `DECRYPTION_FAILED`;
- `ed25519-strict.ts` writes its checks explicitly instead of relying on libsodium's defaults;
- `x25519.ts` holds the low-order blocklist.

**1.5** `blocks/`:
- `wrap` / `unwrap`, `seal` / `open` (context inside the box, nothing allowed after `body`), `sign` / `verify`;
- `stream` / `unstream`:
  - buffered by default;
  - an opt-in async-iterator variant that yields only authenticated chunks and ends with an error on truncation;
  - the incremental ciphertext hash is computed as the stream runs.

Every block takes `(name: Label, context: Field[])`, so call sites can't forget the label or the context.

**1.6** `encoding/link.ts`, written against the §3.5 rules:
- `encodeLinkKey` / `decodeLinkKey`, with the version prefix `1`, exactly 32 bytes, and the low-order check for inbox keys;
- `encodeAnchor` / `decodeAnchor`.

**1.7 Vectors and tests.**
- Vectors: `wrap.v1.json`, `seal.v1.json`, `stream.v1.json`, `link.v1.json`, generated by `test/vectors/generate/*.ts`. The generators use raw `libsodium-wrappers-sumo` and their own small encoder, never `src/`, and refuse to overwrite an existing file.
- Compatibility replay.
- Properties: any flipped byte fails; a value moved to another context fails.
- Security:
  - first cases of `partial-decrypt.test.ts` (SP-18): truncation, missing `FINAL`, early `FINAL`, short chunk, unknown tag;
  - link-prefix cases of `downgrade.test.ts` (SP-17).
- Fuzz: `records.fuzz.test.ts` starts with the decoders (canonical, base64url, link).

**1.8** Fill in the `libsodium-map.md` rows from the code, so the map test passes.

## Phase 2 — Records (§4, §8)

**2.1** `encoding/json.ts` reads a record in the §8 order, stops at the first failure, and dispatches on `v`:
1. shape: the exact field set, no unknown fields, types, base64url lengths, and the D-18 bounds;
2. `v` and `suite`;
3. context ids against the ids the caller asked for.

**2.2** One module per record type, each with:
- `type`;
- `parse(json, expected)`;
- `payloadV1(...)`, a frozen `case 1`;
- `build(...)`, used by writers through `CURRENT_SUITE`;
- `open(...)`, used by readers through `suiteFor(record.suite)`.

The post-checks of §4.3 (`key_mismatch`), §4.9 (recomputed public key) and §4.7 (manifest indexes 0…n−1, 1–128 parts, `meta` up to 4096 bytes) live here.

**2.3 Vectors and tests.**
- Vectors: the record-level cases of `team-key.v1.json`, `item.v1.json` and `submission.v1.json`.
- Fuzz: `records.fuzz.test.ts` (SP-18) covers every parser.
- Security: `downgrade.test.ts` (SP-17) covers every record type with an unknown, older or mismatched `v` or `suite`, and checks that no crypto call is made (a spy suite).

## Phase 3 — Ports and the `crypto-convoy/testing` kit

**3.1** `ports.ts` with the contracts from 0.1, documented in TSDoc. `Settings` applies the D-17 floor and refuses lower values when the library is configured.

**3.2** `testing/`:
- **`MemoryRecordStore`** applies every §11 rule:
  - write-once records;
  - compare-and-set on `team-state`;
  - atomic `commit`;
  - team key version must be current + 1, stored with its signer's grant;
  - grants, items and inboxes only at the current version;
  - parts only after their item;
  - private records served only to their account. The caller identity is passed on each call, to stand in for authentication.
  - Removed wraps are soft-deleted, with a hidden restore window (TH-36).
- **`FakeOprfServer`** implements RFC 9497 `DeriveKeyPair(seed, enc(label("pin-oprf"), u32 oprfKeyId, accountId))`, with one total budget per account across `unlock` and `enroll`, key replacement, and a retired key that keeps working.
- **`MemoryLocalKeyStore`** and **`fixedClock`**.

**3.3** `test/support/fake-store.ts` wraps `MemoryRecordStore` with the tamper hooks from the testing guide: swap, replay, rollback, drop, fork, garbage, withhold.
- `recording-store.ts` keeps every byte written, for SP-01.
- Unit tests prove the honest store refuses each §11 violation. These tests double as the server contract the Go side must reproduce.

## Phase 4 — Account vault (§5)

**4.1** `pin-key.ts` (§5.1):
1. NFKC normalisation;
2. bounds checks;
3. Argon2id;
4. OPRF blind and evaluate. There is no retry anywhere, and a test asserts the store is called exactly once.
5. finalize;
6. keyed BLAKE2b.

`recovery-key.ts` (§5.2) normalises with NFKD, checks the checksum, derives the seed, then applies keyed BLAKE2b.

Vectors: `pin-key.v1.json` (including the RFC 9497 vectors) and `recovery-key.v1.json`.

**4.2** `vault.ts`:
- `setup(pin) → { recoveryPhrase }`, as one atomic commit;
- `unlock()`, which throws `DEVICE_NOT_REGISTERED`;
- `unlockWithPin(pin)`, with the upgrade on unlock;
- `recover(phrase, newPin)`.

The account key version is never lower than the highest the device has seen (SP-07). Failed PIN or recovery wraps give `WRONG_CREDENTIAL`.

**4.3** Device operations (`devices.ts`): register, `listDevices`, `revokeDevice`. The device wrap is never cached.

Credential operations: `changePin`, `replaceRecoveryPhrase`.

**4.4** `rotation.ts` (§5.7): re-wrap every `member-keys-wrap` in the new account key version, then switch the current version in one atomic batch.

**4.5** `member-custody.ts` (§5.8, §5.9):
- create member keys;
- `openTeam` hands over only the bundle. The account key lives in a `#private` field of the vault and never crosses into a team session.
- `leaveTeam`, which throws `LAST_OWNER` for the only owner.

**4.6** Security tests:
- `pin-hardening.test.ts` (SP-08)
- `credential-rotation.test.ts` (SP-09)
- `device-revocation.test.ts` (SP-10). The full remedy is finished in Phase 5.
- `account-rotation.test.ts` (SP-11)
- `recovery.test.ts` (SP-19), including its Limit

## Phase 5 — Team session (§6, §9)

**5.1** `chain.ts` and `anchors.ts` (§4.5, §6.1):
- verify consecutive versions, version 1 rules, `prevHash`, the owner rule, and that owners match their `member-keys`;
- the chain must contain every anchor: a different record for a version is `chain_conflict`, a chain that stops short is `rollback`;
- nothing newer is adopted before the check passes;
- `team-state` is read and written by compare-and-set, with the retry rule.

Vectors: the chain cases of `team-key.v1.json` (forks, gaps, a removed owner, strict Ed25519 cases).

**5.2** `session.ts`:
- `openTeam` runs the load sequence of §6.1;
- access state per §9. `unverified` is sticky for the session;
- `reports` lists owner changes and new approvals (SP-15). It is pull-based, so it is easy to test and the integration can display it.

**5.3** Team operations:
- `createTeam` and `joinTeam({ anchor })`;
- `grant`, `members()`, `inviteAnchor()`;
- `rotate({ keep, approveRekeys })`:
  - `keep` is an allowlist, with one key set per account;
  - writes `STALE_VERSION` on conflict;
  - can resume after an interruption;
- `setOwners(owners, { keep })`, which warns about members granted by a removed owner;
- `needsRotation(active)`;
- opening earlier versions through the chain (§6.2), cached for the session.

Vault side: `rekey(teamId)`, with the continuity hint.

**5.4** Security tests:
- `owner-chain.test.ts` (SP-05)
- `rollback.test.ts` (SP-07)
- `key-substitution.test.ts` (SP-04)
- `member-rekey.test.ts` (SP-12)
- `change-visibility.test.ts` (SP-15)
- `owner-continuity.test.ts` (SP-16)
- `team-isolation.test.ts` (SP-02)
- `device-revocation.test.ts` (SP-10): finish the full remedy (rotate the account key, then re-key).

## Phase 6 — Content (§7)

**6.1** `items.ts`:
- `createItem` returns `{ record, parts }`;
- `openItem` is buffered, and refuses parts above `maxBufferedSize` **before** fetching them;
- `openItemStream` is the opt-in streaming read.

`link-share.ts`: `shareLinkKey(itemId)` and `openSharedItem(linkKey, teamId, itemId)`. The link key is an opaque `LinkKey` string; the item key never leaves the library.

**6.2** `inbox.ts`: `createInbox` and `replaceInbox`. `submissions.ts`: `submitToInbox`, which seals to the key **from the link**, and `openSubmission`.

**6.3** Vectors: the complete `item.v1.json` and `submission.v1.json`.

Security tests:
- `ciphertext-tampering.test.ts` (SP-03)
- `inbox.test.ts` (SP-14)
- `member-removal.test.ts` (SP-06), including its Limit: re-admitting a member opens the gap.
- `partial-decrypt.test.ts` (SP-18): the `maxBufferedSize` cases, and a truncated stream ending with an error.
- `server-view.test.ts` (SP-01): every operation runs through the recording store; no recorded byte sequence may equal a key or a plaintext.

**6.4** The traceability test becomes strict: every non-deferred SP has passing tests.

## Phase 7 — Browser adapter (`crypto-convoy/browser`)

**7.1** `IndexedDbLocalKeyStore({ indexedDB?, subtle?, dbName? })`:
- the platform APIs can be injected, for tests and workers;
- the format is the one fixed in 0.1 (D-08): AES-GCM-256 under a non-extractable key generated once and stored by structured clone, IVs from the suite's randomness, and labelled associated data binding `accountId` / `teamId`;
- an entry that fails to decrypt is an error, never a silent reset;
- `clear(accountId)` is offered for sign-out.

**7.2** `takeLinkKey({ location?, history? })`:
1. read the fragment;
2. decode it with `decodeLinkKey` (prefix and length);
3. `history.replaceState` with the fragment removed;
4. return the `LinkKey`, or throw `MALFORMED_RECORD`. The fragment is removed even when decoding fails.

This fixes the doconvoy gap in `use-fragment-key.ts`.

**7.3** Tests run in Node with `fake-indexeddb`, `globalThis.crypto.subtle` and fake `location` / `history`. They check:
- a round trip;
- tampered rows are refused;
- the stored key is non-extractable: `exportKey` rejects;
- no raw `deviceKey` bytes appear in any stored value;
- the fragment is gone after both success and failure.

## Phase 8 — Developer experience and integration readiness

**8.1 Public API pass.**
- Entry points:
  - `createVault({ store, oprf, localKeys, clock?, settings? }, accountId)`;
  - `createLinkClient({ store, clock? })` for `openSharedItem` and `submitToInbox`;
  - the types and `ConvoyError`.
- Rules:
  - `createVault` and `createLinkClient` are the only async setup step that awaits libsodium.
  - No primitive, suite or raw key is exported (the api-extractor reports prove it).
  - Every operation has a short TSDoc that cites its protocol § and the errors it can throw (see the lean-docs rule).

**8.2** README usage guide:
- quick start with the testing kit;
- vault vs session custody;
- handling each error code;
- the share-link checklist;
- streaming vs buffered reads.

**8.3** `docs/integration.md`, product-neutral, for porting the server side to any backend:
- mapping §11 identities to storage keys;
- write-once, compare-and-set and atomic batches (a transactional write);
- per-account OPRF with `DeriveKeyPair`, the info label and one total budget;
- the strict Ed25519 and X25519 checks a non-libsodium server must add, as the Go standard library needs;
- the restore window;
- which vectors a server implementation should replay.

**8.4** Hand-off section in this plan, not in `docs/` (product terms are forbidden there): the doconvoy follow-up plan.
- A new HTTP adapter implementing `RecordStore` and `OprfService` over reworked `api/e2ee` routes.
- `internal/core/e2ee` storage rebuilt on the §11 rules, with DynamoDB transactions for the atomic batches, and run against the testing kit's contract cases.
- OPRF info changed to the `pin-oprf` label.
- A React binding as a separate package.
- A data migration or reset, per D-01.

**8.5** `npm run prepublishOnly` passes, and the bundle contains no Node-only APIs in the core or `browser/` entries.

---

## Verification (end to end)

- `npm run typecheck && npm test && npm run test:fuzz && npm run check:spec && npm run build` all pass.
- The traceability test is strict and green: all 18 non-deferred SP test files exist and pass.
- The boundary and libsodium-map tests are green, and the api-extractor reports show only high-level operations.
- Compatibility replays all 10 `*.v1.json` vector files. The generators can't overwrite them.
- A scenario test (`test/compatibility/scenario.test.ts`) runs through the testing kit:
  1. two accounts set up and create or join a team;
  2. the owner grants;
  3. items, a share link, an inbox and a submission are created;
  4. a member is removed and the team rotates;
  5. a member re-keys, owners change, and the account key rotates.
- Every step reads back correctly. It doubles as executable documentation.
- The "prove the guard" pass is recorded for each security test in the execution notes.

## Execution notes

_Appended per phase: what changed, deviations, spec changes made through protocol-change, follow-ups._

### Phase 0 (done)
- Spec closure committed before code: the §2 strict lists (Ed25519 small-order R, X25519 low-order keys, both with bit 255 ignored; the Ed25519 list was checked against the 8-torsion computed with `@noble/curves`), §3.6 randomness, §3.7 local storage with labels `local-device-key`, `local-account-version` and `local-anchor`, §4.4 first revision, §12 interface contracts, D-23 and D-24.
- Deviation: the public surface is guarded by entry-point tests and by reviewing the bundled `dist/*.d.ts`, instead of api-extractor reports. `vite-plugin-dts` already bundles each entry with api-extractor; a separate report config adds tooling and no extra guarantee. To revisit before the first release.
- Added a `browser` vitest project, included in `npm test`. The libsodium versions: `libsodium-wrappers-sumo` 0.8.4 (libsodium 1.0.22), `@noble/curves` 2.4.0, `@scure/bip39` 2.4.0, all pinned exactly.
- Proved the guard: the boundary test fails on a layer violation, an unlisted dependency and a DOM global.

### Phase 1 (done)
- §3.4 clarified: ⌈length / 4 MiB⌉ chunks, at least one, so an exact multiple ends with a full `FINAL` chunk.
- Vectors: canonical (expected bytes written by hand), wrap, seal, stream and link, from `test/vectors/generate/*.mjs` (raw libsodium and their own encoder; they refuse to overwrite). The multi-chunk stream ciphertexts are binary attachments in `test/vectors/stream.v1/`, checked by their hash.
- Proved the guards:
  - Removing the `final !== last` check makes "final chunk dropped" and "no FINAL tag" fail. An early `FINAL` is still caught by the done-state check.
  - Removing the explicit X25519 list check makes the 14 low-order seal cases fail. libsodium throws an untyped error instead of `MALFORMED_RECORD`.
  - Non-canonical `S` and small-order `R` are also refused by libsodium 1.0.22 itself. Our explicit checks are defence in depth, and `isCanonicalScalar` is tested on its own.
- Follow-up: there is no streaming *encryption* in v1. A record must be stored before or with its parts (§7.1), and the manifest needs each part's hash first.

### Phase 2 (done)
- §8 clarified: the envelope (`v`, `suite`, `type`) is checked first, then version dispatch, then the shape for that version.
- Spec choices made while coding:
  - Optional fields described as "present only for" (`deviceId`, `kdf`) or "optional" (`continuitySignature`) are **absent** when unset, never `null`. `wrappedPreviousKey` is `null` for version 1, as written.
  - A record's `type` that differs from the one asked for is `MALFORMED_RECORD`.
  - A manifest that decrypts but breaks the §4.7 rules is `MALFORMED_RECORD`, since only a member could have written it.
- `team-key.v1.json` already holds the chain, owner-rule and grant-opening cases, frozen now; their replay arrives with the team session (Phase 5).
- Proved the guards: removing `checkOwners` makes the unsorted and duplicate owner cases fail; removing the item context check makes the three context cases fail.
