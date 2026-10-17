# 003 — Keys vs content, drafts, transfers, status (implements D-25 … D-30)


## Context

Plan 001 implemented protocol v1. The doconvoy fit review (`.agents/plans/002-doconvoy-fit-review.md`) found the library taking on app work and missing what doconvoy's pipelines need. The spec change now in the working tree (`docs/`, uncommitted) settles it:

- **D-25: keys vs content.** `RecordStore` and the server contract keep key records only, `item` and `inbox` included. Parts and submissions are content the app stores.
- **D-26: parts bind only their index.** Ids are bound in the record; `submissionId` is chosen by the app.
- **D-27: drafts.** Parts are encrypted first, the record is sealed last, and parts are opened on demand.
- **D-28: keyed part references** (`partRef`).
- **D-29: sealed team-key transfer** between contexts. The library offers it; the app owns the bridge.
- **D-30: crypto owners** are separate from product roles.
- **Status and warnings API** for setup and for confirming member access (§12, SP-15).

The goal: the code matches the spec exactly, every gate stays green, and doconvoy's secret, request and intake pipelines map onto the library with no change of order.

## Execution mode

As in plan 001:
- **Autopilot:** phase after phase. Stop only for real blockers, such as a spec gap that would change a guarantee.
- **One commit per step**, with no `Co-Authored-By` line.
- **Lean code docs:** short TSDoc with the §, the property and the error codes it throws; comments only for *why*.
- **Gate before each commit:** `typecheck`, `npm test`, `check:spec` when `docs/` changed, `test:fuzz` when a parser changed, `build` + `test:package` when exports changed.
- **Prove the guard** for each new security check: remove the check, watch its test fail, restore it.

---

## Phase A — Commit the spec, keep the gate green

**A1.** Commit `docs/` as reviewed: `docs(spec): keys vs content, drafts, transfers, part references (D-25…D-30)`.
- `test/unit/traceability.test.ts`: add a `PENDING` list holding exactly the new verification files (`key-transfer.test.ts`, `part-ref.test.ts`). They count as `todo` until written; the list is removed in phase G.
- Update the property count: 18 → 19 non-deferred.

**A2.** Save this plan as `.agents/plans/003-keys-content-split.plan.md` and commit it.

## Phase B — Building blocks, records and vectors (§3.8, §3.9, §4.8, §4.10)

**B1. Labels and suite.**
- Add `part-ref` and `team-keys-transfer` to `src/encoding/labels.ts`; the label test syncs with the §1 table.
- `Suite.hasher(key?)`: a keyed incremental BLAKE2b, through `crypto_generichash_init` with a key. Update `docs/libsodium-map.md`.

**B2. Streaming encryption.** In `src/blocks/stream.ts`, add `streamEncryptChunks(…, source)`: an async generator that holds one chunk back, to know which is `FINAL`, and computes the ciphertext hash as it goes. Peak memory is one chunk. It produces the same layout as `streamEncrypt`; a property test checks both give equal sizes and valid streams.

**B3. Part context (D-26).**
- `src/records/item.ts` and `submission.ts`: the part context becomes `[u32(index)]`. The manifest and record bindings stay as they are.
- `parseSubmission`: `submissionId` is read as an id (`fields.id`), no longer as a random id.
- `createSubmission` takes the `submissionId` at seal time.

**B4. New modules.**
- **`src/records/transfer.ts`** (§3.8):
  - `encodeRequest` / `decodeRequest` (prefix `1`, not low order);
  - `sealTransfer(suite, receiverPublicKey, accountId, teamId, bundles)`: newest first, 1–64 bundles;
  - `openTransfer(suite, receiver, expected, transfer)`: prefix, open, order and sizes. The check against published keys is done by the caller.
- **`src/blocks/part-ref.ts`** (§3.9): `refKey(suite, contentKey)`, plus an incremental `partRef` over bytes or chunks.

**B5. Vectors.** Independent generators in `test/vectors/generate/`:
- Update `item.mjs` and `submission.mjs`, then regenerate with `VECTORS_OVERWRITE_UNRELEASED=1`. Add cases: a part moved to another item; an envelope for another id.
- New `transfer.mjs`: open, wrong receiver, other account or team, prefix `2`, low-order request, out-of-order bundles.
- New `part-ref.mjs`: an item key and a submission content key, empty and multi-chunk content.
- Replay them in `test/compatibility/`, and fuzz `decodeRequest` and `openTransfer` in `records.fuzz.test.ts`.

## Phase C — Ports and the testing kit (D-25, §12)

**C1. `src/ports.ts`.**
- Remove `PartKey`, `getPart`, `getPartStream` and `create-part`, and the `submission` record key. `RecordKey` keeps `item` and `inbox`.
- `LocalKeyStore` splits into `DeviceKeyStore` (device key, account key version) and `AnchorStore` (anchors); `LocalKeyStore = DeviceKeyStore & AnchorStore`.
- `callPort` is unchanged.

**C2. `src/testing/memory-record-store.ts`.**
- Drop the parts and submission rules.
- Keep `anonymous()` for reading an `item` record by link holders (one of the D3 routes).
- `test/unit/memory-store.test.ts`: drop the part cases.

**C3. `test/support/content-store.ts`:** a tiny map of parts and submissions, with tamper helpers (swap, drop, truncate, replace) standing in for the app's content backend. `TamperingStore` loses its part hooks.

## Phase D — Content API (§7, D-27)

**D1. `src/content/item-draft.ts`:** `ItemDraft`, created by `team.beginItem()`.
- `addPart(content: Uint8Array, { meta? }) → Uint8Array` (buffered), and `addPartStream(chunks: AsyncIterable<Uint8Array>, { meta? }) → AsyncIterable<Uint8Array>` (streamed).
- **Parts in order.** A new part is refused while a streamed one is unfinished, and every call is refused after `seal`. These are misuse errors, plain `Error`.
- `partRef(content | chunks) → string`.
- `seal(itemId)`:
  - checks the session is `ready`;
  - builds the record at the **current** version;
  - commits the `item` record to the key store, mapping a conflict to `STALE_VERSION`;
  - wipes the key.
- 1–128 parts, else `MALFORMED_RECORD`.

**D2. `src/content/opened.ts`:** `OpenedItem` and `OpenedSubmission`, holding the content key internally.
- `parts: { index, meta, size }[]`.
- `part(index, source)`, where `source` is bytes, an async iterable, or a fetcher `() => Promise<bytes | AsyncIterable>`. The buffered form refuses `size > maxBufferedSize` **before** calling the fetcher. A streamed form `partStream(index, source)` yields authenticated chunks.
- `close()` wipes the key.

**D3. Session and link-client changes.**
- **`TeamSession`:**
  - `beginItem()`;
  - `openItem(itemId)`: reads the record from the key store;
  - `openSubmission(inboxId, submissionRecord)`;
  - `createInbox` and `replaceInbox` return `{ linkKey }` only;
  - `shareLinkKey` is unchanged.
  - Removed: `createItem`, `openItemStream`, and the `content/items.ts` storage code.
- **`src/content/link-client.ts`:** no store.
  - `openSharedItem(linkKey, teamId, itemId, itemRecord) → OpenedItem`;
  - `beginSubmission(linkKey, teamId, inboxId) → SubmissionDraft`, whose `seal(submissionId)` returns the record JSON.
  - `createLinkClient({ clock?, settings? })`.

## Phase E — Vault custody and transfers (§3.8, §5.8, §5.9, D-29)

**E1. Vault options.** `deviceKeys: DeviceKeyStore`, with `anchors?: AnchorStore` needed only for `openTeam` in the same context.
- `createTeam`, `joinTeam` and `rekey` return `void` (§12); `openTeam` returns the session.
- `leaveTeam` verifies the chain in the vault with `verifyChain` (`src/team/chain.ts`) and the member-keys list, with no session. It deletes the local anchor if an `AnchorStore` was given.

**E2. Transfers.**
- `vault.exportTeamKeys(teamId, request) → string`. The vault opens the bundles with `openBundles` (`src/account/member-custody.ts`) and seals them with `sealTransfer`.
- `createTeamKeyReceiver(accountId, teamId) → { request, openTeam({ store, anchors, clock, settings }, transfer) }`, exported from `src/index.ts`. Opening once wipes the receiver; a second open is `DECRYPTION_FAILED`. Each bundle is checked against its published `member-keys` record (`key_mismatch`), then `TeamSession.open`.
- Vault operations take and return plain data only. A unit test structured-clones every vault result.

**E3. `vault.status()`.**
- `account`: `not-set-up` when the server has no account key version; `locked` / `unlocked`.
- `deviceRegistered`: a local device exists and its wrap is live at the current version.
- It never triggers an OPRF call.

## Phase F — Member statuses and warnings (§12, SP-15)

**F1. `team.memberStatuses(accountIds)`**, from published `member-keys` records and the grants of the current version:
- `no-keys`;
- `awaiting-approval`: keys, no current grant;
- `approved`;
- `outdated`: only grants of older versions;
- `rekey-awaiting-approval`: newer keys than the granted ones, with `continuity`.

It reuses `memberRequest`, `#currentGrants` and `#publishedKeys` (`src/team/session.ts`).

**F2. `team.warnings(activeAccountIds) → Warning[]`**, as typed codes the app renders:
- `single-owner`;
- `members-awaiting-approval` (ids);
- `rotation-needed` (granted accounts not active);
- `rotation-interrupted` (kept accounts with a grant for n−1 and none for n).

Each warning carries the action that clears it (`grant`, `rotate`, `completeRotation`, `setOwners`).

## Phase G — Tests, rewired and new

**G1. Rewire** to drafts, opened items and the content store:
- `ciphertext-tampering` (SP-03): add a part moved to another item, and a record served under another id;
- `inbox` (SP-14), `member-removal` (SP-06);
- `partial-decrypt` (SP-18): the fetcher is never called for an oversized part;
- `server-view` (SP-01): scan the key store dump and the content store;
- `team-smoke`, `public-api`, `scenario`.

**G2. New tests.**
- **`test/security/key-transfer.test.ts`** (SP-02, TH-39): wrong receiver, second open, other team or account, tampered transfer, no account key inside, a split layout end to end (vault context and page context with separate stores).
- **`test/security/part-ref.test.ts`** (SP-21, TH-40): different across items, equal within an item, matches no unkeyed hash, streamed equals buffered.
- **`change-visibility`** (SP-15): statuses and warnings follow each step:
  - joined → `awaiting-approval` → `approved`;
  - removal → `rotation-needed`;
  - interrupted rotation → `rotation-interrupted` → `completeRotation`;
  - single owner.
- **Memory:** a streamed 64 MiB part through `addPartStream` and `partStream` with peak heap growth below 3 chunks (`process.memoryUsage`, a coarse bound), in `test/properties`.

**G3.** Remove the traceability `PENDING` list; the test is strict again.

## Phase H — Browser adapter, docs and DX

- **H1. Browser adapter.** `createIndexedDbLocalKeyStore` already implements both halves; export the `DeviceKeyStore` and `AnchorStore` types. In a split layout each origin uses its own database. `takeLinkKey` is unchanged.
- **H2. README.** Rewrite the usage guide: drafts mirroring a create → upload → finalize pipeline, opened items with on-demand parts, link clients without a store, split layouts with receivers, status and warnings, `partRef`.
- **H3. `docs/integration.md`.** Already updated in the spec change; check it against the final API.
- **H4. `test/compatibility/scenario.test.ts`, rewritten as doconvoy's flows** with neutral names:
  - value encrypted before the "server id", files streamed, sealed at finalize;
  - an anonymous intake submission sealed at finalize;
  - per-part reveal, export by iterating parts;
  - a split vault and page with a receiver;
  - owner warnings throughout.
- **H5.** Update `test/package/smoke.mjs` for the new API.

## Phase I — Close

- **I1.** Full gate: `typecheck`, `npm test`, `test:fuzz`, `check:spec`, `build`, `test:package`.
- **I2.** Execution notes in the plan; update plan 002's gap list with what is resolved (G1–G9).

---

## Critical files

- **Change:** `src/ports.ts`, `src/blocks/stream.ts`, `src/records/{item,submission}.ts`, `src/team/session.ts`, `src/account/{vault,member-custody}.ts`, `src/content/*`, `src/testing/memory-record-store.ts`, `src/index.ts`.
- **New:** `src/records/transfer.ts`, `src/blocks/part-ref.ts`, `src/content/{item-draft,opened}.ts`.
- **Tests:** `test/support/{fake-store,content-store,teams,fixtures}.ts`, plus every security test named above.
- **Vector generators:** `test/vectors/generate/{item,submission,transfer,part-ref}.mjs`.

## Verification

- `npm run typecheck && npm test && npm run test:fuzz && npm run check:spec && npm run build && npm run test:package`, all green.
- Traceability is strict with 19 non-deferred properties; boundary, libsodium-map and public-api tests are green.
- 12 vector files are replayed; `item.v1` and `submission.v1` are regenerated once and frozen.
- The scenario test runs doconvoy-shaped pipelines through public entry points only:
  - create → upload → finalize, for both secrets and intake;
  - per-part reveal;
  - a split layout with a receiver;
  - status and warnings at each step.
- Prove-the-guard results recorded for the transfer checks (receiver binding, single use, context), the index binding, `partRef` keying and the buffered pre-download refusal.

## Execution notes

### Phase A (done)
- Spec committed (`98204c6`). The two new labels were added to `labels.ts` in the same commit, so the label test kept matching §1.

### Phase B (done)
- Parts bind only their index. `sealItem` and `sealSubmission` seal drafts; `createItem` and `createSubmission` remain as all-at-once helpers for tests.
- `submissionId` is read as an id.
- `item.v1` and `submission.v1` regenerated, with a foreign-part case and an envelope served under another id. `transfer.v1` and `part-ref.v1` are new.
- A property test checks that streaming encryption gives the buffered layout for any slicing. Slices are at least 50 KB; 1-byte slices of 8 MiB took minutes.

### Phases C–F (one commit)
- They change the ports, content, session and vault together; splitting them would have left the build broken in between.
- **Deviations from the plan, all reflected in §12:**
  - **Invite anchor:** `vault.openTeam(teamId, { anchor })` takes it, not `joinTeam`, because joining no longer opens a session.
  - **`openSubmission(inboxId, submissionId, record)`** takes the expected id, as §3.1 requires: ids come from the caller.
  - **One more warning code,** `rekeys-awaiting-approval`, separate from `members-awaiting-approval`: they are cleared by different actions (rotate vs grant).
  - **Vault options:** `deviceKeys` plus optional `anchors`. Without `anchors`, `openTeam` throws a misuse error pointing to `exportTeamKeys`.
- `loadChain` (`src/team/load.ts`) is shared by sessions and the vault's `leaveTeam` check.
- Opening a team for the first time now reports the team's creation as an owner change (§6.1 at first contact). The test helper opens each joiner's session once.

### Phase G (done)
- **Memory:** 64 MiB streamed through a draft stays under 24 MiB of growth. The measurement needs forced collection; `execArgv: ["--expose-gc"]` is set for the properties project.
- **Proved the guards:**
  - Making `streamEncryptChunks` buffer the whole part fails the memory test.
  - Dropping the transfer context fails the "other team or account" test.
  - An unkeyed `partRefKey` fails the cross-item test.
  - Removing the pre-fetch size check fails the "fetcher never called" test.
  - Removing the receiver's `used` flag fails no test: the receiver's secret key is wiped after the first open, so a second open fails anyway. That's two layers of defence.

### Phases H–I (done)
- README usage guide rewritten. `docs/libsodium-map.md` updated for keyed incremental hashing.
- The scenario test runs the product-shaped pipelines through public entry points only. The package smoke test covers drafts, link clients and transfers.
- **Final gate:** typecheck, 613 tests, 33 fuzz properties, `check:spec`, build, package smoke test.

### Follow-ups
- **TeamSession size:** it is about 550 lines. Move statuses and warnings to `src/team/status.ts` if it grows further.
- **Draft persistence:** a draft lives in memory, so a page reload loses it and the parts already uploaded open with no key (D-27). Resumable uploads would need a protocol decision.
