# 002 — Doconvoy fit review (read-only)

> Input for the spec change that follows plan 001. Product-specific, so it lives here, not in `docs/`.

## Ground rules this review applies

1. **The key store is crypto-convoy's.** Account wraps, member keys, the team key chain, grants, team state, and each resource's key record (item, inbox). That is `RecordStore` and the server contract.
2. **Content is doconvoy's.** Payloads, attachments and submissions, and their storage, upload sessions, PoW, view limits, finalize, file checks (magic bytes, type, size) and dedup.
3. **Doconvoy's creation and reveal pipelines keep their order.** The library fits around them.

Team = workspace (tenant). Account = user.

## Flow by flow

| Doconvoy flow (today) | Library call (new) | Fit |
| --- | --- | --- |
| **Secret creation**: key generated, value encrypted, then `createSecret` → ID, then attachments uploaded one by one (`upload_secret_attachment`), then `createShareableKey` (resource blob, e2ee store), then `finalize_secret_setup` | `beginItem()`, `addPart(value)` → ciphertext; `createSecret` (unchanged) → ID; `addPart(file)` → ciphertext (or chunks) → upload (unchanged); `seal(secretId)` writes the item record to the key store, in place of `createShareableKey`; finalize (unchanged) | Fits **if** part associated data doesn't bind the id (G1) |
| **Request creation**: `createRequest` → ID, then the receivable key pair (resource blob `secret.request`), then finalize, then the link with the public key | `team.createInbox(requestId)` → link key, after the ID | Fits as is |
| **Intake** (handoff, anonymous sender): value sealed, `receive_secret` → ID and upload session, PoW, attachments uploaded, `finalizeSecretSetup` | `beginSubmission(linkKey, teamId, inboxId)`, `addPart(value)` → ciphertext in `receive_secret`; `addPart(file)` → upload; `seal(submissionId)` → envelope sent in finalize | Fits with G1 and G2; the envelope moves from `receive_secret` to finalize (G3) |
| **Member reveals a submission** (`use-reveal-one`): reveal endpoint → sealed payload + attachment URLs + encrypted names; opened with the receivable key pair; attachments decrypted on demand by the viewer and export | `team.openSubmission(requestId, envelope)` → opened handle with each part's `meta`; `opened.part(i, bytes)` per attachment, on demand | Fits; the raw content key no longer reaches UI code (G5) |
| **Creator reveals a share link** (`reveal-secret-link`): fetch resource blob, open with team key, put key in `#fragment` | `team.shareLinkKey(secretId)` | Fits |
| **Link holder views** (handoff `use-reveal-secret-pipeline`): `v_reveal_secret` → payload + attachment URLs; key from fragment | `openSharedItem(linkKey, itemRecord)` → opened handle; parts on demand | Needs the **item record** (manifest) on this path (G4) |
| **Export** (`features/Export`): fetch → decrypt → yield, one attachment at a time, with the raw key | Same generator over `opened.part(i, bytes)` | Fits; the key leaves the export module (G5) |
| **Access status** (`getTeamAccessStatus`, sticky notice, create gate): `ready` / `syncing` / `pending` / `needs_setup` / `unverified` | `vault.status()` and `team.state`, plus member status for owners (G6) | Mostly there; the owner view is missing |
| **Owner completes a member's access** (team page: accept join, backfill history, warnings when the member never set up, or the backfill failed) | `team.memberStatuses(ids)` → per-member state; `team.grant(id, mkv)`. No backfill: the chain gives history (D-07) | Fits, simpler; needs G6 |
| **Rotation after removal** (`rotate-team-key`, active member ids, `rejected` list) | `team.rotate({ keep: activeIds })`; `needsRotation(activeIds)` | Fits; "rejected" becomes members not granted at the current version |
| **Ownership transfer** (handover signed by the owner) | `team.setOwners([...], { keep })` | Fits; the role mapping is a decision (D2) |
| **Key bridge**: page sends an ephemeral public key; the bridge unlocks, derives the workspace root and returns it sealed; PIN, recovery and setup run in the bridge | Vault in the bridge; team session in the page. **No library API to move one team's keys between contexts** | Gap (G7) |
| **Server**: e2ee routes (backup, PIN evaluate, member, invite, resource, identity, authority, trust, session) | One key-store API over `RecordStore` + `OprfService`; `resource` → `item` / `inbox` records; identity, authority and trust → `member-keys`, `team-key-version`, `team-state` | Planned rewrite (Go), no surprise |
| **Ciphertext size check** (`MaxStreamCiphertextBytes`) | Same layout: 24-byte header, 4 MiB chunks, 17 bytes each, at least one chunk | Matches exactly |

## Gaps

**Library changes** (spec first):

- **G1. Part associated data can't bind the resource id.** Both creation pipelines encrypt the value before the server returns the ID. Proposal: a part's associated data becomes `enc(label, u32 index)`. The item binding moves to the per-item random key, plus the manifest hashes, plus the id bound in the record (`wrappedItemKey` / envelope). SP-03 is reworded to match; `item.v1` and `submission.v1` are regenerated (pre-release).
- **G2. `submissionId` is supplied by the app**, like `itemId`, and bound only at `seal`.
- **G4. The link holder needs the item record.** Library side: `openSharedItem(linkKey, itemRecord)` takes it as input; where it comes from is the integration's choice (G4 below).
- **G5. Reading is "open, then parts on demand"**: `openItem` / `openSubmission` / `openSharedItem` return a handle with `meta` per part and `part(i, bytes | stream)`. No raw key leaves the library.
- **G6. Setup and access checks with warnings.** One status API the app can render:
  - `vault.status()`: `not-set-up` | `locked` | `unlocked`, and whether this device is registered.
  - `team.state` (exists): `not-joined` | `pending` | `ready` | `unverified`.
  - `team.memberStatuses(accountIds)` for owners. Per account: `no-keys` (hasn't set up or joined: "ask them to complete setup"), `awaiting-approval` (keys published, no current grant: "complete their access"), `approved`, `outdated` (granted an older version only), `rekey-awaiting-approval` (newer keys published, with continuity `routine` / `unproven`).
  - `team.warnings()`: single owner (D-06), a granted account not in the active list (`needsRotation`), an interrupted rotation (`completeRotation` needed), and members awaiting approval.
- **G7. Moving one team's keys across contexts** (D-03 promises it, the API lacks it):
  - Page: `createKeyReceiver()` → public key.
  - Bridge: `vault.exportTeamKeys(teamId, receiverPublicKey)` → sealed, opaque.
  - Page: `openTeamSession({ store, localKeys, clock, settings }, sealed, receiver)`.
  - Create, join, re-key and leave run in the bridge (the vault). The library supplies the sealing, so the app never sees a raw bundle (D-15).
- **G8. `partRef(bytes)`:** a keyed reference per item (or per submission) to replace `ClientRefHash`.
- **G9. Content out of `RecordStore`** (agreed earlier): parts and submission envelopes leave the ports and the server contract. The item and inbox records stay.

**Doconvoy changes:**

- **G3.** Intake: the sealed envelope (content key + manifest) is sent at finalize instead of in `receive_secret`. The value's ciphertext stays in `receive_secret`.
- **G4.** `v_reveal_secret` (and the member reveal) returns the item record next to the payload. It's a monolith, so the secret app can read the key store server-side; or the handoff page gets anonymous read access to that one record.
- **Uploads.** One HTTP body per attachment. Browsers can't stream request bodies without `duplex: "half"` (Chrome only), so "flat memory" uploads need a chunked or multipart upload API. With today's limits (25 MB per file), one-file-at-a-time buffering is fine. The library supports both: `addPart(bytes)` → ciphertext, and `addPart(stream)` → chunks.
- **Attachment id:** `ClientRefHash` → `partRef` (G8). `EncryptedName` → part `meta`; the server list keeps only refs, sizes and types.
- **Features stop handling keys:** `acquireTeamKey`, `useShareableKey`, `useReceivableKeyPair`, `encryptPayload`, `decryptBlobToFile` and `contentKeyB64` in UI code all go. That's every feature listed above.
- **Data:** D-01. Migrate or reset existing encrypted data.

## Decisions needed

- **D1:** accept G1 (associated data = label + index).
- **D2:** role mapping. Is only the workspace owner a crypto owner, or also admins who can approve members (`canAcceptJoinTeam`)? Any crypto owner can grant and rotate (D-06).
- **D3:** G4 on the server: serve the item record through the secret reveal endpoints, or anonymous key-store access.

## Status after plan 003

- **Resolved in the library:**
  - G1 (index-only parts, D-26) and G2 (`submissionId` from the app).
  - G4 (the item record is an input of `openSharedItem`; the route is the app's).
  - G5 (open, then parts on demand) and G6 (`vault.status`, `memberStatuses`, `warnings`).
  - G7 (sealed transfer, D-29), G8 (`partRef`, D-28) and G9 (key store only, D-25).
- **Doconvoy-side items unchanged** (for the integration plan): the intake envelope moves to finalize, the reveal route for the item record, `ClientRefHash` becomes `partRef`, file names move to `meta`, features stop handling keys, and the data migration or reset.
- **D2 (crypto owners):** supported by the library through `setOwners`. The mapping to product roles is doconvoy's.

