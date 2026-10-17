# Integration

> Status: draft. Follows protocol v1.

## Role

Answers: **how does an integration implement the four interfaces and the server rules, in any backend, and where does its own content pipeline plug in?**

The library calls the outside world only through `RecordStore`, `OprfService`, `LocalKeyStore` and `Clock` (protocol §12). This page turns the [server contract](scope.md#server-contract) and protocol §11 into a checklist for a backend in any language. The testing kit's `MemoryRecordStore` (D-24) applies every rule below and is the reference when in doubt; `test/unit/memory-store.test.ts` lists the cases a server must pass.

## Audience

Backend engineers implementing the server side; integrators writing the client adapters.

## RecordStore: the key store

`RecordStore` holds key records only (D-25). Content (item parts, submissions) is the integration's: see [Content](#content).

### Storage keys

Each record is stored under its identity (§11). A natural key, in identity order:

| Record | Key |
| --- | --- |
| `account-key-wrap` | account, account key version, method, `deviceId` (device wraps only) |
| `member-keys` | team, account, member keys version |
| `member-keys-wrap` | account, team, member keys version, account key version |
| `team-state` | account, team |
| `team-key-version` | team, version |
| `grant` | team, account, member keys version, team key version |
| `item` | team, item |
| `inbox` | team, inbox |
| `invite` | team, invite |

Store the record's JSON as the library sent it. Refuse a record whose identity fields differ from the key it is written under.

### Reads

- `get` returns the stored JSON or `null`.
- `list` supports the queries of protocol §12, results in identity order (versions ascending).
- Private records (`account-key-wrap`, `member-keys-wrap`, `team-state`) are served only to their account (rule 1). Everything else is readable by the team's members. A shared item's `item` record must also reach the people who open its link: through the key store, or through the integration's own content API, as it prefers (§7.3).

### Writes

`commit(ops)` is one transaction: every operation applies, or none (rule 5). In a database, a transactional write of all the operations, with conditions:

| Operation | Condition (refuse with a conflict otherwise) |
| --- | --- |
| `create` | No live record under that key (write-once, rule 3) |
| `create` of `team-key-version` | Version = current + 1 (§11). Accept records up to 384 KiB: the roster of a team of up to 1,000 members (D-34); DynamoDB's 400 KB item limit fits |
| `create` of `grant`, `item`, `inbox`, `invite` | `teamKeyVersion` = the current version, counting a version created in the same batch (rule 6) |
| `compare-and-set` | The stored `revision` equals `expectedRevision` (`null`: no record), and the new one is that plus 1 (rule 4) |
| `delete` | A soft delete: stop serving, keep for the restore window (rule 7, TH-36) |
| `set-account-key-version` | The current version equals `expected`; then stop serving every wrap of the old version (rule 7) |

The client reports a refused condition by throwing the library's `StoreConflictError`. Anything else it throws becomes `STORE_ERROR`. Defence in depth (rule 8): also check that the signer and owners of a new team key version hold the matching role in your product.

## Content

The library produces content and takes it back; the integration stores and serves it (protocol §7):

- **Creating an item:** start a draft, add each part (buffered or as chunks) and store each ciphertext with your own upload pipeline, then seal the draft with the item's id: that stores the `item` record in the key store. Your server can assign the id after the first part is encrypted (D-26).
- **Submissions:** the same draft flow on the sender's side; sealing returns the `submission` record, which you store with its parts.
- **Reading:** open the record, then give each part's ciphertext when it is needed, buffered or streamed.
- **Recommended rules for your content storage:** write-once parts and submissions; an item isn't shown until its `item` record exists; parts of drafts never sealed are deleted after a while (they open with no key).
- **File checks and deduplication** (type, size, content sniffing) run on the plaintext before encryption, in your code. To send your server a reference for a part, use `partRef`, never a plain hash of the content (D-28, TH-40).

## Invites and team administration

- **Invite links are join proofs** (D-32). Deliver them, but never show them back in your own UI, log them, or keep them in a stored outbox (TH-43). Delete an `invite` record when the invite expires or is withdrawn.
- **`autoApproveInvites`** lets owners' `reconcile` admit joiners proven by an invite. Leave it off unless you trust your server and mail delivery with joins: whoever saw the link can make the proof.
- **Run `reconcile` at every owner session** with the accounts your product considers members (§6.9). It rotates out removed accounts and approves re-keys proven by the recovery phrase; it never widens access otherwise (SP-22). Show its `needsHuman` list in your admin screens, with `overview()` for the details.
- **Lost device or leaked credential:** offer `secureAccount` (D-36), and end the account's other sign-in sessions.

## Key custody across contexts

If the vault and team sessions run in different contexts (D-29), carry the transfer request and the transfer over your own channel, and decide which context may receive which team, for example from the requesting page's origin and the signed-in session. The library seals and opens; it never chooses who may ask (§3.8).

## OprfService

The server side of PIN hardening (§5.1, SP-08):

- **One key per account:** `DeriveKeyPair(seed, info)` of RFC 9497 (ristretto255-SHA512, OPRF mode), with `info = enc(string label("pin-oprf"), u32 oprfKeyId, accountId)` (protocol §1 encoding). Keep `seed` secret, outside the database that stores the wraps.
- **Evaluate:** `BlindEvaluate(skS, blindedElement)`; return the 32-byte evaluated element.
- **One total budget per account,** across `unlock` and `enroll` (rule 2). A refused evaluation is reported with `RateLimitedError`; it should not consume budget.
- **Key replacement:** `currentKeyId` returns the id new wraps use. Keep evaluating with a retired id for a transition period: the library upgrades PIN wraps on the next unlock (§5.4).
- `pin-key.v1.json` holds the RFC 9497 vectors and a full PIN key derivation to check an implementation against.

## LocalKeyStore and Clock

- In browsers, use `createIndexedDbLocalKeyStore()` from `crypto-convoy/browser` (§3.7). Elsewhere, keep the device key in the platform's secure storage, and make every value that can't be read back an error, never an empty result.
- `Clock.now()` returns Unix seconds. Timestamps are informative only (TH-35).

## A server written without libsodium

Servers verify signatures only as defence in depth, but should do it exactly as clients do (§2):

- **Ed25519:** apply the strict checks of §2 before verifying. Go's `crypto/ed25519` accepts some signatures libsodium refuses; add the `S < L` check, the public key check (a canonical point of the prime-order subgroup, not of small order) and the small-order list for `R`.
- **X25519:** refuse the public keys in the low-order list of §2.
- **Base64url:** no padding, no other alphabet, no non-zero trailing bits.
- Replay `team-key.v1.json` (signatures, record hashes, chain cases) and `link.v1.json` to check these rules.

## Vectors to replay

| File | For |
| --- | --- |
| `canonical.v1.json`, `link.v1.json` | Encodings |
| `invite.v1.json` | Invite records and proofs, if the server checks them |
| `team-key.v1.json` | Signature checks and chain rules, if the server checks them |
| `pin-key.v1.json` | The OPRF evaluation |
| `wrap.v1.json`, `seal.v1.json`, `stream.v1.json`, `item.v1.json`, `submission.v1.json`, `recovery-key.v1.json` | Clients in other languages |
