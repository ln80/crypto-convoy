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
| `item` | team, item |
| `inbox` | team, inbox |

Store the record's JSON as the library sent it. Refuse a record whose identity fields differ from the key it is written under. A key identifies the **live** record: removed and replaced records move to an archive (see [Archived records](#archived-records)).

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
| `create` of `item`, `inbox` | `teamKeyVersion` = the current version, counting a version created in the same batch (rule 6) |
| `compare-and-set` | The stored `revision` equals `expectedRevision` (`null`: no record), and the new one is that plus 1 (rule 4) |
| `replace` (`account-key-wrap` only) | A live record exists under the key; archive it, then store the new one as live (D-39) |
| `delete` | Archive the live record: stop serving it, keep it for the restore window (rule 7, TH-36) |
| `set-account-key-version` | The current version equals `expected`; then stop serving every wrap of the old version (rule 7) |

Each operation in a batch names a different key: a batch never touches one key twice.

The client reports a refused condition by throwing the library's `StoreConflictError`. Anything else it throws becomes `STORE_ERROR`. Defence in depth (rule 8): also check that the signer of a new team key version is the caller and holds the matching role in your product. Don't check the owners it lists: a co-owner demoted in your product stays listed until an owner change, and refusing would block every rotation, `reconcile` included.

### Archived records

Rule 7 keeps every removed or replaced wrap for a restore window (TH-36, D-39). Each identity has at most one live record and any number of archived ones.

- **Relational database:** an `archived_at` column, and a unique index on the identity over live rows only (a partial index in Postgres).
- **DynamoDB:** the live item under its identity, with a generation counter `gen`. An archived record is a separate item (for example partition `archive#<accountId>`, sort key `<identity>#<gen>`) whose TTL is the archive time plus the restore window, so expiry needs no job.
  - `replace`: read the live item, then one transaction: put the archive item, and put the new live item with `gen + 1`, on condition that `gen` is unchanged.
  - `delete`: the same, deleting the live item instead.
  - Retiring an account key version: serve wraps only at the current version (a read filter), so the switch writes one item. Set the TTL on the old version's items afterwards, best effort.
- **Restoring** is your support process, not a route: list the archived generations of an identity, pick the one from before the incident, archive the live record and make the chosen one live, in one transaction. Never drop the live record: a mistaken restore must be reversible.

### Sizing

What the expensive writes cost, to set product limits against (teams per account, members per team):

| Write | Size |
| --- | --- |
| Account key rotation (one atomic batch, §5.7) | one `member-keys-wrap` per team the account is in, plus 2–3 wraps and the version switch. The vault keeps one bundle per team once re-keys are approved (§6.8 step 4) |
| `secureAccount` (§5.11) | that rotation, then one 2-record write per team |
| Team key version record (§4.5) | about 360 bytes per roster entry: 36 KB for 100 members, 384 KiB at most. One per join, re-key and removal (D-37) |
| Opening a team | the version records since its anchor, and every published `member-keys` record of the team |

For DynamoDB, a rotation must fit `TransactWriteItems` (100 items): cap the teams per account well below that.

### Leaving, removal and account deletion

- **Removal by the product:** a removed member can't read the chain any more, so it can't run `leaveTeam`. Your server deletes that account's `member-keys-wrap` and `team-state` records for the team; owners' next `reconcile` rotates the member out (§6.9).
- **Deleting an account** is your server's job, not one transaction: delete its records for each team as above, then archive its `account-key-wrap` records for the restore window (a session thief could otherwise delete the account, TH-36) and purge them after it. **Never delete records the team shares** (`member-keys`, `team-key-version`, `item`, `inbox`): other members verify old owners' signatures against published `member-keys` records.
- **The last owner:** refuse to remove or delete an account that is the only owner in the newest team key version (`LAST_OWNER`, TH-18). The product's owner role may change before the chain's owner list does (D-30): check the list in the record.

## Content

The library produces content and takes it back; the integration stores and serves it (protocol §7):

- **Creating an item:** start a draft, add each part (buffered or as chunks) and store each ciphertext with your own upload pipeline, then seal the draft with the item's id: that stores the `item` record in the key store. Your server can assign the id after the first part is encrypted (D-26).
- **Submissions:** the same draft flow on the sender's side; sealing returns the `submission` record, which you store with its parts.
- **Reading:** open the record, then give each part's ciphertext when it is needed, buffered or streamed.
- **Recommended rules for your content storage:** write-once parts and submissions; an item isn't shown until its `item` record exists; parts of drafts never sealed are deleted after a while (they open with no key).
- **File checks and deduplication** (type, size, content sniffing) run on the plaintext before encryption, in your code. To send your server a reference for a part, use `partRef`, never a plain hash of the content (D-28, TH-40).

## Invites and team administration

- **Invite links carry the team's anchor** (`team.inviteAnchor()`), so a joiner can't be shown a forged team (§6.4). They hold no secret: approving a joiner is an owner's decision, checked out of band (AS-06).
- **Every access change is one version record** (D-37): accept records up to 384 KiB, and expect one per join, re-key and removal.
- **Run `reconcile` at every owner session** with the accounts your product considers members (§6.9). It rotates out removed accounts and approves re-keys proven by the recovery phrase; it never widens access otherwise (SP-22). Show its `needsHuman` list in your admin screens, with `overview()` for the details.
- **Lost device or leaked credential:** offer `secureAccount` (D-36), and end the account's other sign-in sessions.

## Key custody across contexts

If the vault and team sessions run in different contexts (D-29), carry the transfer request and the transfer over your own channel, and decide which context may receive which team, for example from the requesting page's origin and the signed-in session. The library seals and opens; it never chooses who may ask (§3.8). On a joiner's first open, pass the invite link's anchor to the receiver (`openTeam(ports, transfer, { anchor })`), as you would to `vault.openTeam` in one context (§6.4).

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
| `team-key.v1.json` | Signature checks and chain rules, if the server checks them |
| `pin-key.v1.json` | The OPRF evaluation |
| `wrap.v1.json`, `seal.v1.json`, `stream.v1.json`, `item.v1.json`, `submission.v1.json`, `recovery-key.v1.json` | Clients in other languages |
