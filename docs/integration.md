# Integration

> Status: draft. Follows protocol v1.

## Role

Answers: **how does an integration implement the four interfaces and the server rules, in any backend, and where does its own content pipeline plug in?**

The library calls the outside world only through `RecordStore`, `OprfService`, `LocalKeyStore` and `Clock` (protocol §12). This page turns the [server contract](scope.md#server-contract) and protocol §11 into a checklist for a backend in any language. The testing kit's `MemoryRecordStore` (D-24) applies every rule below and is the reference when in doubt; `test/unit/memory-store.test.ts` lists the cases a server must pass.

## Audience

Backend engineers implementing the server side; integrators writing the client adapters.

## Duties

What an integration must do for the library's guarantees to hold, in one list; the sections below say how. The server's own rules are the [server contract](scope.md#server-contract) (rules 1–8), applied record by record in protocol §11. Reviews count these rows to measure what a change costs integrators.

| Duty | Why |
| --- | --- |
| Run the server contract: authenticate callers, rate-limit PIN evaluations with one total budget, keep write-once records, archive private ones, refuse public deletes, create wraps only with their keys or in a rotation | Server contract rules 1–8, §11, D-58 |
| Ship the OPRF public keys in client code, never from an API response; replace a key in two releases; start POPRF key ids above old ones | AS-02, D-53, TH-51 |
| Keep the vault and the credential prompts in the most isolated context you have | TH-20 |
| In a split layout, carry transfer requests and transfers on a channel your server can't write, and decide which context may receive which team | D-29, TH-39, TH-49 |
| Deliver invite anchors, and owners' repair anchors, outside your server, or have the owner and the joiner compare the invite's anchor code before approving; re-join an existing member only with an owner's anchor | TH-04, D-54, D-59 |
| Let members send share and inbox links themselves: a link your server sends gives it the key the link carries | SP-01 Limit, TH-21, TH-23 |
| Run `reconcile` at every owner session with the accounts your product considers members | D-31, TH-14 |
| Show `ownerChanges` and `memberChanges` in every context that opens a team, background ones included; keep a persistent anchor store per context to get reports from its second open on | D-44, D-57, TH-17 |
| Approve joins and unproven re-keys only after an out-of-band check; pass the overview's handles unchanged | AS-06, D-55 |
| Ask for a current credential before a PIN change or a phrase replacement | D-41 |
| End the account's other sign-in sessions before `secureAccount`, pass it `teamIds` (the teams your product says the user is in), retry the teams it reports failed before your next `reconcile` as an owner, and reset the account's other devices afterwards | D-43, D-60, TH-47, SP-19 |
| Keep a support restore process, authenticated by means other than the session or a credential it would bring back | D-42, TH-45, TH-48 |
| Store the vault's own anchor per team in its `DeviceKeyStore` half; make unreadable local values errors, never empty | D-54, §3.7 |
| Build an inbox link once, from the `linkKey` returned; never rebuild it from the stored record | TH-50 |
| Send your server `partRef` values, never plain hashes of content | D-28, TH-40 |
| When your product removes a member, archive its private records for the team; never remove the last owner in the newest version | §6.9, TH-18 |

## RecordStore: the key store

`RecordStore` holds key records only (D-25). Content (item parts, submissions) is the integration's: see [Content](#content).

### Storage keys

Each record is stored under its identity (§11). A natural key, in identity order:

| Record | Key |
| --- | --- |
| `account-key-wrap` | account, account key version, method, `deviceId` (device wraps only) |
| `member-keys` | team, account, member keys version |
| `member-keys-wrap` | account, team, member keys version, account key version |
| `team-key-version` | team, version |
| `item` | team, item |
| `inbox` | team, inbox |

Store the record's JSON as the library sent it. Refuse a record whose identity fields differ from the key it is written under. A key identifies the **live** record: removed and replaced records move to an archive (see [Archived records](#archived-records)).

### Reads

- `get` returns the stored JSON or `null`.
- `list` supports the queries of protocol §12, results in identity order (versions ascending).
- Private records (`account-key-wrap`, `member-keys-wrap`) are served only to their account (rule 1). Everything else is readable by the team's members. A shared item's `item` record must also reach the people who open its link: through the key store, or through the integration's own content API, as it prefers (§7.3).

### Writes

`commit(ops)` is one transaction: every operation applies, or none (rule 5). In a database, a transactional write of all the operations, with conditions:

| Operation | Condition (refuse with a conflict otherwise) |
| --- | --- |
| `create` | No live record under that key (write-once, rule 3) |
| `create` of `team-key-version` | Version = current + 1 (§11), and the caller is the signer and holds the owner capability (rule 8). A version that fails its checks stops the team for good, since its identity is never written again (TH-25): give the owner capability only to the chain's owners, and verify the signature against the previous version's owners if your server can. Accept records up to 384 KiB: the roster of a team of up to 1,000 members (D-34); DynamoDB's 400 KB item limit fits |
| `create` of `member-keys` | The caller is the record's account, and `memberKeysVersion` is that account's newest for the team plus 1, or 1 (rule 8, D-43) |
| `create` of `member-keys-wrap` | In the same batch as its `member-keys` record, or in a batch that switches the account key version, at the new version (D-58) |
| `create` of `account-key-wrap` | At the account's current key version, or in a batch that switches it, at the new version (D-58) |
| `create` of `item`, `inbox` | `teamKeyVersion` = the current version, counting a version created in the same batch (rule 6). Enforce it, and write-once, in the server itself: they are the only barrier against a former member who kept an old team key (TH-50) |
| `replace` (`account-key-wrap`, `member-keys-wrap`) | A live record exists under the key; archive it, then store the new one as live (D-39, D-52) |
| `delete` | Only the caller's own private records (`account-key-wrap`, `member-keys-wrap`); refuse it for any other record (rule 3). Archive the live record: stop serving it, keep it for the restore window (rule 7, TH-36) |
| `set-account-key-version` | The current version equals `expected`; then stop serving every record of the old version, keeping it archived (rule 7, D-42) |

Each operation in a batch names a different key: a batch never touches one key twice.

The client reports a refused condition by throwing the library's `StoreConflictError`. Anything else it throws becomes `STORE_ERROR`. Defence in depth (rule 8): also check that the signer of a new team key version is the caller and holds the matching role in your product. Don't check the owners it lists: a co-owner demoted in your product stays listed until an owner change, and refusing would block every rotation, `reconcile` included.

### Archived records

Rule 7 keeps every removed or replaced private record (account key wraps, member keys wraps) for a restore window (TH-36, TH-46, D-39, D-42). Each identity has at most one live record and any number of archived ones.

- **Relational database:** an `archived_at` column, and a unique index on the identity over live rows only (a partial index in Postgres).
- **DynamoDB:** the live item under its identity, with a generation counter `gen`. An archived record is a separate item (for example partition `archive#<accountId>`, sort key `<identity>#<gen>`) whose TTL is the archive time plus the restore window, so expiry needs no job.
  - `replace`: read the live item, then one transaction: put the archive item, and put the new live item with `gen + 1`, on condition that `gen` is unchanged.
  - `delete`: the same, deleting the live item instead.
  - Retiring an account key version: serve wraps only at the current version (a read filter), so the switch writes one item. Set the TTL on the old version's items afterwards, best effort.
- **Archiving a live private record** is a support action too: a member keys wrap planted with a stolen account key, which opens with keys its published record doesn't match, fails its team until support archives it (TH-20, D-58). It is never a route.
- **Restoring** is your support process, not a route. A restore brings back whatever the restored records open, a replaced credential or a revoked device included, so authenticate the request by means other than the session or a credential it would bring back (TH-48): list the archived generations of an identity, pick the one from before the incident, archive the live record and make the chosen one live, in one transaction. Never drop the live record: a mistaken restore must be reversible.
- **Restoring an account key version** (D-42), after a takeover with a rotation: set the account's current version back to the one from before, archive the records of later versions, and serve that version's archived records again. With the read filter above, this is the version pointer plus the later versions' records. Tell the user that devices which saw the later version must be reset and registered again, and that teams which approved the thief's keys need an owner to approve the user's re-key. End the account's sessions, then have the user secure the account with a new PIN, and a new phrase if the thief knew the restored one (D-45).

### Sizing

What the expensive writes cost, to set product limits against (teams per account, members per team):

| Write | Size |
| --- | --- |
| Account key rotation (one atomic batch, §5.7) | one `member-keys-wrap` per team the account is in, plus 2–3 wraps and the version switch. The vault keeps one bundle per team once re-keys are approved (§6.8 step 4) |
| `secureAccount` (§5.11) | that rotation, then, per team, the version records since its floor and a 2-record write (D-54) |
| Team key version record (§4.5) | about 360 bytes per roster entry: 36 KB for 100 members, 384 KiB at most. One per join, re-key and removal (D-37) |
| Opening a team | the version records since the lowest of its floor and its local anchor, and every published `member-keys` record of the team; in the vault, a `replace` of one member keys wrap when the chain moved past the floor (D-52) |
| Exporting a team to another context (§3.8) | the same download as opening it, a possible `replace` of one member keys wrap, and one local write of the vault's anchor (D-54) |
| Joining a team (§6.4) | the version records from the invite anchor, or from version 1 without one, and every published `member-keys` record of the team (D-50) |

For DynamoDB, a rotation must fit `TransactWriteItems` (100 items): cap the teams per account well below that.

### Leaving, removal and account deletion

- **Removal by the product:** a removed member can't read the chain any more, so it can't run `leaveTeam`. Your server removes (archives, rule 7) that account's `member-keys-wrap` records for the team; owners' next `reconcile` rotates the member out (§6.9).
- **Inboxes after a removal:** an inbox keeps its key pair (D-20), so a removed member who gets new submissions from storage still opens them (TH-30). If former members must not read new submissions, replace the team's inboxes (`replaceInbox`) after the rotation and send the new links.
- **Deleting an account** is your server's job, not one transaction: delete its records for each team as above, then archive its `account-key-wrap` records for the restore window (a session thief could otherwise delete the account, TH-36) and purge them after it. **Never delete records the team shares** (`member-keys`, `team-key-version`, `item`, `inbox`): other members verify old owners' signatures against published `member-keys` records.
- **Owners leaving:** refuse to remove or delete an account that is a listed owner in the newest team key version, as `leaveTeam` does (`LAST_OWNER`, TH-18, D-65): an owner steps down first, by `setOwners` without them, then leaves; the only owner can't. Drop an account that left from the active list, so the next `reconcile` takes it out of the roster and it can't be named owner again while holding nothing. The product's owner role may change before the chain's owner list does (D-30): check the list in the record.

## Content

The library produces content and takes it back; the integration stores and serves it (protocol §7):

- **Creating an item:** start a draft, add each part (buffered or as chunks) and store each ciphertext with your own upload pipeline, then seal the draft with the item's id: that stores the `item` record in the key store. Your server can assign the id after the first part is encrypted (D-26).
- **Submissions:** the same draft flow on the sender's side; sealing returns the `submission` record, which you store with its parts.
- **Inbox links:** build an inbox's link once, from the `linkKey` that `createInbox` or `replaceInbox` returns, and store the link. Never rebuild it from the stored `inbox` record: a former member with the server can replace that record with a key pair of their own (TH-50).
- **Reading:** open the record, then give each part's ciphertext when it is needed, buffered or streamed.
- **Recommended rules for your content storage:** write-once parts and submissions; an item isn't shown until its `item` record exists; parts of drafts never sealed are deleted after a while (they open with no key).
- **File checks and deduplication** (type, size, content sniffing) run on the plaintext before encryption, in your code. To send your server a reference for a part, use `partRef`, never a plain hash of the content (D-28, TH-40).

## Invites and team administration

- **Invite links carry the team's anchor** (`team.inviteAnchor()`), so a joiner can't be shown a forged team, when the link reaches them outside your server (§6.4, TH-04). They hold no secret: approving a joiner is an owner's decision, checked out of band (AS-06).
- **When your server delivers the link** (an invitation email it sends, for example), the anchor protects the joiner's later devices, not the join: your server could put a forged team's anchor in the link. Close the join with an **anchor code**, compared during the out-of-band check the approval already needs (AS-06):
  - after the join, the joiner's client and the owner's each show the code of their own `team.inviteAnchor()`: the first 10 bytes of SHA-256 over the anchor string's UTF-8, in base32 (RFC 4648, no padding), 16 characters shown in four groups of four;
  - the joiner reads theirs to the owner by voice, video or another channel the server doesn't carry; equal codes mean both hold the same chain up to the same version. If a rotation happened in between, both refresh and compare again;
  - the owner approves only after equal codes, and the joiner writes nothing to the team before them (show it as unverified until then).

  80 bits: forging a team whose newest anchor gives the same code takes the server about 2^80 tries. The same comparison checks any member's view of the team, at any time.
- **Every access change is one version record** (D-37): accept records up to 384 KiB, and expect one per join, re-key and removal.
- **Run `reconcile` at every owner session** with the accounts your product considers members (§6.9). It rotates out removed accounts and approves re-keys proven by the recovery phrase; it never widens access otherwise (SP-22). Show its `needsHuman` list in your admin screens, with `overview()` for the details.
- **Lost device or leaked credential:** end the account's other sign-in sessions, then offer `secureAccount` (D-36, D-43), with a new phrase when the phrase may have leaked (D-45). Ending them first keeps a session thief from publishing keys over its re-keys, and from keeping the user's keys unapprovable (TH-47). Recommend a new phrase and a different PIN every time, and afterwards, once each team has been opened or re-keyed on the securing device, clear the account's local state on the user's other devices: the retired account key version still opens with the old credentials wherever it is served again (SP-19). A team reported `failed` is retried with `rekey(teamId, { phrase, oldPhrase })`: the current phrase, and the one it replaced, which keeps the re-key proven (D-49, D-56); one whose floor didn't check out also takes an anchor an owner sends out of band (`anchor`, D-54). Carry that anchor the way you carry invite links, outside your server, and only from an owner the user recognises: it replaces every root the account holds for the team, so a relayed, stale or forged one roots the account's devices on the chain it names (TH-04). The vault's `recovery-key-mismatch` warning means someone with the account key rewrote the recovery wrap: offer `secureAccount`.
- **The vault's own anchor:** the vault keeps an anchor per team in its `DeviceKeyStore` half (`getVaultAnchor`, `setVaultAnchor`, `deleteVaultAnchor`, D-54). Store it next to the device key, in the vault's context.
- **Credential changes need a credential** (D-41, D-61): ask for the current PIN or the recovery phrase in your PIN-change and phrase-replacement screens, and the PIN in the first recovery setup; an open vault alone isn't enough. An open vault together with the account's session can still replace them (TH-45): the user finds themselves locked out, and your support process restores the account key version and the recovery wrap from before (SP-26). Keep that process ready, and authenticate it by means other than the session.
- **Approve joins in batches.** `owner.approve(handles)` takes every pending account in one rotation (§6.5). Pass the handles the overview returned: they name the keys hash reviewed (D-55); a handle built by hand needs it too. Each approval is a new version carrying the whole roster, about 360 bytes per member, and opening an old item walks back through every version above it (§6.2). For a team's initial setup, invite everyone, let them join, then approve all accounts the overview shows as `awaiting-approval` in one call: 50 members approved one by one make 50 versions, about 460 KB of chain; approved together, one version of about 18 KB. Approving a join stays a human decision: `reconcile` never does it (D-31).

## Devices

- **Names and dates are yours.** `listDevices()` returns `{ deviceId, current }` for every device wrap, and `status().deviceId` names this device (§5.5). After a registration (`unlockWithPin`, `recover`, `setup`), send your server this device's `deviceId` with a label: one the user typed, or one built from the user agent ("Chrome on macOS"). Your server can also record when it stored the device's wrap and when the device last fetched it.
- **Display only.** A label is never a security input: the server controls which wraps it lists, and anyone holding the account key could name a device anything. Decide "this device" with `current`, never with a label.
- **Support restores** (D-42) are easier with these labels: list the archived device wraps with their names, creation and last-use dates.

## Key custody across contexts

If the vault and team sessions run in different contexts (D-29), carry the transfer request and the transfer over your own channel, one your server can't write (`postMessage` with origin checks, a `MessageChannel`; never relayed through the server: a receiver doesn't know who sealed a transfer, TH-49), and decide which context may receive which team, for example from the requesting page's origin and the signed-in session. The library seals and opens; it never chooses who may ask (§3.8). The invite link's anchor goes to `vault.joinTeam(teamId, { anchor })` once; the transfer carries the floor, set there and moved forward by the vault, to every context (§6.4, D-52). After a repair with an owner's anchor (§6.8), clear the team's anchor in each receiving context's `LocalKeyStore` (`deleteAnchor`) before opening a new transfer there: a context that opened the forged chain keeps it as a root (D-54).

## OprfService

The server side of PIN hardening (§5.1, SP-08):

- **One key pair per key id:** RFC 9497 POPRF (ristretto255-SHA512, partially oblivious mode), `DeriveKeyPair` or `GenerateKeyPair` per `oprfKeyId`. Start POPRF key ids above any id your service used before: a wrap made under an older, non-verifiable key would otherwise be evaluated under the new one and answer `WRONG_CREDENTIAL`, spending budget, instead of `UNSUPPORTED_VERSION` (D-53). Keep the secret keys outside the database that stores the wraps (TH-09), and never derive or export a per-account tweaked key: anyone who gets one recovers the key of every account.
- **Evaluate:** `BlindEvaluate(skS, blindedElement, info)` with `info = enc(string label("pin-oprf"), accountId)` (protocol §1 encoding), built from the account you charge, never from the request; return the 32-byte evaluated element and the 64-byte proof. Draw the proof nonce from a CSPRNG: a repeated or biased nonce reveals the key.
- **One total budget per account,** across `unlock` and `enroll` (rule 2). A refused evaluation is reported with `RateLimitedError`; it should not consume budget. Every account's evaluations hit one key per key id, and anyone can open accounts: rotate key ids periodically, or cap evaluations per key id.
- **Public keys in your client code:** pass `settings.oprf = { keys: { [oprfKeyId]: publicKey }, writeKeyId }` to `createVault`, from code your API servers don't serve (AS-02), never from an API response. Replace a key in two releases: first ship its public key in `keys`, so the clients that will see it can read its wraps, then make it `writeKeyId`. Keep evaluating a retired key while wraps made under it may remain; the library upgrades them on the next unlock (§5.4).
- `pin-key.v1.json` holds the RFC 9497 POPRF vectors and a full PIN key derivation to check an implementation against. Its proofs use fixed nonces: test values only.

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
