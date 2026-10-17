# Design decisions

> Status: draft, under review.

## Role

Answers: **why is the design the way it is?**

One entry per decision: the problem, the choice, what was rejected, and the consequence. The other documents say *what* holds; this one keeps the *why*, so a settled question isn't reopened without new information.

Each entry has a stable id `D-01`, `D-02`, and so on, and a status:

- **Accepted** — settled.
- **Proposed** — the current direction. The documents describe it, but it can still change.
- **Deferred** — not in v1. Can be added later as a new record version.
- **Superseded by D-NN** — kept for history.

Several entries come from lessons learned in an earlier implementation of the same model.

---

## D-01: A new protocol, with no legacy formats

Status: Accepted.

Problem: an earlier implementation carries formats and rules that exist only for history.

Decision: crypto-convoy starts at protocol version 1 with no compatibility with earlier formats. Moving existing data is the integration's job (see [scope.md](scope.md)).

Consequence: simpler readers and specs. An application that already stores data in another format needs a migration or a reset before adopting the library.

## D-02: The library is framework- and product-agnostic

Status: Accepted.

Problem: the earlier implementation mixes protocol logic with a UI framework, an iframe key bridge, HTTP tokens and product roles.

Decision: the core has no UI framework, no network code and no product vocabulary. Any bridge between contexts (iframe, `postMessage`, origin checks) is integration code. A UI binding, if any, is a separate package.

Rejected: shipping a bridge in the library. Its security depends on the product's domain layout, which the library can't know.

## D-03: Key custody is split in the API

Status: Accepted.

Problem: removing the bridge from the library must not lose the property it provided: a team's page never holds the account key.

Decision: the API has an account vault and a team session (see [Key custody](scope.md#key-custody)). The vault hands a team session only that team's keys.

Consequence: integrations choose how isolated the two are; the property is stated and testable either way. Moving one team's keys to another context uses the sealed transfer of D-29.

## D-04: Wrap keys that need their own lifetime; derive only short-lived sub-keys

Status: Accepted.

Problem: in the earlier implementation, every team-level key is derived from one account master key. A derived key can't change without its parent changing, so the master key can never be rotated without changing the user's identity in every team.

Decision: keys that may need to change on their own (the account key, member keys, team keys, item keys) are random and stored wrapped (encrypted) by the keys that protect them. Derivation is kept for values computed from a secret the user types (PIN, recovery phrase).

Consequence: one stored record per wrap. In exchange, rotating a key means re-wrapping a few small records instead of resetting the account.

## D-05: One key per device

Status: Accepted.

Problem: in the earlier implementation, each device stores the PIN-derived key. A stolen device can open the backup forever, even after a rotation, and one device can't be revoked on its own.

Decision: each device has its own random key, and the server stores the account key wrapped for each device. Revoking a device deletes its wrap, so the device can't unlock again. What revocation does *not* do is set by D-21.

Consequence: one record per device, and one device can be revoked without affecting the others.

## D-06: Co-owners with equal powers, no quorum

Status: Accepted.

Problem: a team with a single owner freezes if that owner loses their PIN and recovery phrase, and onboarding waits on that one person.

Decision: a team has a list of owners, carried by each team key version (D-19). Any owner can admit members, rotate the team key, and add or remove owners. Every change is signed by an owner of the previous version.

Rejected: a quorum (k of n owners) for owner-list changes. It adds ceremony and a second rule set, and protects little: a stolen owner key can already admit a fake member and read future items, with or without a quorum.

Consequence: losing one owner's credentials no longer freezes a team with two or more owners. One stolen owner key still allows a takeover, the same risk as with a single owner. Owner-list changes are reported on every member's client: that's detection, not prevention, since the attacker can act before anyone looks (TH-17). A team with one owner is allowed, with a warning. A quorum can be added later as an optional field.

## D-07: Earlier team key versions are reached through a chain

Status: Accepted.

Problem: in the earlier implementation, a new member receives every earlier team key version one by one ("backfill"), and a cleanup job deletes versions no longer needed. Both are a large share of the lifecycle code.

Decision: each new team key version stores the previous version encrypted under itself. A member granted the current version can open every earlier one by walking back. New members receive one grant.

Consequence: no backfill and no cleanup job. Access to history is all or nothing: a member who receives the current version can open all earlier ones. A member re-admitted after removal can also open the versions created while they were away. Removed members still can't open versions created after their removal.

## D-08: The browser storage adapter ships with the library, outside the core

Status: Accepted.

Decision: `crypto-convoy/browser` implements device storage with IndexedDB and a non-extractable WebCrypto key. The core depends only on the `LocalKeyStore` interface. The stored format, and why it uses WebCrypto's AES-GCM rather than the suite, is in protocol §3.7.

## D-09: Items are signed by their author

Status: Deferred. Not in v1; authorship stays an accepted risk (TH-15).

Problem: in the earlier implementation, item integrity uses a MAC keyed from the team key, so any member can forge who created an item.

Decision: each member has a signing key. Items carry the author's signature, checked against the member keys owners approved.

Consequence: authorship is provable within the team. One extra signature per item. People outside the team (link shares) can't check it; they only get integrity.

## D-10: Every unlock method is a symmetric wrap; rotation asks for the credentials again

Status: Accepted.

Problem: rotating the account key must re-wrap it for every unlock method. With public-key wraps (seal the new key to each method's public key), rotation would need no PIN or phrase. But anyone can seal to a public key, including the server: it could hand a device or a recovering user a forged account key, and then read every key the user wraps under it.

Decision: the PIN, the recovery phrase and each device wrap the account key with a symmetric key that only that method's holder can compute. Rotation needs the user present: they enter the PIN, and either enter the recovery phrase or receive a new one. Other registered devices stop working and ask for the PIN once to register again.

Rejected: public-key wraps for unlock methods, for the forgery reason above.

Consequence: the server can't forge an account key for any method. Rotation is a deliberate, interactive security action, not a background task.

## D-11: Key fingerprints for out-of-band verification

Status: Deferred. Not in v1: trust on first use at first contact is an accepted trade-off (TH-04).

Problem: the first time a client sees a team's owners, or a member's keys, it has nothing to check them against (trust on first use).

Decision: the library computes a short fingerprint of each member's keys. Users can compare fingerprints through another channel and mark a key as verified; a verified key that changes is reported, never replaced silently.

Consequence: in v1, first contact stays trust on first use with no verification option (TH-04). Every later change is still checked against what the client first accepted.

## D-12: Names describe what a thing is: item, inbox, link share

Status: Accepted.

Problem: the earlier implementation named its records "shareable" and "receivable", after what can be done with them. In this model, any item can be shared by link, so "shareable" stops being a kind of record.

Decision: an **item** is content with its own key. A **link share** is the act of giving that key to someone outside the team. An **inbox** is a key pair that accepts outside submissions. The integration maps these to its own vocabulary.

## D-13: Every owner change is a new team key version

Status: Accepted.

Problem: a removed owner keeps every team key up to the removal and could keep signing grants for the current version. If removing the owner and rotating the key were two separate writes, a removal that landed without its rotation would leave the current key grantable by the removed owner.

Decision: adding, removing or replacing an owner is a rotation whose new version carries the new owner list (D-19). The version record and the signer's grant are written in one atomic batch, so an owner change is never half applied. A removed owner isn't in the owner list of any later version, so their signatures are refused for all of them. Members whose newest grant came from the removed owner are listed as a warning for the rotating owner; it isn't a guarantee, since a later grant by another owner hides the origin.

Consequence: one rotation per owner change. Owner changes are rare, so the cost is small. Removal of a regular member doesn't force a rotation; the integration decides when.

## D-14: Inbox submissions always use a content key

Status: Accepted.

Problem: the earlier implementation has two submission formats: text sealed directly to the inbox key, or a content key sealed to the inbox key with the content encrypted separately. Readers dispatch between them.

Decision: one format. A submission always seals a fresh content key; every part (text, files) is encrypted with it.

Consequence: one reader path; large submissions and small ones work the same way.

## D-15: The library owns content encryption; the application never handles raw keys

Status: Accepted.

Problem: in the earlier implementation, application code generated content keys, called low-level encrypt and decrypt functions, and passed keys around as strings. Each call site chose its own context, and most chose none, which let a server swap parts of an item.

Decision: the public API offers high-level operations only: create and open items, create inboxes, submit and open submissions, and encode and decode link keys. Keys stay inside the library as opaque values. Low-level primitives aren't exported.

Consequence: one correct way to encrypt content; misuse such as missing context or a reused key can't happen at call sites. Flows the API doesn't cover need a library change rather than ad hoc crypto in the application.

## D-16: Items carry a manifest; what parts mean is up to the integration

Status: Accepted.

Problem: an item made of several parts (a text, files, file names) needs the server unable to swap, drop or reorder them. What each part means (a text format, a file type, a form field) is product logic.

Decision: the `item` record lists the item's parts (id, size, ciphertext hash) and authenticates that list with the wrapped key. Each part may carry a small opaque `meta` value defined by the integration; the library encrypts and authenticates it with the part and never reads it. Submissions do the same inside their sealed envelope.

Consequence: the library guarantees the integrity of an item as a whole, without knowing the product. Metadata the integration keeps outside `meta` (for example in clear on its server) is neither encrypted nor authenticated by the library.

## D-17: PIN hashing cost is an integration setting, never a server input

Status: Accepted.

Problem: Argon2id at 256 MiB of memory may be too heavy for some devices, and a later change of cost must not need a new protocol version. A server, though, must never be able to lower the cost: a weak setting makes PIN guessing cheap.

Decision: the integration sets two values: the cost used when writing a PIN wrap (default: 3 passes, 256 MiB) and the minimum cost accepted when reading one (default: the same). Each PIN wrap records the cost it was made with, so readers follow the record within those bounds. Values that come from the server are only ever checked against the bounds, never used to change them. The library has a **hard floor** of 2 passes and 64 MiB (libsodium's interactive level): no setting can go below it, so a misconfigured minimum can't make a weak wrap acceptable.

Consequence: an integration can change the cost for its users without a protocol change, as long as it keeps its own minimum consistent, and never below the floor. Wraps written with a different cost stay readable. After a successful PIN unlock, a wrap made with a cost below the current writer setting, or under a retired server OPRF key, is re-wrapped automatically (upgrade on unlock), so no user needs recovery because a setting changed.

## D-18: Fixed size limits for records

Status: Accepted.

Problem: the server is untrusted, so a record could claim millions of parts or megabytes of metadata to crash or freeze a client. Readers need fixed limits to validate records before any crypto (SP-18). The limits must be part of the protocol, not per-integration settings, or one client could write data another refuses to read.

Decision: at most 128 parts per item or submission, 4096 bytes of `meta` per part, 64 owners per team key version, and 128 bytes per id. An integration may enforce lower limits in its own interface.

Consequence: raising a limit later means a new record version.

## D-19: The owner list lives in the team key chain

Status: Accepted.

Problem: a first draft kept two chains: an owner history, and the team key versions. Each owner history entry declared "the current team key version" as a number, and the rule for which versions an owner could sign was computed from those numbers. A stolen owner key could write a huge number and make every later removal ineffective. Keeping two chains consistent is where that bug came from.

Decision: one chain. Each team key version record lists the owners for that version and the hash of the previous record, and is signed by an owner of the previous version. A grant for version n is valid only if its signer is in the owner list of version n. Version numbers are consecutive and write-once, so nobody chooses them.

Rejected: keeping two chains and adding rules to keep them in step (an atomic batch, a check that the declared number matches a real version, a "greater than or equal" rule). It works, but it keeps the duplication that caused the bug.

Consequence: one record type fewer; the owner rule is a direct lookup; a member's anchor is a single (version, hash) pair. Every owner change creates a team key version (D-13).

## D-20: Inboxes keep their key pair in v1

Status: Accepted.

Problem: an inbox's private key is wrapped by the team key version current when it was created, and its public key is in the link. A member removed later can still open submissions sent to it, if they also get the ciphertexts (a database leak, an insider, a server authorization bug). Rotating the team key doesn't help: they may have copied the inbox private key itself. Only a new key pair helps, and a new key pair means a new link.

Decision: in v1, inboxes keep their key pair. The exposure is accepted and stated plainly (TH-30). The library offers "replace inbox"; the integration decides when to use it, for example for sensitive requests or links not yet sent.

Rejected for v1:
- Replacing every open inbox on each member removal: every outstanding link would stop working.
- Signed rotating inbox keys (below): sound, but more moving parts in v1.

Recorded for a later version (signed rotating inbox keys, the pattern known as signed prekeys):
- Each inbox has a stable signing key, random and wrapped by the team key. Its public half goes in the link.
- The inbox encryption key for team key version v is derived from that version's team key and the inbox id. No private key is stored; members recompute it.
- For each version, a small public record holds the inbox's encryption public key, signed by the inbox signing key.
- The sender checks the signature with the key from the link and seals to the latest signed key.
- After a rotation, the new key of each open inbox is published as part of the rotation. The step is idempotent because the key is derived.
- Result: links keep working, and a removed member plus a database leak can't read new submissions. They would also need the server to serve a fake key signed with the old inbox signing key.

## D-21: Revoking a device stops it from unlocking; nothing more

Status: Accepted.

Problem: a device that was used by an attacker while unlocked may have given them the account key and the member keys of every team it opened. Revoking the device and rotating the account key doesn't change member keys, and every new team key version is sealed to those same keys. Fully evicting such an attacker needs a re-key in every affected team, each approved by an owner.

Decision: the guarantee of revocation is that the device can't unlock the account again (SP-10). The full remedy, when a device may have been misused, is a documented procedure built from existing operations: rotate the account key (SP-11), then re-key in each affected team (SP-12). The library offers both; the integration decides whether to guide users through them.

Rejected: making the full remedy part of revocation. It's heavy (an owner approval per team), and it's only needed in the serious case.

Consequence: revocation is cheap and immediate. The protocol's claims stay true: revocation alone doesn't evict someone who already copied keys (TH-10).

## D-22: A share link carries the item key; protecting the link is the integration's job

Status: Accepted.

Problem: a share link is a bearer capability: whoever holds the full URL can decrypt the item. The cryptography is sound (a random 256-bit key with authenticated encryption, carried in the URL fragment, which browsers don't send to servers). The risks are where the link travels: email security services that rewrite links (fragment included), browser history and sync, extensions, page scripts that read the address, and a server that sends the link itself.

Decision: in v1, the link carries the item key, as encoded by `encodeLinkKey`. The integration protects the link with a short checklist ([scope.md](scope.md#what-the-integration-does)). The browser adapter offers `takeLinkKey()`, which reads the key from the fragment, validates it, and removes it from the address bar and history.

Rejected for v1, recorded for later:
- **Per-share keys:** the link carries a share secret that unwraps the item key, so each link is a separate, deletable record and the item key never leaves the team.
- **Split keys:** the share key is derived from the link secret and a second factor sent through another channel, either a random code or a passcode (hardened with Argon2id or the PIN OPRF). A leaked link alone then decrypts nothing.

Consequence: no new record or mechanism in v1. Leaked links are covered by the integration's controls (expiry, view limits, server-side checks) and accepted in TH-23.

## D-23: Expected failures are thrown as typed errors

Status: Accepted.

Problem: an operation can fail in expected ways (wrong PIN, not granted, stale version). Returning a result object forces every caller to unwrap values, and differs from how asynchronous TypeScript APIs usually behave; throwing untyped errors makes failures hard to tell apart.

Decision: every public operation is asynchronous and throws one error class, `ConvoyError`, with a `code` from protocol §9 and, for `TRUST_FAILURE`, a `reason`. Messages are fixed per code and never carry keys, plaintext or record contents. Internal parsers and checks stop at the first failure and raise the same error.

Rejected: a `Result<T, E>` return type for expected failures. It's more explicit, but verbose at every call, and a forgotten check silently drops the error.

Consequence: integrations branch on `error.code`. Errors from the integration's own interfaces are wrapped (`STORE_ERROR`) unless they are the library's signals (`StoreConflictError`, `RateLimitedError`).

## D-24: The library publishes a testing kit

Status: Accepted.

Problem: integrations need an honest server to test against, and a server implementation (in any language) needs a precise statement of the server contract. Both otherwise get written from prose, and drift.

Decision: `crypto-convoy/testing` ships an in-memory `RecordStore` that applies every rule of protocol §11, a fake OPRF server (RFC 9497, one key and one total budget per account), an in-memory `LocalKeyStore` and a fixed clock. The tamper hooks used by the library's own adversarial tests stay outside the package.

Rejected: keeping the fakes in the test folder only. Each integration would write its own, with weaker rules.

Consequence: one more public entry point, kept out of the core (the core never imports it). Its store is a reference for the server contract, not a production store: nothing is persisted.


## D-25: The library manages keys; the integration stores content

Status: Accepted.

Problem: the first implementation stored and fetched item parts and submissions through `RecordStore`, beside the key records. That pulls the integration's content storage (upload sessions, view limits, quotas, cleanup) into the library's server contract, and mixes two backends an integration usually keeps apart.

Decision: the server contract and `RecordStore` cover **key records** only: account key wraps, member keys and their wraps, team states, the team key chain, grants, and each resource's key record (`item`, `inbox`). Item parts, submission envelopes and submission parts are **content**: the library produces and consumes them, and the integration stores and serves them as it wants (protocol §7, §11).

Rejected: one store for everything. Simpler to describe, but it forces the integration's content pipeline into the library's shape.

Consequence: the library's guarantees on content don't depend on where it's stored, since every part is authenticated and listed by its key record (SP-03). The integration should still keep content write-once and not present an item before its key record exists.

## D-26: A part binds its index; the record binds the ids

Status: Accepted.

Problem: integrations often encrypt the first part (a text, a form) before their server assigns the resource its id, then upload files, then finalize. Binding `itemId` (or `submissionId`) into every part's associated data forces either client-chosen ids or a different pipeline.

Decision: a part's associated data is its label and its index only (protocol §4.8, §4.10). The part is bound to its item through the item's own random key and the manifest, which lists each part's index, size and ciphertext hash; the id is bound in the key record (`wrappedItemKey`, the sealed envelope), written last. The integration chooses `submissionId`, as it already chooses `itemId`.

Rejected: ids in every part's associated data. It adds nothing once each item has its own key and a manifest, and it dictates the integration's ordering.

Consequence: moving a part to another item fails (another key), and moving it within an item fails (index and manifest). A record moved to another id fails to open.

## D-27: Items and submissions are drafts until sealed

Status: Accepted.

Problem: a part's ciphertext hash is known only once the part is encrypted, the manifest needs every hash, and a write-once record can't be completed later. Large files must not be held in memory.

Decision: creating an item or a submission is a draft. The draft holds the content key, encrypts parts one at a time (buffered, or as a stream of chunks for the integration to upload), and is **sealed** last with the id: sealing writes the manifest and the key record. Parts are uploaded before the record; the record makes them openable.

Rejected: plaintext hashes in the manifest, which would allow the record first: decrypting before detecting a substituted part, and reading each file twice. Splitting the record into a key record and a later manifest record: a new record type for the same result.

Consequence: an interrupted draft leaves parts no key opens; cleaning them up is the integration's job. Reading is per part, on demand: open the record, then decrypt each part when needed.

## D-28: Part references are keyed per item

Status: Accepted.

Problem: integrations need a stable reference for a part (deduplication, attachment ids). A plain hash of the content, sent to the server, lets anyone who holds a candidate file check whether it was stored (confirmation of file) and links equal files across items.

Decision: the library offers `partRef(content)`: a keyed BLAKE2b-256 of the content, under a key derived from the item's (or submission's) content key (protocol §3.9). The integration may send it to its server.

Rejected: a reference keyed by the team key, which allows deduplication across items but shows the server which items share a file.

Consequence: a reference reveals nothing without the item key and differs across items (SP-21). Equal content within one item gives equal references, which is what deduplication needs.

## D-29: Team keys move between contexts only sealed to a receiver

Status: Accepted.

Problem: the account vault and team work may run in different contexts (for example an iframe on another origin and the product's page). A team session there needs that team's member keys, and only those. A bridge between contexts depends on the product's domain layout, which the library can't know (D-02).

Decision: the library offers a sealed transfer (protocol §3.8). The receiving context creates an ephemeral receiver; the vault exports one team's member keys sealed to it, bound to the account and the team; only that receiver opens them, once. The integration carries the opaque values and decides which context may receive which team. A single-context integration opens the team directly in the vault.

Rejected: shipping a bridge (D-02). Sending the account key or a root that derives every team's keys: a compromise of one page would reach every team.

Consequence: the account key never leaves the vault; one team's keys reach only a context the integration authorized (SP-02).

## D-30: Owners are a cryptographic role, separate from product roles

Status: Accepted.

Problem: products have their own roles (owner, admin) with their own meaning. Tying team key ownership to one product role forces every product to change its roles, or forces the library to know them.

Decision: the owners of each team key version are an explicit list in the chain (D-19). The integration decides which accounts hold the cryptographic owner role, and applies changes with an owner change (§6.7). A server may check, as defence in depth, that listed owners hold the product capability the integration maps to it (server contract, rule 8).

Consequence: a change of product owner needs an owner change in the chain only if the cryptographic owners change.
