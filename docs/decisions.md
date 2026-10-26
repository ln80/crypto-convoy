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

Decision: each device has its own random key, and the server stores the account key wrapped for each device. Revoking a device removes its wrap (the server stops serving it, D-39), so the device can't unlock again. What revocation does *not* do is set by D-21.

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

Decision: each new team key version stores the previous version encrypted under itself. A member given the current version can open every earlier one by walking back. New members receive one version, in its roster (D-37).

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

Decision: the PIN, the recovery phrase and each device wrap the account key with a symmetric key that only that method's holder can compute. Rotation needs the user present: they enter the recovery phrase, and optionally a new PIN (D-40, D-41). Other registered devices stop working and register again after a PIN or phrase unlock.

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

Decision: adding, removing or replacing an owner is a rotation whose new version carries the new owner list (D-19). The version record carries the new owner list and the roster of members receiving it (D-34), in one write, so an owner change is never half applied. A removed owner isn't in the owner list of any later version, so their signatures are refused for all of them. Members whose current access the removed owner signed are listed as a warning for the rotating owner; it isn't a guarantee, since access re-signed later by another owner hides the origin.

Consequence: one rotation per owner change. Owner changes are rare, so the cost is small. Every other access change is a rotation too (D-37).

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

Consequence: an integration can change the cost for its users without a protocol change, as long as it keeps its own minimum consistent, and never below the floor. Wraps written with a different cost stay readable. After a successful PIN unlock, a wrap made with a cost below the current writer setting, or under a key id other than the setting's `writeKeyId` (D-53), is re-wrapped automatically (upgrade on unlock), so no user needs recovery because a setting changed.

## D-18: Fixed size limits for records

Status: Accepted.

Problem: the server is untrusted, so a record could claim millions of parts or megabytes of metadata to crash or freeze a client. Readers need fixed limits to validate records before any crypto (SP-18). The limits must be part of the protocol, not per-integration settings, or one client could write data another refuses to read.

Decision: at most 128 parts per item or submission, 4096 bytes of `meta` per part, 64 owners per team key version, 1,000 accounts in a team key version's roster and 384 KiB of JSON per version record (D-34), and 128 bytes per id. An integration may enforce lower limits in its own interface.

Consequence: raising a limit later means a new record version.

## D-19: The owner list lives in the team key chain

Status: Accepted.

Problem: a first draft kept two chains: an owner history, and the team key versions. Each owner history entry declared "the current team key version" as a number, and the rule for which versions an owner could sign was computed from those numbers. A stolen owner key could write a huge number and make every later removal ineffective. Keeping two chains consistent is where that bug came from.

Decision: one chain. Each team key version record lists the owners for that version and the hash of the previous record, and is signed by an owner of the previous version. Who receives version n is its roster, signed with it (D-34, D-37). Version numbers are consecutive and write-once, so nobody chooses them.

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

Consequence: revocation is cheap and immediate. The protocol's claims stay true: revocation alone doesn't evict someone who already copied keys (TH-10). The full remedy is one vault operation, `secureAccount` (D-36), whose team re-keys owners approve without an out-of-band check (D-33).

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

Decision: `crypto-convoy/testing` ships an in-memory `RecordStore` that applies every rule of protocol §11, a fake OPRF server (RFC 9497 POPRF, one key pair per key id and one total budget per account, D-53), an in-memory `LocalKeyStore` and a fixed clock. The tamper hooks used by the library's own adversarial tests stay outside the package.

Rejected: keeping the fakes in the test folder only. Each integration would write its own, with weaker rules.

Consequence: one more public entry point, kept out of the core (the core never imports it). Its store is a reference for the server contract, not a production store: nothing is persisted.


## D-25: The library manages keys; the integration stores content

Status: Accepted.

Problem: the first implementation stored and fetched item parts and submissions through `RecordStore`, beside the key records. That pulls the integration's content storage (upload sessions, view limits, quotas, cleanup) into the library's server contract, and mixes two backends an integration usually keeps apart.

Decision: the server contract and `RecordStore` cover **key records** only: account key wraps, member keys and their wraps, team states, the team key chain, and each resource's key record (`item`, `inbox`). Item parts, submission envelopes and submission parts are **content**: the library produces and consumes them, and the integration stores and serves them as it wants (protocol §7, §11).

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

Consequence: the account key never leaves the vault; one team's keys reach only a context the integration authorized (SP-02). The transfer carries each bundle's anchor floor (D-48, D-50), so splitting contexts keeps the first-contact protection of an invite (TH-04, SP-07). The sender of a transfer isn't authenticated: whoever sees the request can seal keys to it, so the channel must be one the server can't write (TH-49).

## D-30: Owners are a cryptographic role, separate from product roles

Status: Accepted.

Problem: products have their own roles (owner, admin) with their own meaning. Tying team key ownership to one product role forces every product to change its roles, or forces the library to know them.

Decision: the owners of each team key version are an explicit list in the chain (D-19). The integration decides which accounts hold the cryptographic owner role, and applies changes with an owner change (§6.7). A server may check, as defence in depth, that the signer of a new version holds the product capability the integration maps to it; the owners a version lists aren't checked (server contract, rule 8).

Consequence: a change of product owner needs an owner change in the chain only if the cryptographic owners change.

## D-31: Owners run an autopilot that only narrows access

Status: Accepted.

Problem: owners must turn warnings into the right operation themselves: rotate after a removal, approve re-keys, admit members. Integrations get this wrong or skip it, and every step waits for an owner to act by hand.

Decision: an owner's session offers `reconcile(activeAccountIds)`, meant to run at every owner session. It does what needs no human judgement and reports the rest:
- rotates the team key without accounts that hold the current version but are no longer active;
- approves re-keys proven by the member's recovery key (D-33), for members who aren't owners;
- approves the calling owner's own re-key when its session holds those keys (D-47).

Everything else (first joins, members who held only an older version, unproven re-keys, other owners' re-keys, inactive owners) is returned as needing a human. **Automatic actions only reduce access; widening it needs a cryptographic proof or a human.** Owner operations live on a separate owner object, so code paths that aren't an owner's can't reach them. A dry run returns the plan without writing.

Rejected: giving the version again to accounts whose keys an owner approved in the past (`outdated`). The active list comes from the integration's server; a server listing a removed member as active would undo the removal.

Consequence: one call keeps a team in order. A server that lies about the active list can cut access (denial of service) and never add a reader, but it can keep one: a removed member it still lists as active keeps receiving new versions (SP-22 Limit, TH-14). Otherwise, removed members stop receiving new versions at the next owner session, not at an integration's discretion.

## D-32: Invite links carry a join proof

Status: Deferred. Not in v1: the design below is recorded for a later version (D-11 addresses the same identity problem). Invites in v1 carry only the team's anchor (§6.4).

Why deferred: when the integration's own server delivers the invite (the usual case), the proof shows only that the joiner held a link the server also saw, so it stays a hint; making it act alone (an `autoApproveInvites` flag) would hand admission to mail delivery. Its cost (a record type, a link format, three labels, single-use rules) outweighs that.

Problem: an owner confirming a join must check, out of band, that the published keys are the invitee's (AS-06). In practice owners click approve, so a session thief who publishes keys under the invitee's account first (TH-37) is admitted.

Decision: an owner creates an `invite` record holding a random join secret, wrapped under the current team key and signed by the owner. The invite link carries the anchor and the secret. The joiner's `member-keys` record carries a MAC (a keyed hash) of its keys under the secret. Owners see "joined with the invite" or "no proof". By default this is a hint and approval stays human; the integration may set `autoApproveInvites` for `reconcile` to admit proven joiners. Auto-approval holds once per invite and only for invites of the current team key version.

Rejected: always auto-approving. Invites are usually emailed by the integration's server, which then knows the secret and could admit keys of its own.

Consequence: a session thief without the invite link can't produce a proof. With `autoApproveInvites`, the integration trusts its server and its mail delivery for joins (TH-02, TH-04, TH-43).

## D-33: The recovery phrase is the account's offline root of trust

Status: Accepted.

Problem: replacing compromised member keys needs an owner to verify the request out of band in every team, because the old keys can't vouch for their replacement: the attacker may hold them (SP-12). After a misused device, that's one human check per team.

Decision: the recovery phrase also derives an Ed25519 **recovery signing key**. Its public key is in every `member-keys` record, so an owner's approval pins it with the keys. A re-key signed by the recovery key of the keys an account currently holds is **proven**: the phrase isn't stored anywhere, so a stolen device or session doesn't have it. `reconcile` approves proven re-keys of members automatically. An owner's re-key still needs a human approval, or the owner's own `reconcile` holding those keys (D-47), so a leaked phrase can't silently change the owner list. Replacing the phrase re-keys every team with the new recovery key: proven when the user still has the old phrase, a human approval otherwise.

Proofs are `recovery` or none: the continuity signature is gone (D-38).

Rejected:
- Continuity signatures by the old member keys as proof: the attacker holds them.
- Auto-approving owners' proven re-keys: a leaked owner phrase would become a silent takeover of the owner list.
- A separate per-account chain of identity keys: more records for the same effect in v1.

Consequence: the phrase becomes more powerful. A thief holding it can already open the account key; now they can also replace a member's keys in every team, racing the real user, and only a human ends the race (TH-41). Recovery must be set up before any team work (D-35).

## D-34: A team key version carries its roster

Status: Accepted.

Problem: a rotation wrote the version record with the signer's grant, then one grant per other member. Interrupted, it left members without the new version (`completeRotation`). Large teams didn't fit one database transaction. And what members held a version was only what the server chose to list, so hidden grants could suppress the "rotation needed" signal (TH-42).

Decision: each team key version record carries its **roster**: for every account that receives the version, its keys (as a hash) and the version sealed to them. The owner signs it with the record. A rotation is one record. At most 1,000 accounts per roster (D-18). Since D-37 the roster is the only way to hold a version.

Rejected: keeping the roster in a separate record committed with its hash. Smaller chain records, but one more record type and batch rule. Clients fetch the chain from their anchor (§6.1), so old rosters are downloaded only at first contact.

Consequence: no interrupted rotations and no resume operation; the server's "version with its signer's grant" batch rule goes. A record grows to about 360 bytes per member: about 360 KB at 1,000 members with 36-byte ids, under the 384 KiB cap per record that fits common database item limits (400 KB). Who held each version is signed chain data.

## D-35: Recovery is confirmed before team work

Status: Accepted.

Problem: a phrase shown once and never checked is the usual way an end-to-end encrypted account is lost. With D-33 it is also the only way to prove a re-key.

Decision: setting up recovery is two steps: the vault generates a phrase and keeps it in memory; the user enters it back, and only then is the recovery wrap stored. No recovery wrap at the current account key version means recovery isn't set up. Creating or joining a team requires it (`RECOVERY_NOT_SET_UP`). An account key rotation needs the phrase and keeps it (D-41), so recovery, once set up, stays set up.

Rejected: a "confirmed" flag on a stored wrap: a flag the server can't verify, and a phrase that already works before anyone saved it.

Consequence: an account is never in a team without a working phrase. The integration shows one more step at setup.

## D-36: Securing an account is one operation

Status: Accepted.

Problem: the remedy after a misused device or a leaked credential was a procedure of four steps across the vault and every team (D-21). Integrations would stop at revocation.

Decision: `vault.secureAccount({ phrase, newPin? })` rotates the account key, with a new PIN or none when the PIN budget is spent (D-40), which cuts every other device (D-10), then re-keys every team with a recovery signature (D-33), one team per write. It reports the teams re-keyed and those that failed, which the integration retries with `rekey(teamId, { phrase })`. Each team's owners approve the new keys at their next `reconcile` (D-31). When the phrase itself may be known to someone else, it also replaces the phrase in the same pass (D-45).

Rejected: one atomic batch for everything: it doesn't fit common database transaction limits. A stored resume marker: a retry per failed team is enough.

Consequence: the full remedy is one call plus the owners' routine `reconcile`. Until an owner of a team runs it, the copied keys still open what that team writes.

## D-37: Roster-only: every access change is a rotation

Status: Accepted.

Problem: D-34 kept grants for members admitted between rotations. That made two ways to hold a version: every reader, the owner overview and `reconcile` had to accept "roster or grant"; the server could hide a grant from other owners (TH-42); and a removed owner could still sign grants of versions they owned (TH-33).

Decision: there is no grant record. Approving a joiner, approving a re-key and removing a member are all rotations: a new team key version whose roster lists exactly the accounts that receive it (§6.6). Several approvals share one rotation. Writers whose item or inbox write is refused because the version moved reload and retry once at the new version (§7.1, §7.4).

Rejected: grants between rotations, an optimisation for frequent joins that costs every reader a second path; a version record without a new key for joins, which breaks "one version, one key".

Consequence: one record type, one rule and one list of holders, signed in the chain. Every join creates a new team key version; a new device downloads one roster per access change since the team began, about 360 bytes per member each.

## D-38: No continuity signature

Status: Accepted.

Problem: a continuity signature by a member's previous keys over their new keys was shown to owners as a hint. Whoever copied the previous keys can produce it too, so it never distinguished the member from a thief, and with recovery proofs (D-33) it added a third proof class for no protection.

Decision: a re-key is either proven by the recovery key the account's held keys carry, or approved by a human after an out-of-band check (AS-06). There is no continuity signature.

Rejected: keeping it as a UI hint: a hint that an attacker can forge teaches owners to trust it.

Consequence: proofs are `recovery` or none, in records, the owner overview and `reconcile`.


## D-39: Removed key records are archived; a replacement is one operation

Status: Accepted; `replace` extended to `member-keys-wrap` by D-52.

Problem: a PIN change or a recovery phrase replacement was sent as a `delete` and a `create` of the same identity. A server keyed by identity either overwrote the removed wrap, losing the copy the restore window keeps (TH-36), or hit its unique key. Some databases refuse two actions on one item in a transaction (DynamoDB), so the pair couldn't even be mapped as sent. And restoring assumed one removed record per identity, when a session thief can replace a wrap several times.

Decision: each identity has at most one **live** record. `delete`, the new `replace` (an `account-key-wrap` only, which must be live) and the retirement of an account key version move the live record to an **archive**: no longer served, kept for the restore window. A replacement takes effect at once. Restoring is a support action outside the `RecordStore` interface: it brings back a chosen archived record and archives the live one, so a restore can itself be undone. A conforming server may implement the retirement of a version as a read filter on the current version.

Rejected: keeping `delete` then `create` and having servers collapse the pair, a batch rule every backend would have to discover; a new identity for each generation, which breaks `get` by identity.

Consequence: one more write operation, which every backend maps one to one. The identity is unique among live records only; archived records live beside them (an archive table, or a separate item with an expiry).

## D-40: The PIN is optional when rotating with the recovery phrase

Status: Accepted.

Problem: every rotation of the account key made a new PIN wrap, so it needed a server evaluation from the account's PIN budget. A session thief (A11) can spend that budget on purpose: until it resets, `secureAccount` can't run, `recover` unlocks but can't replace the PIN, and a PIN the thief set keeps opening the account (TH-44).

Decision: a rotation needs the recovery phrase (D-41), and the PIN is optional. Without a PIN, the new account key version has no PIN wrap: the rotation still retires every wrap of the old version, the thief's PIN and devices included. The account then reports `pin: "not-set-up"` and the `pin-not-set-up` warning; unlocking with a PIN answers `PIN_NOT_SET_UP` before any evaluation, and `changePin` creates the PIN wrap once the budget allows. `secureAccount` takes the phrase and an optional new PIN.

Rejected: a PIN wrap made without the server evaluation, which would let a stolen wrap test PINs offline (SP-08); relying only on the integration resetting the budget, which leaves the thief's PIN working until someone acts.

Consequence: an account can exist without a PIN wrap, at the current version, after a phrase-only rotation. It unlocks with the phrase or a registered device until a PIN is set. The integration may still reset a spent budget through its support process.

## D-41: Changing a credential needs a current credential

Status: Accepted.

Problem: same-device unlocks need no PIN, so a stolen device, or a script running in the vault, holds an open vault without knowing any credential. With only that, it could replace the recovery phrase, change the PIN, and rotate the account key with a PIN of its choice, which dropped the recovery wrap. The user was then locked out, and `secureAccount`, which needs the phrase, no longer ran (TH-45). An open vault proves possession of a device, not of the account.

Decision: an operation that changes how the account is opened needs a current credential besides the open vault:
- `changePin` needs the current PIN, checked by opening the live PIN wrap (one server evaluation), or the recovery phrase. With no PIN set (D-40), only the phrase.
- Replacing the recovery phrase needs the current phrase or the current PIN. Setting up recovery the first time needs neither: an account without recovery can't be in a team (D-35). (Amended by D-61: every setup needs a current credential.)
- Rotating the account key needs the current phrase, and keeps it; a new PIN is optional (D-40). A rotation never drops recovery.

A user who lost the phrase replaces it with the PIN, then secures the account with the new phrase if the old one may have leaked.

Rejected:
- Accepting the risk: a stolen device would be an account takeover.
- Only the phrase may replace the phrase: a lost phrase, which is common, could never be replaced, and the account could never rotate again.

Consequence: a device alone uses the account but can't change how it is opened; a user who forgot the PIN and lost the phrase keeps a working device but can't set new credentials. A PIN change costs two evaluations. A PIN thief with a session can still replace the phrase and rotate (TH-11); the remedy is a support restore (D-42). Revoking a device still needs only an open vault: it costs the user a new registration, never the account.

## D-42: The server never destroys an account's private records; a version can be restored

Status: Accepted; its rejected repair of an unreadable team state revisited by D-62.

Problem: D-39 archived removed account key wraps, so support could undo a session thief's changes within one account key version. Three cases weren't covered: a rotation by someone holding a credential (TH-11, TH-41) left the user's previous version with its member keys wraps "deleted"; a session thief could delete member keys wraps, or write a garbage team state that the server stored in place of the previous one (TH-46); and nothing let support make an older account key version current again.

Decision: the server never destroys an account's private records: account key wraps, member keys wraps and team states. Deleting, replacing or retiring one archives it, and each team state write archives the previous revision. Support may restore a single record (D-39) or an **account key version**: that version becomes current again, the records of later versions are archived, and that version's records are served again. Restores go only through the integration's support process; the library takes no part.

Rejected:
- Repairing an unreadable team state in the library from a device's local anchor: a session holding an older bundle could overwrite a newer team state, moving the account's anchor back.
- Deleting after a delay instead of archiving: the user's previous state would be gone when support needs it.

Consequence: a takeover is undone by restoring the version from before it. What a restore can't undo: devices that accepted the later version refuse the older one (SP-07, `rollback`) and must be reset and registered again; owner approvals of the thief's keys stay, and the restored user re-keys with an owner's approval. Archives are kept for the restore window only, which bounds what a data thief finds (TH-36).

## D-43: New member keys follow the newest published version

Status: Accepted.

Problem: the vault numbered new member keys from the bundles it held: 1 on joining, the newest held version + 1 on a re-key. Someone holding the user's session can publish `member-keys` records under the account (TH-37). Any version they took made the member's own write collide, forever, with `STALE_VERSION`, including the re-keys of `secureAccount` (TH-47). The member couldn't tell why.

Decision: new member keys take the account's newest published version for the team, plus one. The vault reports `foreign-member-keys` for a team where a published version is newer than every bundle it holds: keys this vault didn't make. The integration ends the account's other sign-in sessions before `secureAccount`, so nobody can publish newer keys over its proven re-keys. As defence in depth, the server accepts a `member-keys` record only from its own account, and only at that account's newest version for the team plus one: no other account can publish under it, and nobody can jump to the largest version and leave none for the member.

Rejected: refusing gaps in member keys versions. Approvals and rosters pin exact keys by version and hash, so a gap means nothing, and refusing one would hand the blocking back to the thief.

Consequence: a session thief can publish bait keys but can't block a member's writes. The member sees the warning; owners see the bait as unproven keys, which only a human approves (TH-37). Approvals are another matter: only the newest published keys can be approved, so while the thief keeps the session, bait published after each of the member's keys leaves the member's keys unapprovable. Ending the account's other sessions, which `secureAccount` already requires, ends it (TH-47).

## D-44: Membership changes are reported like owner changes

Status: Accepted; which records a report covers amended by D-57.

Problem: SP-15 promised that every newly approved member key is reported on every member's client. The library reported owner list changes only, and `team.members()` showed the current roster. A member admitted by a stolen owner key and removed again between two opens was never seen (TH-17).

Decision: chain verification reports, for every record newer than the client's highest anchor, the accounts added to, removed from or re-keyed in the roster, with the signer (`team.memberChanges`), as it reports owner changes.

Consequence: detection covers every access change since the client last verified the team, from the verified chain only. A first contact reports the whole history, as owner changes do.

## D-45: Securing an account can replace the recovery phrase

Status: Accepted.

Problem: `secureAccount` and `rotate` keep the phrase (D-41). When the phrase itself leaked (TH-11, TH-41), or after a support restore brought back the version whose phrase a thief used (D-42, TH-48), securing the account left that phrase working: the thief could take the account over again. The remedy was two operations, replacing the phrase then securing with the new one, which re-keyed every team twice, the first time with proofs the thief could also make.

Decision: `secureAccount({ phrase, newPhrase?, newPin? })` takes an optional new phrase, the one `beginRecoverySetup()` showed, typed back (D-35). It is checked, with the current phrase, before anything is written (`WRONG_CREDENTIAL`). The rotation stores the new version's recovery wrap for the new phrase instead of the current one, and the team re-keys carry the new recovery public key, each signed by the current phrase's recovery key: proven against the keys each team holds (SP-23). `rotate` keeps the phrase.

Rejected:
- Keeping two operations: users and integrations stop after the first, and the teams are re-keyed twice.
- A new phrase on `rotate` as well: securing is the operation for a compromise; a rotation alone leaves member keys the thief may hold (SP-11).

Consequence: one call ends a phrase leak: new account key, new phrase, other devices cut, every team re-keyed with a proof. The proof is still made with the leaked phrase, so a thief who publishes proven keys first races the user as in TH-41; ending the account's other sessions first removes the way to publish. A team that failed to re-key is retried with `rekey(teamId, { phrase, oldPhrase })`: the new phrase, whose key the new keys carry, and the **old** one, which still proves it (D-49, D-56).

## D-46: Every roster entry names published member keys

Status: Accepted.

Problem: readers checked owners' roster entries against published `member-keys` records (§4.5), but took every other entry as written. Someone holding a stolen owner key could seal a version to keys of their own under an existing member's account id, keys nobody published. Every client then reported "re-keyed" for that member instead of a new account, and listed the member among the holders: the admission was hidden in the one report that detects a stolen owner key (TH-17, SP-15).

Decision: a reader accepts a version record only if every roster entry matches a published `member-keys` record of that account and `memberKeysVersion`, with that `keysHash`; otherwise `TRUST_FAILURE` (`key_mismatch`). It applies to every record the client verifies, as the owner check does.

Rejected: checking only entries that changed since the client's anchor. Same safety for a smaller cost, but one more rule to implement, and the cost is already small.

Consequence: a roster names only keys their account published, so the accounts SP-15 reports are the accounts the keys belong to, as long as the server honours rule 8. The client already fetches every `member-keys` record of the team (§6.1), so the check costs one hash per entry and no request. A server that loses or hides one `member-keys` record makes the team `unverified` for every member, where before only owners failed, at their next rotation: an availability loss like TH-28.

## D-47: An owner's own reconcile approves its own re-key

Status: Accepted.

Problem: owners' re-keys were never approved automatically (D-33), so after `secureAccount` an owner waited for another owner, and in a single-owner team the spec named nobody who could approve. Until then, the owner key an attacker copied from a misused device stayed an owner key, able to admit members or remove the other owners (TH-17). Owners could already approve their own keys with `approve`, but only if the integration added that step.

Decision: an owner's `reconcile` approves the **caller's own** re-key when its newest published keys are keys the session holds: one of the bundles the vault handed it, each already checked against its published record (§4.3). The rotation is signed with the caller's previous owner key and replaces it in the owner list (§6.8 step 3). Every other owner's re-key, proven or not, stays `owner-rekey` for a human.

Rejected:
- Approving owners' proven re-keys for anyone: a leaked phrase would become a silent change of the owner list (D-33).
- Having `secureAccount` approve in each team itself: the vault would open owner sessions, which a split layout's vault can't do without the team's anchors.

Consequence: the owner's next routine `reconcile`, on the device where it secured the account, closes the window, in a single-owner team too. Holding the private keys is the proof that the account's vault holds them, not that the user made them. Keys someone only publishes under the account never qualify (TH-37). A bundle the vault holds but didn't make takes the account key: a device thief re-keying from the stolen vault, or someone who copied the account key or knows the phrase and writes a wrapped bundle with a session (TH-11, TH-12, TH-41). Each of them already holds the owner key, so they gain nothing they couldn't sign directly (TH-17), and `secureAccount` cuts them out; what they lose the owner is the `owner-rekey` item that used to show a re-key nobody asked for. Automatic actions still never add an account or an owner.

## D-48: Member keys carry an anchor floor

Status: Accepted; which anchor the floor is, and when it counts, amended by D-50, D-52 and D-54. The current rules are stated in D-54.

Problem: a device with no local anchor took its anchor from the account's `team-state` (§4.4). If the server didn't serve it, or a session thief deleted it, the device was on first contact, trusting whatever chain the server presented (TH-04): a malicious server could show an existing member's new device a forged team whose key it held. Nothing told "joined, never opened" apart from "the record was withheld". An invite anchor protected only the joiner's first open, and had to be passed again in each context.

Decision: each member keys bundle carries an optional **anchor floor**, a (version, record hash) the vault built or verified, inside the `member-keys-wrap` (§4.3), the one private record the vault can't open the team without, and that the server can't forge or alter:
- at team creation, version 1 of the new chain;
- at join, the invite link's anchor, now given to `joinTeam(teamId, { anchor })`, which checks that the served chain contains it before writing anything;
- at a re-key, the newest bundle's floor, or, if it has none, an anchor the vault already trusts (its local anchor, else the account's `team-state`);
- at an account rotation, the same floor, re-wrapped, or, if it has none, filled as at a re-key.

A transfer carries each bundle's floor (§3.8). A device uses the floor only when it has no local anchor and no readable `team-state` (§6.1 step 1): any real `team-state` anchor is at or above it in the same chain.

Rejected:
- The floor in the public `member-keys` record: a change to a signed public format, and it shows every member's join point.
- Requiring a `team-state` to exist: the server can serve an older revision, and the first revision is written only at the first open.
- Using the floor on every open: the client would download the chain from its join version each time (D-34).
- Keeping the invite anchor on `openTeam`: it protects one open in one context, and a wrong link can be retried without it.

Consequence: withholding or deleting `team-state` no longer puts an existing member's device on first contact; it starts from the floor, so a forged team is refused. A member who joined without an invite anchor stays on first contact until its first re-key or account rotation gives it a floor. The invite anchor is checked once, at join, and a wrong one is refused before the member's keys exist. `openTeam` and the receiver lose their `anchor` option.

## D-49: A re-key can be proven by the phrase the team's keys carry

Status: Accepted; the retry's arguments amended by D-56 (`rekey(teamId, { phrase, oldPhrase })`).

Problem: a proof verifies against the recovery key of the keys a team holds (§4.2). After a phrase replacement, those keys carry the old recovery key until the team approves the re-key; but `rekey(teamId, { phrase })` accepted only the current phrase. A team that failed to re-key during `confirmRecoveryPhrase` or `secureAccount` with a new phrase could only be retried unproven, so an owner approved it by hand.

Decision: `rekey(teamId, { phrase })` accepts the current phrase, or a phrase whose recovery key one of the vault's bundles for that team carries. The proof is signed with that phrase's key; the new keys carry the account's current recovery key.

Rejected: keeping the old recovery signing key for retries: it would be stored, and a stored recovery key is what D-33 forbids.

Consequence: a failed team is retried with the old phrase and stays proven. The proof means what it meant: whoever holds the old phrase can prove a re-key in teams that still hold keys carrying it (TH-41), which replacing the phrase never prevented before the team approves.

## D-50: The anchor floor is the newest anchor the vault trusts

Status: Accepted; the sources of the floor at a re-key or a rotation amended by D-51; the read rule, the re-key and the rotation superseded by D-52, then D-54. Its join rule still holds; the current rules are stated in D-54.

Problem: D-48's floor was set once (version 1, or the invite anchor) and then only carried, or filled from another anchor when missing. It counted only when a device had no other anchor, so an archived `team-state` below it won (TH-05). A member who joined without an invite anchor had no floor until a re-key or rotation: while the server withheld `team-state`, each new device was a new first contact (TH-04). The "carry, else fill" rule had two branches, written in five places.

Decision: one rule for writing and one for reading.
- **Write:** a bundle's floor is the newest anchor the vault trusts when it writes the bundle. At team creation, version 1. At join, the tip of the chain the vault verifies there, from the invite anchor if given, else from version 1. At a re-key or an account rotation, the highest of the team's bundles' floors, the local anchor and the account's `team-state` anchor (one that doesn't open is skipped, TH-46); a rotation gives it to every bundle of the team.
- **Read:** the newest bundle's floor counts as an anchor unless it is below the lowest other anchor (§6.1 step 1).
- `joinTeam` with an anchor when the account already has keys for the team checks that the served chain contains it, writes nothing and leaves the floor as it is.

Rejected:
- Counting the floor on every open: a floor below every other anchor would make the client fetch the chain from it (D-34, D-48).
- Advancing the floor at every open: the bundle is write-once, so it would mean a new wrap per open.
- Keeping first contact at the first open for a joiner without an invite anchor: it repeats on each new device while `team-state` is withheld.

Consequence: every member has a floor from its join on; a floor is at most one re-key or rotation old, and no `team-state` revision below it is followed. Without an invite anchor, the join is the member's one first contact (TH-04), and a join to a team with no chain fails there. The floor never adds a download: the fetch starts from the lowest anchor, as before.

## D-51: The floor comes only from the account's own records

Status: Superseded by D-52 (review 006 C: a `team-state` anchor isn't the account's own record).

Problem: D-50 wrote the floor at a re-key or a rotation from the highest of the team's bundles' floors, the local anchor and the `team-state` anchor. The local anchor is written on the device (`LocalKeyStore`), where an injected script or someone with the device (A9, A7) can change it, and nothing checked it against a chain. A re-key or a rotation, `secureAccount` included, copied it into every bundle of the team, under the account key: every new device of the member and every receiving context then trusted it. Alone, the attacker made the team unopenable for the member's new devices; with the server, they opened a forged team (review 005 A).

Decision: at a re-key or an account rotation, the floor is the highest of the team's bundles' floors and the account's `team-state` anchor, opened with any of the team's bundles (one that doesn't open is skipped, TH-46). The local anchor isn't a source: it stays this device's anchor for its own opens (§6.1 step 1). Creation and join are unchanged.

Rejected:
- Keeping the local anchor and verifying the chain at each re-key and rotation: it refuses a bad local anchor, but costs one chain download per team at every rotation, `secureAccount` included.

Consequence: what reaches the floor was written by the vault (a floor) or by `advanceAnchor` from a verified chain under a `teamStateKey` (§4.4); the server can only serve an older `team-state`, which the highest ignores. A local anchor a script or a thief changed stops only that device, and `secureAccount` no longer spreads it. A floor can lag this device's newest anchor until its `team-state` write lands; the next open writes it.

## D-52: The anchor floor is the root of trust

Status: Accepted; the re-key's floor and its fallback amended by D-54, which adds the vault's anchor to the roots. The current rules are stated in D-54. With a floor, a `team-state` under keys being replaced is absent (D-63).

Problem: every anchor was a root of trust of its own. A record at an anchor's version was accepted by its hash alone, and the floor, the one anchor the vault builds from a chain it verified, was dropped as soon as a higher anchor existed (D-50). A local anchor, which a script in the origin or someone with the device can write, or a `team-state`, which any holder of a `teamStateKey` can write, therefore chose the chain once it was above the floor. With the server, a forged team opened `ready`; its anchor spread through `team-state` to new devices, and the re-key in `secureAccount` made it the floor (review 006 B and C). D-51 had removed only the local anchor from the floor's sources.

Decision:
- **Read:** the roots are the newest bundle's floor and the local anchor; for keys with no floor, the `team-state` anchor too. The chain is fetched from the lowest root and must contain every root, so every anchor is linked to the floor by hashes and owner signatures. The `team-state` anchor is then checked against that chain: a version the chain holds with another hash is `TRUST_FAILURE` (`state_conflict`), a version above its tip is `rollback`, and one below it isn't followed (§6.1).
- **Advance:** when the vault opens or exports a team (§5.8) and the chain it verified has a tip above the newest bundle's floor, it replaces that bundle's wrap with the tip as its floor (`replace`, D-39), in the batch of the clean-up of §6.8 step 4 when that runs.
- **Re-key:** the new floor is the tip of the chain verified from the newest bundle's floor alone; in `secureAccount`, from this device's local anchor when it has one (§5.11 runs on a device the attacker didn't control), else from the floor. If the verification fails, the floor stays the current one, so no chain problem blocks a re-key.
- **Rotation:** each bundle keeps the floor it carries.

Rejected:
- Counting the floor on every open without advancing it: nearly every open would fetch the chain from the join version (review 007 A; D-34, D-48, D-50).
- Counting the floor only on a device with no local anchor: the tampered device itself would still open a forged team.
- Overwriting a `team-state` the chain contradicts: it heals without support, but discards the evidence of a split view (TH-38).
- Taking the floor from the highest anchor read (D-50, D-51): an anchor is only as good as whoever wrote it.

Consequence: an anchor written outside the vault can no longer choose the chain. A forged local anchor stops its own device; a forged `team-state` stops the account's devices with `state_conflict` or `rollback` until support restores the previous revision (TH-46). The floor stays near the tip, so a fetch from the floor costs about what a fetch from the lowest anchor did, and a vault open or export that sees a new version costs one more small write. Someone holding the account key can plant a floor; `secureAccount` on a device that has opened the team replaces it in each new bundle, and on one that hasn't, verifies from the floor it holds (TH-20). The server can serve an older wrap, whose older floor bounds a rollback as in TH-05.

## D-53: PIN evaluations are verifiable, and the key id is a client setting

Status: Accepted.

Problem: PIN hardening ran RFC 9497's OPRF in base mode, with no proof, under a key id the server named (`currentKeyId`). A party that controlled the answers for a while without holding the key, such as a compromised front end before an isolated key service, could answer with a key of its own, at every enrolment and, by moving the key id, at every account's next unlock. Every PIN wrap written then could be checked offline by whoever later stole the database (review 006 E, TH-51).

Decision:
- The PIN evaluation is RFC 9497 POPRF (ristretto255-SHA512), with public info `enc(label("pin-oprf"), accountId)` built by the server from the account it charges. One key pair per `oprfKeyId`; each evaluation returns a proof.
- The client checks the proof against the public key its settings pin for the key id, shipped in the integration's code (AS-02), never fetched from the server. An unpinned key id is `UNSUPPORTED_VERSION` before any work; a failed proof is `TRUST_FAILURE` (`bad_signature`) before anything is derived. Neither is retried.
- New wraps use the settings' `writeKeyId`, as the Argon2id cost is a setting (D-17). `OprfService.currentKeyId` is removed. A key is replaced in two releases: pin it, then make it `writeKeyId`.
- The unlock stands when only its upgrade fails; the old wrap is kept.
- v1 isn't released (§13): cc1's PIN hardening is changed in place, the wrap layout stays, and POPRF key ids start above any id used before, so a base-mode wrap from a test deployment fails with `UNSUPPORTED_VERSION`, never as a wrong PIN.

Rejected:
- A verifiable OPRF with a key per account: its public keys can't be pinned in client code.
- Keeping `currentKeyId` and upgrading only to pinned ids: the server could still send writers back to an older pinned key, or flip ids to spend the budget (review 008 A).
- Accepting it in TH-09: isolating the OPRF key from the database would protect nothing against whoever answers in its name.
- A mode field and a new wrap version: a fallback to delete later, for wraps no release ever wrote.

Consequence: whatever answers PIN evaluations without the key can only refuse them. One key now serves every account of a key id, so a repeated proof nonce, or one account's tweaked key, reveals it for all: the integration draws nonces from a CSPRNG, exports no tweaked key, and rotates key ids or caps evaluations per key id (scope rule 2). POPRF rests on a stronger assumption than base mode (RFC 9497, security considerations). The integration ships each public key in its client code before using it. The server can still make guesses within each account's budget (TH-08), and a key holder is as strong as before (TH-09).

## D-54: Floors are written only where every root agrees; the vault keeps its own anchor

Status: Accepted; the repair also replaces this device's local anchor (review 035 A).

Problem: D-52 wrote a re-key's floor from a chain verified from the local anchor or the floor, and kept the current floor when that failed. Someone who held the account key could plant a floor in a wrap: a vault with no anchor of its own (a split layout, a new device) verified from it; a server that made the verification fail had it kept; a retry and an export fell back to it; a forged local anchor could stand in for it (reviews 009 B, 010). And `secureAccount` was trusted to end the old account key's reach, while a retired version comes back on a stateless or stale device, or through a support restore (review 009 C).

Decision. The current floor rules, in one place (they replace what D-48, D-50 and D-52 state, which keep their history):
- **Write.** A bundle's floor is version 1 at creation (§6.3); at join, the tip of the chain verified from the invite anchor, or from version 1 without one (§6.4, D-50); at a re-key, the tip of a chain that contains every root the vault holds for the team, or of one from an owner's anchor (§5.9, §6.8); when the vault opens or exports the team, the verified tip if it is newer (§5.8). A rotation keeps it. Nothing else writes it.
- **Read.** The roots are the newest bundle's floor, the local anchor, and in the vault's context the vault's own anchor; for keys with no floor, the `team-state` anchor too. The chain is fetched from the lowest root and must contain every root; the `team-state` anchor counts only on that chain (`state_conflict` when contradicted, `rollback` when above it) (§6.1, D-52).

What this decision changed:
- The vault keeps its own anchor per team, in its half of local storage (`local-vault-anchor`, §3.7), apart from the sessions' anchors. It records the tip of every chain it verifies (creation, join, open in its context, export) and never moves down, except when a repair from an owner's anchor replaces it.
- A re-key writes a floor only from a chain that contains every root the vault holds for the team: the newest bundle's floor and its own anchor. If they conflict or the chain doesn't verify, the re-key fails and writes nothing. An export refuses on the same failure. D-52's "else the current floor" goes.
- An anchor an owner gives out of band (`team.inviteAnchor()`), passed to `rekey` or `secureAccount`, is then the only root: the repair for a planted floor or a device with no anchor. The repair replaces the vault's anchor and this device's local anchor with the new floor, so the device it runs on opens on the repaired chain; other devices repair the same way, or are reset, and a receiving context gets a new transfer (review 035 A).
- A rotation keeps each bundle's floor; `secureAccount`'s re-keys then write checked floors.
- Retired versions: no client rule stops a server that serves one to a device with no newer state, or a support restore. The limits say so (SP-11, SP-19, TH-05, TH-12); a new phrase is the recommended default; a new PIN that opens the current PIN wrap is refused; the integration resets the account's other devices after `secureAccount`; `foreign-member-keys` advises `secureAccount`, not `rekey`.

Rejected:
- Trusting the vault's anchor alone (the first proposal, review 010 D): a forged anchor, written by any script in the origin, would become the floor.
- Requiring a new phrase, or a new PIN, in `secureAccount` (review 010 C): each closes one path of several, and a required PIN blocks `secureAccount` when the budget is spent (D-40, TH-44).
- Keeping a re-key going on a failed check: whoever makes the check fail chooses the floor.

Consequence: a planted floor, a forged local anchor or a failed chain becomes a team reported failed, not a floor carried; the owner's anchor repairs it on the device that runs the repair. A vault that never verified the team on this device still trusts the floor it holds until an owner's anchor is given; a new device of the account trusts the floor of the wrap it is served, a planted one the server kept included (TH-20, review 037 E). The vault's anchor refuses a floor written directly, not one given through the open vault, since `rekey` with an anchor needs no credential (review 037 D). The vault's anchor is one more local value, writable by any script in its origin, but a forged one only fails re-keys and exports on that device. Split layouts give the vault its `DeviceKeyStore` half, as before; same-origin layouts keep one store with two labels.

## D-55: An approval names the keys hash it reviewed

Status: Accepted.

Problem: an approval named only `{ accountId, memberKeysVersion }`. `reconcile` checked the recovery proof, or the caller's custody of its own keys (D-47), on the record of one list; the rotation fetched the account's records again and sealed to whatever came back at that version. A server serving another record the second time got the next team key, or, for an owner's own re-key, an owner seat (review 013 A). Listing two records for one version did the same between the custody check and the handle (review 014 A).

Decision:
- The handle an owner approves is `{ accountId, memberKeysVersion, keysHash }`, `keysHash` being the keys hash (§4.2) of the record whose proof or custody the owner's client checked.
- A rotation that approves a handle seals to the account's newest published record only if it has the handle's keys hash. A newer version is `STALE_VERSION`, as before; the handle's version with another hash is `TRUST_FAILURE` (`key_mismatch`).
- Two records for one account and `memberKeysVersion`, in any list an owner's client reads, are `TRUST_FAILURE` (`key_mismatch`): write-once records can't have two values.

Rejected:
- Checking the proof again at rotation time: a second rule, which covers neither unproven keys a human approves nor the owner's own re-key (D-47).
- An opaque handle: handles are plain data the integration stores, shows and passes back (D-31).

Consequence: what the overview showed, what `reconcile` checked and what the rotation seals to are one record. Held keys stay pinned by the roster's keys hash (§6.6). Handles carry one more field, which an integration that builds handles itself must fill from the overview.

## D-56: The phrase the user types is the only recovery key the vault uses

Status: Accepted; amends D-49's arguments; amended so a stored key that doesn't open is a mismatch (review 032 A).

Problem: the recovery wrap carries the recovery public key under the account key, apart from `wrappedAccountKey` (§4.1). Whoever holds the account key and the session could replace that field alone: the user's phrase still opened the account, `secureAccount` compared the phrase with the stored key and refused it, and the `rekey-needed` warning led the user to `rekey(teamId, { phrase })`, which signed, with the real phrase, keys carrying the attacker's recovery key (D-49's "a phrase a bundle carries"). The attacker then proved its own re-keys (review 013 B).

Decision:
- Given the current phrase, the vault checks it by opening the current recovery wrap's `wrappedAccountKey` with the recovery key derived from it, as a rotation and a PIN change already did, and uses the recovery public key derived from it for every key it writes or signs, never the stored one. A recovery signature is made only on keys carrying the key of a phrase typed in that operation: the current phrase, or the new phrase being set.
- A stored key that differs from the typed phrase's is reported (`recovery-key-mismatch`, action `secureAccount`), never refused: `recover` opens the account. `rotate`, `secureAccount` and `confirmRecoveryPhrase` write a new recovery wrap from the typed phrase, which repairs it.
- A retry after a replacement is `rekey(teamId, { phrase, oldPhrase })`: `phrase` is the current phrase, whose key the new keys carry; `oldPhrase` signs instead, and must be carried by one of the vault's bundles for the team, a guard against a typing mistake (owners check the keys the roster pins). `oldPhrase` without `phrase` is `MALFORMED_RECORD`.

Rejected:
- Binding the recovery public key to `wrappedAccountKey` (a new record version): the account-key holder replaces the whole wrap instead, and the user's phrase stops working, which is no better.
- Refusing a mismatched wrap, in `recover` too: a user without a PIN couldn't unlock anywhere, so couldn't run `secureAccount`, the repair (review 014 B).
- Dropping D-49: a team that fails during `secureAccount` with a new phrase would need an owner by hand.
- Pinning the recovery public key in local storage: one more local value, which any script in the origin can write.

Consequence: a replaced field can't make the user's phrase vouch for someone else's keys, and `secureAccount` repairs it. Operations given no phrase (`createTeam`, `joinTeam`, `rekey` without one) still read the stored key: keys they make while an account-key holder controls it carry its recovery key, so in those teams its re-keys stay proven; after `secureAccount`, a server colluding with it can publish proven keys above the user's (D-43's server rule is defence in depth), until an owner approves the user's re-key by hand (TH-12).

Amendment (review 032 A, review 033 1): a session alone can replace the recovery wrap with one whose `wrappedRecoveryPublicKey` is missing, doesn't open, or isn't a valid key, or with a record that doesn't parse, its `wrappedAccountKey` intact or not. Reading the stored key threw, which refused `secureAccount`, a proven `rekey`, a phrase replacement, `recover` and the warnings; the PIN kept working, so nothing showed it. Now a stored key that can't be read counts as one that differs: given the phrase (checked by opening `wrappedAccountKey`), the phrase's key is used and the mismatch reported; `warnings()` reports `recovery-key-mismatch` for a recovery wrap that doesn't parse or whose key can't be read, and then leaves out `rekey-needed`, which needs that key; a recovery setup with the PIN (D-61) replaces the live wrap without parsing it. Operations given no phrase still need the stored key and fail. Accepted: a garbled `wrappedAccountKey` can't be told from a wrong phrase, so the phrase reads as wrong; the remedy is a recovery setup with the PIN, or a support restore of the archived wrap, the only one for an account with no PIN (TH-46).

## D-57: Change reports cover every record above the lowest root

Status: Accepted; amends D-44.

Problem: reports covered the records newer than the highest anchor, and the anchors included the floor and the `team-state` anchor, which belong to the account, not to a device. Only the first device or context of an account to open after a change reported it: another device reported nothing afterwards, and a split layout never did, since the export moves the floor to the tip before sealing it. A stolen owner key could admit and remove a member unseen, when detection is the mitigation (TH-17). Anyone holding a `teamStateKey` could also hide reports on every device by writing `team-state` at the tip (review 016 A, review 017).

Decision: reports (`ownerChanges`, `memberChanges`) cover every record of the verified chain above the lowest root, the version the chain is fetched from (§6.1). A session adds the reports of each reload to those it holds.

Rejected: bounding reports by this device's local anchor, with a fallback to the highest root: a fallback, and a context without its own anchor still reported nothing (review 017 E).

Consequence: a device or context reports every change since it last verified the team, whatever another device did; a fresh one reports nothing older than its roots, and a first contact the whole history, as before. Hiding reports on a device takes raising every root, the floor included. While the floor lags behind the local anchor, a change can be reported twice; floor upkeep on open and export makes that rare. Every context that opens a team must show its reports.

## D-58: A record that fails its own checks is absent

Status: Accepted; amended so a team whose bundles fail stops only that team (review 028 A), so a wrap read by its identity that doesn't parse costs only its method (review 035 B), and so a PIN wrap whose `kdf` the reader refuses, or this device's wrap that doesn't open, does too (review 037 B, C).

Problem: one record could stop everything around it. A session created a garbage `member-keys-wrap` under a new identity: every account-wide operation failed (`secureAccount`, `rotate`, the warnings), and no restore removed a record with no archived generation. An account-key holder could do the same with a wrap that opens but whose published keys don't match. A joiner published a `member-keys` record with a bad signature, and every member's team became `unverified`, with no way to delete it (review 016 B, C; review 017 A–C, F, G).

Decision:
- A `member-keys-wrap` that doesn't parse, or doesn't open under the account key, was never the account's: the vault treats it as absent, as if withheld, wherever it lists wraps. An account's teams are those with at least one wrap that opens. A device `account-key-wrap` that doesn't parse is left out of the device list. A wrap that opens but doesn't match its published keys stays `TRUST_FAILURE` (`key_mismatch`) when its team is opened.
- A rotation re-wraps every wrap that opens, without fetching its published record.
- A `member-keys` record that fails its checks, an unknown version or suite included, is left out of every list used to verify the chain, build an overview, reconcile or approve, before D-55's duplicate check. Numbering new keys and `foreign-member-keys` still read every published version.
- Server rule: a `member-keys-wrap` is created only in the batch that creates its `member-keys` record, or in a rotation's batch at the version it switches to; an `account-key-wrap` only at the current version or in that batch. New member keys are numbered from published records only.

Rejected:
- A support action archiving a live record with no generation: every device fails until support acts.
- Leaving a mismatched wrap behind in a rotation: a server forging or withholding `member-keys` records could make a rotation drop real bundles.
- Requiring servers to verify `member-keys` signatures: defence in depth only (rule 8).

Consequence: a session or a joiner can no longer stop an account's or a team's operations with one record; what the server could already withhold, they can make absent, and nothing more. Accepted: an account-key holder can still plant a wrap that opens with keys its published record doesn't match, which fails that team for the account, its repairs included, until support archives that wrap (TH-20, review 022 A); a garbage replacement of a live wrap now looks like a deletion, restorable from the archive (TH-46). A rotation re-wraps the wraps it lists: one the server withholds then stays with the retired version, archived, until support restores it (TH-28, review 032 F).

Amendment (review 028 A): the account-wide lists still opened every team's bundles unguarded, so one team whose wrap opens but doesn't match its published record, or whose published record fails its checks or is withheld, made `warnings()` throw and `confirmRecoveryPhrase` throw after replacing the phrase, with no team re-keyed. Now, wherever the vault goes through every team of the account, a team whose bundles fail (any error but `STORE_ERROR`) stops only that team: `warnings()` lists it under `foreign-member-keys`, since only keys or a wrap this vault didn't make, or a withheld record, get it there, and every re-key across teams counts it among the teams to re-key, so it is reported `failed`. Rejected: a new warning code (new API for the case `foreign-member-keys` already names, with the same remedy); leaving the team out (the user would never learn of it, and a phrase replacement would leave it on the old recovery key unreported). A team listed under `foreign-member-keys` isn't listed under `rekey-needed` too, whose advice differs (review 029 A). An operation that re-keys across teams lists them before its first write, so a store error, which still stops it, writes nothing (review 030 A).

Amendment (review 035 B): the vault reads the PIN wrap, the recovery wrap and this device's wrap by their identity, and a record that didn't parse there threw: a session replacing the PIN wrap made `status()` and `warnings()` throw, hiding every warning, and refused the PIN change with the phrase, `secureAccount` with a new PIN and `recover`. Now each of those reads gives absent, readable, or present but unreadable (it doesn't parse, or a known `v` and suite fails its shape or context checks; an unknown `v` or suite stays `UNSUPPORTED_VERSION`, readers first, §10). Present but unreadable: `status()` reads that method as set up; `warnings()` reports `pin-not-set-up` for the PIN, and `recovery-key-mismatch` for recovery, with action `beginRecoverySetup`, since the phrase can't be checked against it (D-56); unlocking with it is `WRONG_CREDENTIAL`, or `DEVICE_NOT_REGISTERED` for this device's wrap; and the operation that writes the method replaces it without reading it (a PIN change, whose same-PIN check is skipped as for a spent share; a recovery setup), or, for this device's wrap, registers the device again under a new id. A session's garbage there costs that method only; support restores it (SP-26).

Amendment (review 037 B, C): two records a session can write still cost more than their method. A PIN wrap that parses but whose `kdf` the reader refuses (an `oprfKeyId` the settings don't pin, `UNSUPPORTED_VERSION`; a cost outside the reader's bounds, `MALFORMED_RECORD`) made the same-PIN check throw, so `secureAccount` with a new PIN refused. This device's wrap that parses but doesn't open under its `deviceKey` gave `DECRYPTION_FAILED` at every same-device unlock, counted as a registration, so the device never registered again, and read as registered in `status()`. Now the same-PIN check is skipped when the derivation refuses the wrap's `kdf`, as for a wrap that doesn't parse; a bad proof (`TRUST_FAILURE`) and a store error still throw, being the OPRF service's and the store's. Unlocking with that PIN wrap is unchanged: an unpinned key id is also the honest sign that the settings lag. This device's wrap that doesn't open under its key is present but unreadable: `unlock()` is `DEVICE_NOT_REGISTERED`, `status()` reads it as not registered, and an unlock with the PIN or the phrase registers the device again under a new id. A random device key never fails honestly, so only a writer of the record chooses this branch, which garbling the record already gave it. Accepted, as for a PIN wrap that doesn't parse: with the check skipped, the user can set the PIN of a retired version again (SP-19), which a server must still serve to a stateless device.

## D-59: The vault's own anchor roots every vault verification

Status: Accepted; amends D-54's list of operations.

Problem: a join verified the served chain from the invite anchor, or from version 1, without the vault's own anchor. The server withheld an existing member's wraps, so the vault saw no keys, and a join without an anchor, which §6.4 called harmless for a member, rooted new keys on a forged chain and moved the vault's anchor up to its tip (review 019 A). A vault whose anchor a forged join had moved then refused the real invite anchor, and `rekey` couldn't repair a team with no bundle (review 020).

Decision: every chain the vault verifies (opening, exporting, the leave check, a re-key, a join) contains the vault's own anchor for the team, when it has one, and the newest bundle's floor, when it holds one; a join adds the invite anchor. Only an owner's anchor given to `rekey` or `secureAccount` replaces them (D-54), and `rekey` with one runs when the vault holds no bundle for the team.

Rejected: letting an invite anchor replace the vault's anchor: the server can deliver the link (TH-04), and would roll the vault back.

Consequence: a server withholding an existing member's wraps can't re-root a device that verified the team. On a device with no vault anchor, a join is a first contact (TH-04): the integration re-joins an existing member only with an owner's anchor.

## D-60: `secureAccount` reports the product's teams it can't re-key

Status: Accepted.

Problem: `secureAccount` worked on the teams with a wrap that opens (D-58). A device thief with the session copied a team's bundle, then deleted its wrap: the team was neither re-keyed nor reported, and the stolen keys stayed in its roster (review 019 B).

Decision: `secureAccount` takes an optional `teamIds`, the teams the integration's product says the user belongs to. A listed team with no wrap that opens is reported failed. It is repaired with `rekey(teamId, { phrase, anchor })` and an owner's anchor (D-59): a proven re-key that owners' `reconcile` approves, which ends the old keys. With no bundle, `oldPhrase` isn't checked against carried keys.

Rejected: a `DeviceKeyStore` method listing the vault's anchors (a port duty, and only for teams this device verified); an account-wide team index on the server (a new record).

Consequence: the integration passes the list it already has. It comes through the server, which can add a report but not hide one more than it already could by withholding wraps. `warnings()` still reads the wraps: a deleted wrap hides `foreign-member-keys` for that team until `secureAccount` with `teamIds` (accepted).

## D-61: Every recovery setup needs a current credential

Status: Accepted; amends D-35 and D-41.

Problem: a first recovery setup needed no credential, on the premise that an account without recovery can't be in a team. A session deleting the recovery wrap made that premise false: the vault saw a first setup, the user following `recovery-not-set-up` set a phrase with no credential, and every team was re-keyed without proof; whoever held the session with an open vault could set a phrase of its own the same way (review 019 D, review 013 D, review 020).

Decision: with no recovery wrap, a recovery setup needs the current PIN (one server evaluation); with one, the current phrase or PIN, as before. `recover` with no recovery wrap answers `RECOVERY_NOT_SET_UP`.

Rejected: a credential only when the account holds team wraps (review 020): whoever deletes or withholds the wraps decides whether a credential is asked.

Consequence: onboarding asks for the PIN once more (one evaluation). An account with neither a PIN nor a recovery wrap, which only tampering reaches, needs a support restore. A setup with the PIN re-keys without proof; a user who kept the old phrase proves the re-keys with `rekey(teamId, { phrase, oldPhrase })`. A script holding the account key still writes wraps directly (TH-45).

## D-62: With a floor, a team state that doesn't open is absent

Status: Accepted; revisits D-42's rejected repair; amended for malformed records and unknown versions (reviews 024 A, 026 B); which key opens it narrowed by D-63.

Problem: a `team-state` that doesn't open stopped every device at `state_unreadable`. After a session deleted a team's wrap, the repair D-59 and D-60 document (a proven `rekey` with an owner's anchor, approved) left the member there for good: the server's `team-state` was under the deleted bundle's key, and only support could replace it. A session writing garbage did the same (TH-46) (review 022 B).

Decision: when the newest bundle holds an anchor floor, a `team-state` that no `teamStateKey` the session holds opens is absent, as a wrap that doesn't open is (D-58). The anchor advance (§6.1 step 7) replaces it, by compare-and-set on its revision, under the newest bundle's key, if that bundle is in the tip's roster; keys the roster no longer holds never overwrite it. For keys with no floor, `team-state` is a root, and an unreadable one stays `state_unreadable`. A revision is below the largest safe integer.

Rejected:
- Replacing `team-state` only in the repair with an owner's anchor (review 023 D): garbage from any other cause would still stop every device until a user acts.
- Replacing it from any context: a context holding older keys and one holding the current keys would overwrite each other on every open (review 023 C).

Consequence: D-42 rejected this repair because a device holding an older bundle could overwrite a newer `team-state` and move the anchor back. With a floor, `team-state` chooses nothing (D-52) and bounds no report (D-57); it still bounds rollback above the floor for a context with no local anchor, and only when it opens. Only keys the roster holds replace it, which a stale context's aren't. A garbage `team-state` now stops only keys with no floor (TH-46).

Amendment (reviews 024 A, 025 A, 026 B): a record that failed its shape checks still stopped the team, before any key was tried, and `leaveTeam` with it. Now the reader takes `revision` first, an integer from 1 to 2^53 − 2; a `revision` that fails is `MALFORMED_RECORD`, whatever the floor. With a floor, the rest is read by version: an unknown `v` or suite is absent and never replaced, since readers ship first (§10) and an older client must not overwrite a newer one's record; a known version that fails its shape, context or decryption doesn't open, so it is absent and replaced as above. With no floor, each failure is the error it was. The `revision` field keeps its name and meaning in every `team-state` layout. The server accepts a write only at the current revision + 1 (scope rule 4), which the cap relies on: without it, a session writes a revision the replacement would push past the cap. Rejected: narrowing the claim to well-formed records (the explanation costs more than the branch); replacing an unknown version (with mixed library versions on one account, the record would switch formats back and forth). Consequence: a session's record at an unknown version stays absent until support restores the previous revision, as a deleted one would without the next advance; the floor bounds it (D-50, TH-46).

## D-63: With a floor, a team state counts only under the newest keys

Status: Accepted; narrows D-62; revisits, for keys being replaced, D-52's rejected overwrite.

Problem: a holder of a copied bundle with the session (a script in the vault, or someone with a signed-in device) writes a readable `team-state` under that bundle's `teamStateKey`, naming a forged anchor. `secureAccount` re-keys the team, but the vault keeps the old bundle until the new keys are approved, and every held bundle opened `team-state`: every open was `state_conflict`, so a sole owner's own `reconcile` (D-47) never approved the new keys, and the copied owner key stayed the owner's until support restored the record (review 025 B).

Decision: when the newest bundle holds a floor, `team-state` counts only if it opens under that bundle's `teamStateKey`. One that opens only under an older bundle's key is absent (D-62), and the anchor advance replaces it once the newest bundle is in the tip's roster. Writers already write under the newest bundle's key. The vault's clean-up (§6.8 step 4) no longer rewrites `team-state`; the next advance does. For keys with no floor, `team-state` is a root and every held bundle still opens it.

Rejected:
- The re-key writing `team-state` under the new keys (review 026 A, C, D): the server replays the archived forged revision, a holder of the old key with a session rewrites it, a failed write is silent, and the write could move an anchor back.
- A support step in the remedy: a documented procedure would leave the user compromised until someone acts.

Consequence: after a re-key, a `team-state` under the old keys stops nothing, whoever wrote or replayed it; the owner's own `reconcile` approves and the next open replaces it. Contexts never take turns: while a re-key is pending, a context holding only the old keys may write under them, which contexts holding the new keys ignore; after approval the old keys aren't in the roster and never write. Accepted: while a re-key is pending, a `team-state` under the old keys neither bounds rollback nor shows a split view to contexts with the new keys; the floor (D-50) and the local anchor still bound them. A server withholding the newest wrap chooses the older keys, and can replay a forged `team-state` written under them: availability only, like TH-28, since the floor and the vault's anchor still bound the chain (review 028 B). A forged record under the newest keys still fails with `state_conflict` or `rollback` (D-52).

## D-64: `reconcile` approves only keys still the newest, and rotates with the rest

Status: Accepted; its report and rotation narrowed by review 033.

Problem: `reconcile` plans the approvals of proven re-keys and the removals of inactive holders in one rotation. At apply time, keys that are no longer the account's newest are refused (`STALE_VERSION`, D-55), and `reconcile` retried once, then failed. A member publishing a newer proven re-key between the snapshot and the apply, twice, kept every removal from happening (SP-22, TH-14) (review 032 B).

Decision: at apply time, `reconcile` drops an approval whose keys are no longer the account's newest: that account receives the new version with the keys it holds, and isn't listed in `approvedRekeys`. The removals and the other approvals go ahead; if none is left, it doesn't rotate. The account's newer keys are classified by the next overview and `reconcile` like any others (`rekeys-awaiting-approval`, `rekey-unproven`, `owner-rekey`). `approve`, called with a person's handles, still refuses `STALE_VERSION`: a person reviewed exactly those keys. Another record for a reviewed version still stops it (`TRUST_FAILURE`, D-55).

Rejected:
- Retrying until the keys settle: a member publishing continuously keeps it failing.
- Two rotations, removals then approvals: twice the versions at every `reconcile`.
- A new `needsHuman` reason for the dropped approval (review 033 4): public API for nothing a person must do, and its advice ("handled next time") would wave away bait keys the next run reports anyway.

Consequence: a member can delay its own approval by publishing, as TH-47 already accepts, but no longer anyone else's removal, and never its own access to the version.

## D-65: A listed owner steps down before leaving

Status: Accepted.

Problem: `leaveTeam` refused only the sole listed owner. With two listed owners, one left, then the other: the owner list still named both, nobody held keys, and the team was frozen for good (TH-18, SP-16, review 032 C).

Decision: `leaveTeam` refuses any account in the newest version's owner list, with `LAST_OWNER`. An owner steps down first, by `setOwners` without itself, which any owner may call, itself included; `setOwners` keeps at least one owner, so the only owner can never step down or leave.

Rejected:
- Counting owners who still hold keys: nothing in the chain says who deleted their wraps.
- `leaveTeam` stepping down by itself: a leave would write a team key version, with the owner's signing key, and change the owner list without a separate act.

Consequence: an owner who leaves takes one more step; the integration's owner-leave flow calls `setOwners` first, and its own removal of an account refuses a listed owner the same way. `LAST_OWNER` now means "a listed owner". An owner whose team doesn't open can't step down itself; another owner removes it (`setOwners`). Not covered (review 033 2): an account that left and is named owner again by another owner; a server serving a chain from before the account became owner, to a device that hasn't opened the team since (availability only, as withholding); a session deleting an owner's wraps directly (TH-46). Another owner can name a leaving owner again after each step-down; the product's removal is then the way out.
