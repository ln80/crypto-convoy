# Scope

> Status: draft, under review.

## Role

Answers: **what is this library responsible for, and what is left to the application that uses it?**

Every other document builds on this boundary. A threat outside the library's scope is listed in [threat-model.md](threat-model.md) as the application's responsibility, not mitigated by the library.

## Audience

Anyone deciding whether to use the library, integrating it, or reviewing it.

## What the library is

crypto-convoy is a TypeScript library for end-to-end encrypted (E2EE) team storage. A team shares encrypted items through a server that it doesn't trust with their contents. The library manages keys and does the cryptography; the integration stores the content (D-25). The library:

- creates and protects each user's keys;
- shares a team key among members without the server being able to read it or swap it;
- encrypts and decrypts the team's items;
- lets people outside the team send encrypted submissions to it.

The library knows nothing about the product that uses it. It has no UI, no network code, and no framework dependency.

## Vocabulary

These terms are used the same way in every document.

| Term | Meaning |
| --- | --- |
| **Account** | One person using the library. Holds keys that work across all their teams. |
| **Account key** | The key at the top of an account. It protects the account's keys for each team. It can be rotated. |
| **Unlock method** | A way to open the account key: a PIN, a recovery phrase, or a registered device. |
| **Device** | One browser profile or app install where an account has been unlocked and registered. |
| **Team** | A group of accounts sharing encrypted items. |
| **Member** | An account admitted to a team. Each member has its own key pair for that team (member keys). |
| **Owner** | A member allowed to admit members, rotate the team key, and change the owner list. A team has one or more owners, all with equal powers. |
| **Team key** | The symmetric key that protects a team's items. It has numbered versions; each rotation creates a new one. Each version can open the version before it, so a member given the current version can reach every earlier one (D-07). |
| **Team key chain** | The signed records of a team's key versions. Each lists the owners for that version and links to the previous record, so the chain is also the history of the owner list (D-19). |
| **Roster** | The list, inside a team key version record signed by an owner, of the members receiving that version, each with the version sealed to their keys. The only way to hold a version (D-37). |
| **Item** | A piece of content the team stores, made of one or more parts (for example a text and some files). Each item has its own random item key, stored wrapped by the team key. Items never change: new content is a new item. |
| **Link share** | Giving someone outside the team an item's key, usually inside a URL fragment, so they can decrypt that item and nothing else. |
| **Inbox** | A key pair that lets outside senders encrypt submissions that only the team can open. The public key is given to senders; the private key is stored wrapped by the team key. |
| **Record** | Any piece of data the library asks the server to store: wrapped keys, signed statements, ciphertexts. |
| **Server** | Whatever stores and returns records. Not trusted for confidentiality or for the authenticity of keys. |
| **Integration** | The application code that connects the library to a product: UI, network, sign-in, roles, storage choices. |

## What the library does

1. **Account keys.** Creates the account key and wraps it for each unlock method: PIN, recovery phrase (confirmed by the user before any team work, D-35), registered devices. Supports changing the PIN, replacing the recovery phrase, registering and revoking devices, rotating the account key, and securing a compromised account in one operation (D-36).
2. **PIN hardening.** Turns a short PIN into a strong key with a server-assisted OPRF (oblivious pseudorandom function), so a stolen backup can't be brute-forced offline. The library implements the client side and specifies what the server must do.
3. **Team trust.** Verifies each team's key chain, including who the owners are at each version, and remembers the last record it verified (its anchor), so it detects a forged or rolled-back chain.
4. **Team key distribution.** Seals each team key version only to member keys an owner approved, and opens a team key only from a record an owner signed for this member's own keys. The recovery phrase proves a member's re-key (D-33), so owners can approve it without an out-of-band check; every other approval is a human's.
5. **Team key lifecycle.** Creates and rotates team key versions (one signed record listing who receives the version; every join, re-key and removal is a rotation, D-34, D-37), and opens earlier versions through the chain of versions. An owner autopilot, `reconcile`, does what needs no human judgement and only ever narrows access by itself (D-31).
6. **Item encryption.** Encrypts items part by part, as drafts sealed last (D-27), including large files as a stream of chunks. Each item's key record lists its parts, so the server can't modify, swap, drop or reorder them undetected (D-16). Opens an item's parts one at a time, on demand. The application gets ciphertext to store and plaintext back; it never handles content keys (D-15). It can get a keyed reference for each part, safe to send to its server (D-28).
7. **Inboxes and link shares.** Creates inboxes, seals outside submissions to them, opens them for members, and encodes and decodes the keys carried in links.
8. **Status and warnings.** Reports whether the account is set up, unlocked and has recovery, each team's access state, and, for owners, an overview of each member's access, its proof, and what needs a human: members awaiting approval, unproven re-keys, a team with a single owner (§12, SP-15).
9. **Formats.** Defines versioned record formats and canonical encodings, and refuses unknown versions and algorithms. Ships frozen test vectors so other implementations can check their compatibility.

Not in v1: author signatures on items (D-09) and key fingerprints for out-of-band verification (D-11).

## What the integration does

The library doesn't do any of the following. The integration owns them:

- **UI:** PIN and recovery dialogs, warnings, notices. A UI framework binding (React or other) can be a separate package; the core never depends on one.
- **Network and sign-in:** HTTP, tokens, sessions, retries. The library never sees an auth token.
- **Who belongs to the team, and who should be an owner:** invitations, roles, removal, and which accounts hold the cryptographic owner role, which needn't match a product role (D-30). The library enforces only the cryptographic rules: who signed what.
- **Content storage and its pipeline** (D-25): storing and serving item parts, submission envelopes and submission parts; upload sessions, retries and quotas; not presenting an item until its key record is stored; cleaning up parts of drafts never sealed (D-27). Checks on files before encryption (type, size, content sniffing) and deduplication are the integration's too, with `partRef` as the reference it may send (D-28).
- **Policy:** PIN length and strength rules, PIN hashing cost (above the library's floor, D-17), rate-limit numbers, the list of active accounts it gives `reconcile` at each owner session (D-31) inbox lifetimes and when to replace an inbox, the largest part the buffered API accepts (`maxBufferedSize`), device inactivity period, the restore window for removed wraps, and when to offer `secureAccount` after a lost device or leaked credential (D-36). The library takes these as parameters or exposes the operation; the integration decides when to call it.
- **Isolating key custody:** where the account key lives (iframe, web worker, separate origin, native process), the channel between contexts, and which context may receive which team's keys. See [Key custody](#key-custody).
- **Delivering links:** carrying link-share keys, inbox public keys and invite links (which carry the team's anchor) to the people who use them.
- **Protecting share links** (D-22). A share link is the key to its item. On the page that opens it:
  - read the key from the fragment and remove it at once (`takeLinkKey()` does both in a browser);
  - load no third-party scripts, analytics or error tracking, and never log the page address;
  - set a strict Content Security Policy and `Referrer-Policy: no-referrer`;
  - reveal only after an explicit click, so link scanners don't trigger or use up views;
  - avoid sending share links from the integration's own server, which would then see the key (TH-23).
- **Devices and accounts:** ending a revoked device's sign-in sessions; refusing to delete an account that is a listed owner of a team (D-65); authenticating restore requests to its support process, which bring back whatever the restored records open (TH-48).
- **What parts mean:** text formats, file types, form fields. The integration can store such details in each part's opaque `meta`, which the library encrypts and authenticates without reading (D-16).
- **What it sends to its own server:** values the integration computes from plaintext (for example file hashes or file names sent in clear) leak content. The library never produces them; the integration must not either.
- **Presenting timestamps:** record timestamps are chosen by their writer; the integration must not show them as a trusted time (TH-35).
- **Code delivery:** making sure users run the expected code (reproducible builds, published hashes).
- **Server side:** storing key records and enforcing the [server contract](#server-contract); serving a shared item's key record to the people the integration lets open its link, by whatever route it chooses.
- **Product events:** audit logs, notifications, cleanup jobs, billing.
- **Migrating existing data:** moving data from an older encryption scheme to this protocol is the integration's job (D-01).

## Interfaces the integration provides

The library reaches the outside world only through these interfaces. An integration implements each one.

| Interface | Job |
| --- | --- |
| `RecordStore` | Fetch and publish key records (D-25). The integration adds authentication and maps calls to its API. |
| `OprfService` | Send a blinded PIN value to the server and return the server's evaluation and its proof, which the library checks against the public keys the integration pins in its client code (D-53). |
| `LocalKeyStore` | Keep, on this device, the device key, the highest account key version and the vault's own anchor per team (used by the vault, D-54), and each team's anchor, the last team key version record verified (used by team sessions). In a split layout, each context keeps its own half. |
| `Clock` | Current time, for record timestamps. |

Randomness is not an interface: the library always uses the platform's cryptographically secure random generator (through libsodium).

An optional browser adapter, `crypto-convoy/browser`, implements `LocalKeyStore` with IndexedDB and a non-extractable WebCrypto key (D-08), and offers `takeLinkKey()`, which reads a key from the URL fragment, validates it and removes it from the address bar and history (D-22). It ships with the library but outside the core, which stays platform-neutral (browser, Node, workers).

A testing kit, `crypto-convoy/testing`, provides an in-memory `RecordStore` that applies every server rule of protocol §11 (key records only), a fake OPRF server, an in-memory `LocalKeyStore` and a fixed clock (D-24). The exact contracts of the four interfaces are in protocol §12.

## Key custody

The API splits key custody into two roles (D-03):

- **Account vault.** Holds the account key, and does only what needs it: setup, unlock (device, PIN, recovery phrase), registering and revoking devices, changing credentials, rotating the account key, and creating, wrapping and deleting member keys (creating or joining a team, re-keying, leaving). Hands a team session only that team's member keys.
- **Team session.** Does team work with one team's member keys: verifying the chain, rotations (approvals, removals), owner changes, and all content encryption and decryption. Never receives the account key or another team's keys.

The integration decides how far apart these two run:

- **One context.** The vault opens a team session directly (`openTeam(teamId)`). The API split stays, but script injection in the page reaches every key the account holds.
- **Separate contexts.** For example, the vault in an iframe on its own origin and team sessions in the product's pages. The team's context creates an ephemeral **receiver**; the vault exports one team's member keys **sealed** to it; only that receiver opens them, once (§3.8, D-29). The integration carries these opaque values over its own channel (for example `postMessage`) and decides which context may receive which team. That channel and that decision are integration code: the library supplies the sealing, never the bridge (D-02).

## Server contract

The library verifies everything it can on its own: signatures, the team key chain and its owners, authenticated encryption, versions. It never relies on the server for confidentiality or for the authenticity of keys. Some things only a server can do, though. A conforming server must:

1. **Authenticate callers** and serve an account's private records (account key wraps, member key wraps) only to that account.
2. **Keep the OPRF key secret, build each evaluation's `info` from the account it charges (never from the request), prove every evaluation, and rate-limit PIN evaluations** with **one total budget per account**, whatever purpose a call declares: every evaluation is a usable PIN guess. Proof nonces come from a CSPRNG, and no per-account tweaked key is ever exported: either reveals the key of every account (D-53). This is the only thing standing between a stolen backup and a short PIN.
3. **Store a record only under the key its identity fields name, and never overwrite write-once records:** team key versions, member key records, `item` and `inbox` records. A rotation re-wraps member keys wraps without fetching their published records, which relies on the first part (D-58). A client's `delete` applies only to its own account's private records (rule 7); a record the integration removes on its own keeps its identity used, so nobody can write it again. Otherwise one member could delete and re-create an item, or any account delete the records a team verifies (TH-50, TH-46).
4. Removed before release (D-66): no record changes in place by revision any more. The number is kept so references stay stable.
5. **Apply atomic batches** where the protocol requires them: team creation, the switch to a new account key version. Create a member keys wrap only in the batch that creates its `member-keys` record, or in a batch that switches the account key version, and an account key wrap only at the version current once its batch applies, so a session can't take an identity the account will need (D-58).
6. **Accept new `item` and `inbox` records only at the current team key version**, and a new team key version only as current + 1.
7. **Never destroy an account's private records; archive them:** account key wraps and member keys wraps. Revoking a device, replacing a PIN or a recovery phrase, replacing or deleting a member keys wrap, and retiring an account key version stop serving the record it replaces or removes, and keep it.
   - A replaced record stops being served as soon as its replacement is stored. A removed one (a revoked device) stops being served after a short delay at most; until then, the old credential still works.
   - It keeps them in an **archive** for a **restore window** set by the integration, and restores them only through the integration's own support process. Someone holding the user's session could otherwise replace every wrap with garbage and destroy the account (TH-36, TH-46). Each identity has at most one live record; restoring brings back a chosen archived record and archives the live one (D-39).
   - Support may also restore an **account key version**: it becomes current again, the records of later versions are archived, and its own records are served again (D-42). That undoes a takeover by someone who held a credential and rotated (TH-11).
   - The integration may also have the server stop serving a device wrap that hasn't been used for a set period; the device then registers again with the PIN or the recovery phrase.
8. **Check that signed changes come from people allowed to make them:** the signer of a new team key version is the caller and holds the capability the integration maps to the cryptographic owner role (D-30); a `member-keys` record is written only by its account, at its next version (D-43). This is defence in depth: clients check the signatures regardless. The owners a version lists aren't checked: an owner demoted in the product stays in the list until an owner change, and clients report every change to the list (SP-15).

The contract covers key records only. Content (item parts, submissions) is the integration's (D-25): keeping it write-once and serving an item's parts only once its key record exists is recommended, not relied on, since every part is checked against its key record.

A server that breaks these rules can deny service or weaken PIN protection. It still can't read items or plant keys without clients detecting it, except where [threat-model.md](threat-model.md) records an accepted risk.

## Non-goals

- Protecting metadata: who is in a team, how many items exist, their sizes and timing.
- Protecting against a compromised device or browser at the moment of use (malware, malicious extensions).
- Guaranteeing that the server delivers honest code. This is the integration's responsibility.
- Real-time messaging semantics (per-message forward secrecy, as in Signal or MLS). The library protects stored items.
- Separate encryption boundaries inside a team. All items of a team share its team key.
- Post-quantum security in v1. Records name their algorithms, so a later suite can add it (TH-32).
