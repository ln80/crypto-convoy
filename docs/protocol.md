# Protocol

> Status: draft, under review. Protocol version 1, suite `cc1`.

## Role

Answers: **how does the cryptographic system work?**

Specifies algorithms, encodings, records and operations precisely enough that a compatible implementation can be written in another language from this document and the test vectors alone. [key-hierarchy.md](key-hierarchy.md) explains *why* each key exists; this document says *exactly how* it is used. Terms are defined in [scope.md](scope.md#vocabulary).

## Audience

Cryptography implementers, protocol reviewers, external contributors.

## Contents

1. [Conventions](#1-conventions)
2. [Algorithm suite `cc1`](#2-algorithm-suite-cc1)
3. [Building blocks](#3-building-blocks)
4. [Records](#4-records)
5. [Account operations](#5-account-operations)
6. [Team operations](#6-team-operations)
7. [Content operations](#7-content-operations)
8. [Verification order](#8-verification-order)
9. [Team access states and errors](#9-team-access-states-and-errors)
10. [Versioning](#10-versioning)
11. [Server rules per record](#11-server-rules-per-record)
12. [API shape (informative)](#12-api-shape-informative)
13. [Test vectors](#13-test-vectors)
14. [Open points](#14-open-points)

---

## 1. Conventions

How values are written down, so two implementations produce the same bytes.

### Identifiers

| Id | Chosen by | Form |
| --- | --- | --- |
| `accountId`, `teamId`, `itemId`, `inboxId` | The integration | Opaque UTF-8 string, 1–128 bytes, no NUL. Unique in its scope (`itemId` and `inboxId` within a team). |
| `deviceId` | The library, at registration | 16 random bytes, base64url without padding. |
| `submissionId` | The library, on the sender's side | 16 random bytes, base64url without padding. |
| Part `index` | The library | Position of a part in its item or submission, from 0. |

The library never interprets an id; it only binds ids into signatures and associated data so a record can't be moved.

### Canonical encoding

Every value that is signed, hashed or used as associated data is first encoded with this canonical binary encoding. It has no optional whitespace, no field names and no reordering, so the same input always gives the same bytes.

| Type | Encoding |
| --- | --- |
| `u8` | 1 byte. |
| `u32` | 4 bytes, big-endian. |
| `u64` | 8 bytes, big-endian. |
| `bytes` | `u32` length, then the raw bytes. |
| `string` | `bytes` of its UTF-8 encoding. |
| `list<T>` | `u32` count, then each element encoded as `T`. |
| `optional<T>` | `u8 0` if absent; `u8 1` then `T` if present. |

`enc(a, b, c, …)` means the concatenation of each field's encoding, in order.

Every canonical payload starts with a **label**, a `string` naming its purpose. Labels keep a value made for one purpose from being accepted for another (domain separation).

Labels are written in this document by their short name, for example `"account-key-wrap"`. The bytes actually encoded are always the full label:

> `label(name)` = `"crypto-convoy/v1/"` followed by `name`, for example `crypto-convoy/v1/account-key-wrap`.

Every `wrap`, `seal`, `sign`, `stream` and key derivation below encodes `string label(name)` as its first field. There are no other forms.

| Short name | Used for |
| --- | --- |
| `pin-key` | Combining the Argon2id and OPRF outputs |
| `pin-oprf` | The server's per-account OPRF key derivation (§5.1) |
| `recovery-key` | Deriving the recovery key |
| `account-key-wrap` | Wrapping the account key for an unlock method |
| `member-keys` | Self-signature of a member keys record |
| `member-keys-continuity` | Optional signature by a member's current keys over their new keys (§4.2) |
| `member-keys-wrap` | Wrapping a member keys bundle |
| `team-state` | Wrapping a member's team state |
| `team-key-version` | Signing a team key version record (with its owner list) |
| `team-key-link` | Wrapping version n−1 under version n |
| `grant` | Signing a grant |
| `grant-seal` | Context inside a grant's sealed box |
| `item-key` | Wrapping an item key |
| `item-manifest` | Encrypting an item's manifest |
| `item-part` | Associated data of an item part's stream |
| `inbox-key` | Wrapping an inbox private key |
| `submission` | Context inside a submission envelope |
| `submission-part` | Associated data of a submission part's stream |

### Records on the wire

Records are JSON objects. Every record has:

- `v`: the record format version (1 here);
- `suite`: the algorithm suite (`"cc1"`);
- `type`: the record type.

Byte values are base64url **without** padding, everywhere: in records and in links. There is one encoding. Integers are JSON numbers (all fit in 53 bits). Item and submission parts are raw binary, not JSON.

Values carried in links (an item key, an inbox public key, an invite anchor) use the same encoding, after a one-character version prefix (§3.5).

Timestamps (`createdAt`) are Unix seconds from the writer's `Clock`. They are informative: authenticated where listed, so the server can't change them, but the writer chooses them freely. They are never used for a security decision, and an integration must not present them as a trusted time, for example as proof of when a submission was sent (TH-35).

---

## 2. Algorithm suite `cc1`

The fixed set of primitives used by every v1 record. All come from libsodium, except the OPRF (`@noble/curves`) and BIP-39 (`@scure/bip39`).

| Purpose | Primitive | Sizes |
| --- | --- | --- |
| Symmetric wrap | XChaCha20-Poly1305-IETF (`crypto_aead_xchacha20poly1305_ietf`) | key 32, nonce 24 (random), tag 16 |
| Seal to a public key | `crypto_box_seal` (X25519 + XSalsa20-Poly1305) | public key 32, overhead 48 |
| Signature | Ed25519 (`crypto_sign_detached`) | public key 32, seed 32, signature 64 |
| Hash | BLAKE2b-256 (`crypto_generichash`, 32-byte output; keyed where stated) | 32 |
| Content stream | `crypto_secretstream_xchacha20poly1305` | key 32, header 24, 17 bytes per chunk, 4 MiB (4,194,304 bytes) of plaintext per chunk |
| PIN hashing | Argon2id v1.3 (`crypto_pwhash`, `ALG_ARGON2ID13`) | salt 16, output 32 |
| PIN hardening | OPRF, RFC 9497, ciphersuite ristretto255-SHA512, base mode | output 64 |
| Recovery phrase | BIP-39, English word list, 128-bit entropy (12 words), seed by PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase | seed 64 |

Two rules every implementation must apply identically, because the team key chain depends on every client accepting exactly the same records:

- **Strict Ed25519 verification** (RFC 8032 with libsodium's checks): reject a signature whose `S` isn't canonical (S ≥ L), a public key that isn't a canonical encoding or has small order, and a signature whose `R` has small order. Some libraries (for example Go's `crypto/ed25519`) don't make all these checks by default; they must be added.
- **No low-order X25519 keys:** a published encryption public key or inbox public key that is a low-order point is refused (`MALFORMED_RECORD`). Sealing to one would give a shared secret known to anyone; libsodium already refuses it, and other implementations must too.

### Bounds the client enforces

The client checks these before any work, so a server can't weaken the PIN hashing or make the client run out of memory. The Argon2id values are integration settings (D-17), which can never go below the library's hard floor; the others are fixed by the protocol (D-18).

| Value | Writers use | Readers accept | Hard floor (library) |
| --- | --- | --- | --- |
| Argon2id `opslimit` | 3 (setting) | from the setting's minimum (default 3) to 10 | 2 |
| Argon2id `memlimit` | 256 MiB (setting) | from the setting's minimum (default 256 MiB) to 1 GiB | 64 MiB |
| Owners in a team key version | — | 1–64 | — |
| Parts in an item or submission | — | 1–128 |
| Id length | — | 1–128 bytes |
| `meta` per part | — | 0–4096 bytes |

---

## 3. Building blocks

Six constructions used everywhere. Each record and operation below is defined in terms of them.

### 3.1 `wrap` and `unwrap`

Encrypts a short secret (a key) under a symmetric key, bound to its context.

`wrap(key, name, context…, plaintext)`:

1. `nonce` = 24 random bytes.
2. `ad` = `enc(string label(name), context…)`.
3. `ciphertext` = XChaCha20-Poly1305-IETF encrypt(`plaintext`, `ad`, `nonce`, `key`).
4. Output `{ nonce, ciphertext }`.

`unwrap` checks that `nonce` is 24 bytes and `ciphertext` at least 16 bytes, rebuilds `ad`, and decrypts. Any failure is `DECRYPTION_FAILED`. How `ad` is rebuilt:

- **Ids and versions** (team, item, inbox, account, version numbers) come from what the caller expects: the record it asked for. They're never taken from the record alone, so a record moved elsewhere fails.
- **Informative fields** (`createdAt`, `createdBy`, `kdf`) come from the record itself. The decryption authenticates them: if the server changed one, it fails.

### 3.2 `seal` and `open`

Encrypts to someone's public key, bound to its context. The sender is anonymous.

`seal(publicKey, name, context…, body)` = `crypto_box_seal(enc(string label(name), context…, bytes body), publicKey)`.

`seal` refuses a low-order public key (§2). `open` runs `crypto_box_seal_open`, then parses the result. The label and every context field must equal the expected values (ids and versions, as in §3.1), and nothing may follow `body`. Any failure is `DECRYPTION_FAILED`. `crypto_box_seal` has no associated data input, which is why the context travels inside the box.

### 3.3 `sign` and `verify`

`sign(signingKey, name, fields…)` = Ed25519 detached signature over `enc(string label(name), fields…)`.

`verify` checks key and signature lengths first, then verifies strictly (§2). Any failure is `TRUST_FAILURE` (reason `bad_signature`).

### 3.4 `stream`

Encrypts content of any size in chunks, bound to its context.

`stream(key, name, context…, plaintext)`:

1. `ad` = `enc(string label(name), context…)`.
2. Initialise secretstream with `key`; it outputs a 24-byte `header`.
3. Split `plaintext` into chunks of 4 MiB. Every chunk except the last is exactly 4 MiB and is pushed with tag `MESSAGE`; the last chunk (0 to 4 MiB) is pushed with tag `FINAL`. An empty plaintext is one empty `FINAL` chunk.
4. Every chunk is pushed with the same `ad`.
5. Output `header ‖ chunk₀ ‖ chunk₁ ‖ …`.

The reader pulls chunks of 4 MiB + 17 bytes and fails with `DECRYPTION_FAILED` if:

- a chunk fails to authenticate;
- a `FINAL` tag appears before the end;
- the data ends without a `FINAL` tag;
- a non-final chunk is short;
- any tag other than `MESSAGE` or `FINAL` appears.

The **default API is buffered**: it returns the plaintext only after the `FINAL` chunk and every check of §8 have passed. It refuses, before downloading, any part whose `ciphertextSize` in the manifest exceeds `maxBufferedSize`, an integration setting, so a sender or member can't exhaust the reader's memory with an oversized part (TH-25). A **streaming API is opt-in**, for content too large to hold in memory: it delivers only authenticated chunks and ends with an error if the content is incomplete. Consumers of the streaming API must discard what they received when it does, for example by writing to a temporary file and keeping it only on success (SP-18).

The **ciphertext hash** of a stream is BLAKE2b-256 of its full output, header included.

### 3.5 Link values

Every value the library puts in a link starts with a one-character **format version**, `1` in v1, so a later format (for example a post-quantum inbox key) can never be confused with this one. Readers refuse any other prefix with `UNSUPPORTED_VERSION` (SP-17).

- `encodeLinkKey(32 bytes)` = `"1"` followed by the key in base64url without padding (44 characters). Used for item keys (§7.3) and inbox public keys (§7.4).
- `decodeLinkKey` accepts only `"1"` followed by input that decodes to exactly 32 bytes, and for an inbox public key, not a low-order point (§2); anything else is `MALFORMED_RECORD`.
- `encodeAnchor(version, recordHash)` = `"1"` followed by `enc(u32 version, bytes recordHash)` in base64url without padding. An **invite anchor** (§6.4) lets someone joining a team start from a chain position they received outside the server. `decodeAnchor` applies the same rules.

The integration places these values in the URL fragment (after `#`), which browsers don't send to servers.

In a browser, `takeLinkKey()` (from `crypto-convoy/browser`) reads the fragment, decodes it, and removes it from the address bar and history (`history.replaceState`), so the key doesn't linger where other scripts, extensions or history sync can read it (D-22).

### 3.6 Random values

Every key, nonce, id and salt comes from libsodium's `randombytes_buf`. There is no other source of randomness.

---

## 4. Records

Each record lists its fields, how it is protected, and what a reader checks. "Context" means the values bound into associated data or a signature. Field names follow one convention: a `wrap` output is called `wrapped…`, a `seal` output `sealed…`.

### Catalogue

| Record | Written by | Read by | Protected by | Server rule (§11) |
| --- | --- | --- | --- | --- |
| `account-key-wrap` | The account | The account | `wrap` under a PIN, recovery or device key | Write-once; deleted on revoke, replace, retire |
| `member-keys` | The member | Team members | Self-signature | Write-once |
| `member-keys-wrap` | The account | The account | `wrap` under the account key | Write-once; deleted with its account key version |
| `team-state` | The account | The account | `wrap` under the team state key | Compare-and-set |
| `team-key-version` | An owner | Team members | Owner signature, hash chain, `wrap` link | Write-once; current + 1; atomic with the signer's grant |
| `grant` | An owner | The member (and owners) | Owner signature, `seal` | Write-once; current version only |
| `item` | A member | Members, link holders | `wrap` under the team key and the item key | Write-once; current version only |
| Item part | A member | Members, link holders | `stream` under the item key | Write-once; after or with its `item` |
| `inbox` | A member | Members | `wrap` under the team key | Write-once; current version only |
| `submission` and its parts | An outside sender | Members | `seal` to the inbox key, `stream` | Write-once |

### 4.1 `account-key-wrap`

The account key, wrapped for one unlock method.

| Field | Type |
| --- | --- |
| `accountId` | string |
| `accountKeyVersion` | integer ≥ 1 |
| `method` | `"pin"`, `"recovery"` or `"device"` |
| `deviceId` | present only for `device` |
| `kdf` | present only for `pin`: `{ salt, opslimit, memlimit, oprfKeyId }` |
| `wrappedAccountKey` | `wrap` output |

Protection: `wrappedAccountKey = wrap(methodKey, "account-key-wrap", accountId, u32 accountKeyVersion, string method, optional<string> deviceId, kdfFields, accountKey)`. For `pin`, `kdfFields` = `bytes salt, u64 opslimit, u64 memlimit, u32 oprfKeyId`; for the others it is empty. `methodKey` is the `pinKey`, `recoveryKey` or `deviceKey`.

Reader checks: `kdf` within bounds (§2); `accountKeyVersion` not lower than the highest the device has seen (SP-07); the opened key is 32 bytes. For PIN and recovery, a failed `unwrap` is reported as `WRONG_CREDENTIAL`.

The server also tells the client which `accountKeyVersion` is current. The client never trusts a lower one than it has seen. A device with no stored state has seen none: a malicious server that kept a retired version's wraps can make it adopt that version, which the user's PIN still opens. That residual is accepted (TH-05, SP-19).

### 4.2 `member-keys`

A member's public keys for one team. Public.

| Field | Type |
| --- | --- |
| `teamId`, `accountId` | string |
| `memberKeysVersion` | integer ≥ 1, increases on each re-key |
| `signingPublicKey`, `encryptionPublicKey` | 32 bytes each |
| `createdAt` | integer |
| `signature` | 64 bytes |
| `continuitySignature` | 64 bytes, optional: only on a re-key, when the previous keys are still trusted |

Protection: `signature = sign(memberSigningKey, "member-keys", teamId, accountId, u32 memberKeysVersion, bytes signingPublicKey, bytes encryptionPublicKey, u64 createdAt)`.

On a routine re-key, the member also signs the new record with their **previous** signing key: `continuitySignature = sign(previousSigningKey, "member-keys-continuity", teamId, accountId, u32 memberKeysVersion, bytes signingPublicKey, bytes encryptionPublicKey)`.

Reader checks: `encryptionPublicKey` is not a low-order point (§2); the signature verifies with `signingPublicKey` (proof that both keys belong to the same holder). It proves nothing about who the member is; that comes from a grant (§4.6). If present, `continuitySignature` is checked against the signing key of the `member-keys` record with `memberKeysVersion` − 1; it is shown to the approving owner as a hint, never accepted as approval on its own (§6.8).

### 4.3 `member-keys-wrap`

A member's private keys for one team, wrapped by their account key. Private to the account.

| Field | Type |
| --- | --- |
| `accountId`, `teamId` | string |
| `memberKeysVersion`, `accountKeyVersion` | integer |
| `wrappedKeys` | `wrap` output |

Protection: `wrappedKeys = wrap(accountKey, "member-keys-wrap", accountId, teamId, u32 memberKeysVersion, u32 accountKeyVersion, bundle)`, where `bundle` = `signingSeed (32) ‖ encryptionSecretKey (32) ‖ teamStateKey (32)`.

Reader checks: the public keys computed from the bundle equal those in the `member-keys` record with the same `memberKeysVersion`; otherwise `TRUST_FAILURE` (reason `key_mismatch`).

### 4.4 `team-state`

What a member last accepted about a team, so their other devices start from it. Private to the account.

| Field | Type |
| --- | --- |
| `accountId`, `teamId` | string |
| `revision` | integer, increases on each write |
| `wrappedState` | `wrap` output |

Protection: `wrappedState = wrap(teamStateKey, "team-state", accountId, teamId, u64 revision, state)`, where `state` = `enc(u32 anchorVersion, bytes anchorHash)`: the newest team key version record this account has verified, and its record hash (§4.5).

The server can't forge a `team-state`, since it doesn't have `teamStateKey`. It can only serve an older revision. A `team-state` that fails to decrypt was corrupted or tampered with (for example by someone holding the account's session): it is a `TRUST_FAILURE` with reason `state_unreadable`, never silently ignored, since ignoring it would send the device back to first-contact trust. How the anchor is used is in §6.1.

### 4.5 `team-key-version`

Announces team key version n, names the team's owners for that version, and links it to version n−1. The records of a team form one hash chain: the team key chain, which is also the history of the owner list (D-07, D-19).

| Field | Type |
| --- | --- |
| `teamId` | string |
| `version` | integer n ≥ 1 |
| `prevHash` | 32 bytes: the record hash of version n−1; 32 zero bytes when n = 1 |
| `owners` | list of `{ accountId, signingPublicKey }`: the owners for version n, sorted by `accountId` (byte order), no duplicate `accountId`, 1–64 |
| `wrappedPreviousKey` | `wrap` output, or `null` when n = 1 |
| `signer` | `{ accountId, signingPublicKey }` |
| `createdAt` | integer |
| `signature` | 64 bytes |

Protection:
- `wrappedPreviousKey = wrap(teamKey_n, "team-key-link", teamId, u32 n, teamKey_{n−1})`.
- `payload = enc(string label("team-key-version"), teamId, u32 n, bytes prevHash, list<string accountId, bytes signingPublicKey> owners, optional<bytes> BLAKE2b-256(wrappedPreviousKey.nonce ‖ wrappedPreviousKey.ciphertext), string signer.accountId, bytes signer.signingPublicKey, u64 createdAt)`, and `signature` is the signer's Ed25519 signature over `payload`.
- The **record hash** is `BLAKE2b-256(payload)`. The signature isn't part of it, so the chain doesn't depend on how a signature is encoded.

Reader checks, for the chain from the client's anchor (or from version 1 at first contact) to the newest record:

1. Versions are consecutive: n, n+1, n+2, … with no gap.
2. **Version 1:** `prevHash` is all zeros, `wrappedPreviousKey` is `null`, and the signer is in its own `owners` list.
3. **Version n > 1:** `prevHash` equals the record hash of version n−1; `wrappedPreviousKey` is present; and the signer (same `accountId` **and** same key) is in the `owners` list of version n−1.
4. **Owners are real members:** for each owner, a valid `member-keys` record (§4.2) of that `accountId` has that `signingPublicKey`. Otherwise `TRUST_FAILURE` (reason `key_mismatch`). Owner changes reported to the integration (SP-15) therefore name the account the key belongs to.
5. The chain contains every anchor the client holds (§6.1). If a version holds a different record: `TRUST_FAILURE` (reason `chain_conflict`). If the chain stops before an anchor: `TRUST_FAILURE` (reason `rollback`).

These checks need no team key, so a `pending` member verifies the chain too. Opening `wrappedPreviousKey` with `teamKey_n` additionally confirms that `teamKey_n` is the key this record was made with.

**Owner rule.** A grant for version n is valid only if its signer is in the `owners` list of version n. A record for version n is valid only if its signer is in the `owners` list of version n−1. There's nothing else to compute: every owner change is a new version (§6.7), so the owner list of a version never changes after it's written.

### 4.6 `grant`

Gives one member one team key version. This is also how an owner approves a member's keys.

| Field | Type |
| --- | --- |
| `teamId`, `accountId` | string (the member) |
| `memberKeysVersion` | integer: which of the member's keys |
| `memberSigningPublicKey`, `memberEncryptionPublicKey` | 32 bytes each |
| `teamKeyVersion` | integer n |
| `sealedTeamKey` | bytes |
| `signer` | `{ accountId, signingPublicKey }` |
| `createdAt` | integer |
| `signature` | 64 bytes |

Protection:
- `sealedTeamKey = seal(memberEncryptionPublicKey, "grant-seal", teamId, accountId, u32 memberKeysVersion, u32 n, teamKey_n)`.
- `signature = sign(signerKey, "grant", teamId, accountId, u32 memberKeysVersion, bytes memberSigningPublicKey, bytes memberEncryptionPublicKey, u32 n, bytes BLAKE2b-256(sealedTeamKey), string signer.accountId, bytes signer.signingPublicKey, u64 createdAt)`.

Reader checks:
- the signature, and the owner rule: the signer is in the `owners` list of version n (§4.5);
- the member's public keys equal the reader's own keys (when opening for oneself) or the published `member-keys` record (when carrying the member forward in a rotation);
- the sealed box opens with the expected context, and the team key is 32 bytes.

### 4.7 `item`

An item's header: its key, wrapped by the team key, and its encrypted manifest.

| Field | Type |
| --- | --- |
| `teamId`, `itemId` | string |
| `teamKeyVersion` | integer n |
| `createdBy` | string (an `accountId`) |
| `createdAt` | integer |
| `wrappedManifest` | `wrap` output |
| `wrappedItemKey` | `wrap` output |

Protection:
- `wrappedManifest = wrap(itemKey, "item-manifest", teamId, itemId, list)`, where `list` = `enc(list<u32 index, u64 ciphertextSize, bytes ciphertextHash, bytes meta>)`.
- `wrappedItemKey = wrap(teamKey_n, "item-key", teamId, itemId, u32 n, string createdBy, u64 createdAt, bytes BLAKE2b-256(wrappedManifest.nonce ‖ wrappedManifest.ciphertext), itemKey)`.

The manifest is encrypted under the item key, not the team key, so a share link holder can read it too. `wrappedItemKey` binds the manifest, so a member also detects a swapped manifest. `createdBy` is integrity against the server only: any member could write any value (TH-15, D-09 deferred).

Reader checks: manifest indexes are 0, 1, … in order, with 1–128 parts; each `meta` is at most 4096 bytes.

### 4.8 Item part

One part of an item, as raw binary: `stream(itemKey, "item-part", teamId, itemId, u32 index, plaintext)`.

Reader checks: the ciphertext's size and hash equal the manifest entry for `index`, then the stream decrypts (§3.4).

### 4.9 `inbox`

An inbox's key pair: public key in clear, private key wrapped by the team key.

| Field | Type |
| --- | --- |
| `teamId`, `inboxId` | string |
| `teamKeyVersion` | integer n |
| `publicKey` | 32 bytes |
| `createdBy` | string |
| `createdAt` | integer |
| `wrappedSecretKey` | `wrap` output |

Protection: `wrappedSecretKey = wrap(teamKey_n, "inbox-key", teamId, inboxId, u32 n, bytes publicKey, string createdBy, u64 createdAt, inboxSecretKey)`.

Reader checks: `publicKey` is not a low-order point (§2); the X25519 public key computed from the opened secret key equals `publicKey`, otherwise `TRUST_FAILURE` (reason `key_mismatch`).

### 4.10 `submission`

A sealed submission to an inbox, and its parts.

| Field | Type |
| --- | --- |
| `teamId`, `inboxId` | string |
| `submissionId` | string |
| `sealedEnvelope` | bytes |

Protection:
- `sealedEnvelope = seal(inboxPublicKey, "submission", teamId, inboxId, submissionId, body)`, where `body` = `enc(bytes contentKey, u64 createdAt, list<u32 index, u64 ciphertextSize, bytes ciphertextHash, bytes meta>)`.
- Each part is `stream(contentKey, "submission-part", teamId, inboxId, submissionId, u32 index, plaintext)`.

Every submission uses a fresh `contentKey`, even a short text (D-14).

Reader checks: the envelope opens with the expected context; the manifest rules of §4.7; each part matches its size and hash, then decrypts.

---

## 5. Account operations

What the account vault does. Each step that can fail names its error.

### 5.1 Deriving the PIN key

1. Normalise the PIN to Unicode NFKC and encode it as UTF-8.
2. Check the `kdf` bounds (§2), else `MALFORMED_RECORD`.
3. `a` = Argon2id(PIN, `salt`, `opslimit`, `memlimit`), 32 bytes.
4. `(blind, blindedElement)` = OPRF `Blind(a)` (RFC 9497 §3.3.1).
5. `evaluatedElement` = `OprfService.evaluate(accountId, blindedElement, oprfKeyId, purpose)`, where `purpose` is `unlock` or `enroll`. This call is **never retried automatically**: each call spends one rate-limited attempt. A refusal is `PIN_RATE_LIMITED`.
6. `y` = OPRF `Finalize(a, blind, evaluatedElement)`, 64 bytes.
7. `pinKey` = keyed BLAKE2b-256(key = `a`, message = `enc(string label("pin-key"), accountId, bytes y)`).

Server side (SP-08):
- The server evaluates with a key specific to the account. A conforming derivation is RFC 9497 `DeriveKeyPair(seed, info)` with `info = enc(string label("pin-oprf"), u32 oprfKeyId, accountId)`. `oprfKeyId` lets the server replace its seed. The server keeps a retired key working for a transition period; PIN wraps made under it are upgraded on the next unlock (§5.4), so no user needs recovery because of a key change.
- `purpose` only lets the server split its limits. Both purposes produce the same `pinKey`, so **every** evaluation is a usable PIN guess: the server must enforce one **total** budget per account across both purposes ([server contract](scope.md#server-contract), rule 2).

### 5.2 Deriving the recovery key

1. Normalise the phrase as BIP-39 requires (NFKD) and check its checksum, else `WRONG_CREDENTIAL`.
2. `seed` = BIP-39 seed (64 bytes).
3. `recoveryKey` = keyed BLAKE2b-256(key = `seed`, message = `enc(string label("recovery-key"), accountId)`).

### 5.3 Setting up an account

1. Generate `accountKey` (version 1) and a 16-byte `salt`.
2. Derive the `pinKey` (§5.1, purpose `enroll`). Create the PIN `account-key-wrap`.
3. Generate a recovery phrase and derive the `recoveryKey` (§5.2). Create the recovery wrap. Return the phrase once, for the integration to show.
4. Register this device (§5.5).
5. Store the three wraps and set the current version to 1, atomically.

### 5.4 Unlocking

The account key opens only through one of these three paths (SP-19).

- **Same device.** Read the `deviceKey` and `deviceId` from `LocalKeyStore`, fetch that device's wrap at the current version, and unwrap. If the wrap is gone (revoked, or removed by a rotation), the device must register again: `DEVICE_NOT_REGISTERED`.
- **PIN.** Fetch the PIN wrap, derive the `pinKey` (purpose `unlock`), unwrap. Then register the device (§5.5).
  - **Upgrade on unlock:** if the wrap's Argon2id cost is below the current writer setting, or its `oprfKeyId` isn't the server's current one, derive a new `pinKey` from the same PIN (new salt, current settings, purpose `enroll`) and replace the PIN wrap (§5.6). The extra evaluation counts in the account's budget.
- **Recovery phrase.** Fetch the recovery wrap, derive the `recoveryKey`, unwrap. Then register the device (§5.5) and set a new PIN (§5.6). Unlocking with the phrase and registering the device need no server evaluation, so they work even when the PIN budget is used up; only setting the new PIN waits for it.

### 5.5 Registering and revoking a device

- **Register.** With the `accountKey` open: generate `deviceKey` and `deviceId`, keep both in `LocalKeyStore`, and store a device wrap at the current version. The wrap is fetched from the server at each unlock and never cached on the device.
- **List.** `listDevices()` returns the `deviceId` of every device wrap at the current version. Human-readable names and dates belong to the integration's own data.
- **Inactivity.** The server may stop serving a device wrap unused for a period set by the integration ([server contract](scope.md#server-contract), rule 7). The device then gets `DEVICE_NOT_REGISTERED` and registers again with the PIN, which limits how long a forgotten device stays able to unlock.
- **Revoke.** Ask the server to delete the device's wrap. From then on, the device can't unlock the account again (SP-10). That's the whole guarantee of revocation (D-21). The integration also ends that device's sign-in sessions, so it can't fetch other private records.

If the device may have been used by an attacker while unlocked, revocation isn't enough: they may have copied the account key and the member keys of every team the device opened. The remedy is the account key rotation (§5.7, SP-11) followed by a re-key in each affected team (§6.8, SP-12). The library offers both operations; the integration decides whether to guide users through them (TH-10).

### 5.6 Changing the PIN, replacing the recovery phrase

With the `accountKey` open, create the new wrap (a new `salt` for a PIN; a new phrase for recovery) and store it in place of the old one. The old credential keeps working until the server stops serving the old wrap, which it must do after a short delay ([server contract](scope.md#server-contract), rule 7; SP-09). The server keeps removed wraps for a restore window, so an account whose wraps were replaced with garbage by someone holding its session can be restored through the integration's support process (TH-36).

### 5.7 Rotating the account key (D-10)

1. Open the current `accountKey` (version a).
2. Derive the `pinKey` (purpose `enroll`). Either derive the `recoveryKey` from the current phrase, or generate a new phrase.
3. Generate `accountKey` version a+1.
4. For every team: unwrap the `member-keys-wrap` with version a, re-wrap it with version a+1.
5. Create the PIN, recovery and current-device wraps for version a+1.
6. Store everything and switch the current version to a+1, in one atomic batch.
7. The server deletes every record of version a. Other devices get `DEVICE_NOT_REGISTERED` on their next unlock.

Rotation retires the account key only. Member keys are unchanged, so anyone who already copied a member keys bundle keeps that team's access until the member re-keys in that team (§6.8) (SP-11).

### 5.8 Opening a team (vault → session)

1. The vault fetches the `member-keys-wrap` for `teamId` at the current account key version and unwraps it.
2. It checks the bundle against the `member-keys` record (§4.3).
3. It hands the bundle to the team session. The `accountKey` never leaves the vault (SP-02).

### 5.9 Creating member keys, leaving a team, deleting an account

Anything that wraps or unwraps a member keys bundle needs the `accountKey`, so it runs in the vault:

- **Create member keys** (when creating or joining a team, and when re-keying): generate the signing key, the encryption key and the `teamStateKey`; publish the `member-keys` record; store the `member-keys-wrap`. Then open the team (§5.8).
- **Leave a team:** delete this account's `member-keys-wrap` records and its `team-state` for the team. Refused with `LAST_OWNER` if the account is the only owner in the newest version of the team key chain: another owner must be added first (§6.7). The member's keys and grants stay valid for the history they already had; the remaining owners rotate without them in the keep list (§6.6).
- **Delete an account:** delete every record private to the account (§11). The integration must refuse while the account is the only owner of a team, for the same reason as above (TH-18).

---

## 6. Team operations

What a team session does.

### 6.1 Loading and verifying team state

Run when a team session starts, before any other team operation.

1. **Collect anchors.** An anchor is a (version, record hash) pair this account already verified. Read the local one (`LocalKeyStore`), the server's `team-state` (§4.4), and on a first join the invite anchor if the invite carried one (§6.4). All are authenticated or received outside the server: the server can serve an older `team-state`, but can't forge one, and one that fails to decrypt stops here with `TRUST_FAILURE` (`state_unreadable`). With no anchor at all, this is a first contact: the chain is accepted as the server presents it (TH-04).
2. **Verify the chain.** Fetch the team key version records from the lowest anchor (or from version 1 at first contact) to the newest, and check them (§4.5). The chain must contain **every** anchor. The client adopts nothing newer than its anchors before this check passes. This order matters: the anchor comes from what the client verified, never from the record it's about to check.
3. **Report owner changes.** For every record newer than the highest anchor whose owner list differs from the previous version, report to the integration the signer and the owners added or removed (SP-15).
4. The current version n is the newest record of the verified chain.
5. Fetch the newest grant for this member's keys. Check it (§4.6) and open it. For a granted version above 1, open its `wrappedPreviousKey` with the granted key.
6. Work out the access state (§9).
7. **Advance the anchor** to version n, locally and in the server's `team-state` (compare-and-set on `revision`). On conflict: reload the server's state, check that the chain contains it, then retry.

Any `TRUST_FAILURE` puts the team in the `unverified` state for this session.

### 6.2 Opening an earlier team key version

To open version m below the granted version n: for k = n down to m+1, unwrap `wrappedPreviousKey` of record k (already checked in §6.1) with `teamKey_k` to get `teamKey_{k−1}`. Opened versions are cached for the session.

### 6.3 Creating a team

1. The vault creates the creator's member keys (§5.9), `memberKeysVersion` 1.
2. Generate `teamKey_1`.
3. Create the version record for version 1 (owners: the creator; `prevHash` all zeros; no `wrappedPreviousKey`) and a grant of version 1 to the creator.
4. Store both in one atomic batch.
5. Save the anchor (§6.1 step 7).

### 6.4 Joining a team

1. The vault creates the member's keys for the team (§5.9). If the invite link carried an invite anchor (§3.5), it becomes the member's first anchor: the chain must contain it (§6.1), so a server can't present a forged team. An owner gets the anchor to put in an invite from `team.inviteAnchor()`.
2. The member is `pending` until an owner grants them (§6.5).

### 6.5 Granting a member (owner)

1. Fetch and check the member's `member-keys` record (§4.2).
2. The integration confirms the request is genuine (AS-06). The library reports the member's identity and keys.
3. Create and store a grant of the current version to those keys (§4.6).

Any member can list the grants of the current version, with who signed each one (`team.members()`), so a newly admitted member is visible to everyone (SP-15). This is detection, not prevention: a member admitted by a stolen owner key can read until someone notices and rotates.

### 6.6 Rotating the team key (owner)

1. Open the current version n. The caller must be in the `owners` list of version n.
2. Recipients: for each account the caller **keeps** (an explicit allowlist, normally the integration's active members) that holds a valid grant for version n (§4.6 checks), **one** set of keys: the newest `member-keys` record the account published, if an owner approves it in this rotation, otherwise the keys in its grant. Only grants for the **current** version count, so a grant for an older version is never carried forward, and an account's older keys never receive the new version. An account left out of the list loses access to the new version: forgetting someone costs them access, never leaks it. `team.needsRotation(activeAccountIds)` tells the integration when a granted account is no longer active, so it can rotate at the removal or at an owner's next session (TH-14).
3. Owners of version n+1: the same list as version n, unless the owner list changes (§6.7).
4. Generate `teamKey_{n+1}`. Create the version record n+1 (§4.5): `prevHash` = record hash of version n, `wrappedPreviousKey = wrap(teamKey_{n+1}, "team-key-link", …, teamKey_n)`, signed by the caller.
5. Store the version record and the caller's own grant for n+1 in one atomic batch. This makes n+1 current. If the server refuses because n is no longer current, stop with `STALE_VERSION`.
6. Grant n+1 to the other recipients.
7. **Resume:** if interrupted after step 5, run step 6 again for recipients still missing a grant for n+1. No new version is created.

### 6.7 Changing the owner list (owner)

Every owner change is a rotation (§6.6) whose new version carries the new owner list (D-13, D-19). There is no separate owner record.

1. Choose the new owner list. New owners must be members with a valid grant for version n; their signing keys come from their `member-keys` records.
2. Run the rotation (§6.6) with that list in version n+1. The version record, signed by an owner of version n, and the caller's grant are written in one atomic batch. An owner change is never half applied.
3. When an owner is removed: members whose newest grant was signed by the removed owner are listed for the caller to review before step 2 includes them. This is a **warning**, not a guarantee: a grant later signed by another owner no longer shows as coming from the removed owner (SP-15).

Adding an owner, removing an owner and replacing an owner's signing key (after a re-key) are all this one operation. Any single owner can run it, so a team with two or more owners never depends on one person (SP-16).

A removed owner isn't in the owner list of version n+1 or any later version, so their signatures are refused for all of them. They can still sign grants for versions up to n, whose keys they already hold; such grants are never carried forward (TH-33).

### 6.8 Re-keying a member

1. The vault creates new member keys for the team with `memberKeysVersion` + 1 (§5.9). The member stays able to read with the old keys until the rotation.
2. An owner checks the request is genuine and rotates the team key (§6.6), approving the new keys. If the new record carries a valid `continuitySignature` (§4.2), the library reports a routine re-key; without one, it reports that the keys were replaced without proof from the current keys, and the owner should verify out of band (AS-06, TH-37). Either way, the rotation is the approval: the new version is sealed to them, and the old keys receive nothing. That one rotation is the approval; a signature by the old keys is never accepted as approval, since an attacker may hold them (SP-12).
3. If the member is an owner, the same rotation replaces their signing key in the owner list (§6.7).

The new grant gives the member the current version, and the chain gives every earlier one, so no grant of an older version to the new keys is needed.

---

## 7. Content operations

What a team session (and, for links and inboxes, an outside client) does with content. The application passes plaintext and `meta` and gets plaintext and `meta` back; it never sees `itemKey`, `contentKey` or a team key (D-15).

### 7.1 Creating an item

Input: `itemId` and a list of parts, each with content and an optional `meta`.

1. Check the access state is `ready` (§9). Otherwise `NOT_GRANTED` or `STALE_VERSION`.
2. Generate `itemKey`.
3. For each part i: `stream(itemKey, "item-part", teamId, itemId, u32 i, content)`, then record its size and hash.
4. Build the manifest and the `item` record under the current version n (§4.7).
5. Return the record and the part ciphertexts. The integration must store the record **before or together with** the parts, so content never exists without its key.

### 7.2 Opening an item (member)

1. Fetch and check the `item` record (§8).
2. Open `teamKey_n` (§6.1, §6.2), unwrap `wrappedItemKey`, unwrap `wrappedManifest`.
3. For each part: check its manifest size against `maxBufferedSize` (§3.4), fetch, check size and hash, decrypt (§4.8).

### 7.3 Sharing an item by link

- **Create:** a member opens the item key (§7.2 steps 1–2) and gets `encodeLinkKey(itemKey)`. The integration builds the link with `teamId` and `itemId` in the path and the key in the fragment, and handles it with the share-link checklist ([scope.md](scope.md#what-the-integration-does), D-22). A link sent by the integration's server exposes the key to that server (TH-23).
- **Open:** the recipient's client decodes the key (§3.5; `takeLinkKey()` in a browser), fetches the `item` record and parts, unwraps `wrappedManifest` with the key, then checks and decrypts each part. The recipient can't check `createdBy` or the team key version; they get integrity of the content and manifest only.

### 7.4 Creating an inbox

1. Check the access state is `ready`.
2. Generate an X25519 key pair. Create the `inbox` record under the current version (§4.9).
3. Return the record and `encodeLinkKey(publicKey)`. The integration builds the link with `teamId` and `inboxId` in the path and the public key in the fragment.

**Replacing an inbox.** An inbox keeps its key pair for life, so a member removed later can still open submissions sent to it, if they also obtain the ciphertexts (TH-30, D-20). Replacing an inbox creates a new key pair under the current team key version, with a new link; the old link stops being usable for new submissions once the integration retires it. When to replace is the integration's decision.

### 7.5 Submitting to an inbox (sender)

1. Decode the public key from the link (§3.5).
2. Generate `submissionId` and `contentKey`.
3. Encrypt each part with `stream(contentKey, "submission-part", …)` and record its size and hash.
4. Seal the envelope (§4.10) to the public key **from the link** (SP-14).
5. Return the `submission` record and the parts for the integration to send.

If the integration's page fetches the inbox public key from its server instead of reading it from the link, the server chooses the key (TH-21).

### 7.6 Opening a submission (member)

1. Fetch the `inbox` record, open `teamKey_n`, unwrap the inbox secret key and check it against `publicKey` (§4.9).
2. Open the envelope with the expected context (§4.10).
3. For each part: check size and hash, decrypt.

---

## 8. Verification order

Every record is checked in this order. The first failure stops processing (fail closed).

1. **Shape:** a JSON object with the required fields and types; byte fields decode as base64url without padding, to the right length; nothing unknown. Else `MALFORMED_RECORD`.
2. **Version and suite:** `v` and `suite` are in the supported list. Else `UNSUPPORTED_VERSION` (SP-17).
3. **Context:** the ids in the record equal the ids the caller asked for (team, item, inbox, account). Else `TRUST_FAILURE` (reason `context_mismatch`).
4. **Signature and trust:** signatures, the owner rule, chain continuity and anchors. Else `TRUST_FAILURE`.
5. **Decryption:** `unwrap`, `open` and `stream` with the expected context. Else `DECRYPTION_FAILED`.
6. **Post-checks:** recomputed public keys match, sizes and hashes match the manifest. Else `TRUST_FAILURE` (reason `key_mismatch`) or `DECRYPTION_FAILED`.

No plaintext and no key is returned before every step has passed (SP-18).

---

## 9. Team access states and errors

### Access states

What a team session reports to the integration after loading (§6.1):

| State | Meaning | Can read | Can write |
| --- | --- | --- | --- |
| `not-joined` | This account has no member keys for the team. | No | No |
| `pending` | Member keys exist, but no grant for the current version yet. | Versions up to the newest grant | No |
| `ready` | A valid grant for the current version. | All versions | Yes |
| `unverified` | A trust check failed in this session. | No | No |

`unverified` never clears by itself within a session, and the library never retries automatically: it signals tampering or a bug, and the integration should surface it.

### Errors

| Code | Meaning | Retry? |
| --- | --- | --- |
| `MALFORMED_RECORD` | A record or link value has the wrong shape. | No |
| `UNSUPPORTED_VERSION` | Unknown `v` or `suite`: update the library. | No |
| `TRUST_FAILURE` | A signature, owner rule, chain or context check failed. Carries a `reason`: `bad_signature`, `not_an_owner`, `chain_conflict`, `rollback`, `state_unreadable`, `context_mismatch`, `key_mismatch`. | No |
| `DECRYPTION_FAILED` | Authenticated decryption failed: wrong key, tampered or truncated data. | No |
| `WRONG_CREDENTIAL` | The PIN or recovery phrase didn't open the account key. | Yes, by the user |
| `PIN_RATE_LIMITED` | The server refused another PIN evaluation. | Later, or use the recovery phrase |
| `DEVICE_NOT_REGISTERED` | This device has no current wrap (revoked or rotated). | After a PIN unlock |
| `NOT_GRANTED` | The member has no grant for the version required. | After an owner grants |
| `STALE_VERSION` | A write used a version that is no longer current. | After reloading team state |
| `LAST_OWNER` | The account is the only owner: it can't leave the team until another owner is added. | After adding an owner |
| `STORE_ERROR` | `RecordStore` or `OprfService` failed (network, server). | Yes, except PIN evaluations |

Error messages never contain keys, plaintext or record contents.

---

## 10. Versioning

How the protocol changes without breaking stored data.

- **Readers dispatch on what a record declares** (`v`, `suite`) and support a fixed list. **Writers always use the newest.**
- A released label, layout or field meaning **never changes**. A new layout is a new `v` for that record type, with its own frozen vectors.
- A new algorithm set is a new `suite` (for example one adding a post-quantum key exchange, TH-32). Seals use the recipient key's suite.
- Changes ship in **two releases**: first readers that understand the new format, then writers that produce it.
- Stored records stay readable as long as the data they protect exists.

---

## 11. Server rules per record

The [server contract](scope.md#server-contract) applied to each record.

| Record | Identity on the server | Rule |
| --- | --- | --- |
| `account-key-wrap` | account, version, method, deviceId | Write-once. Served only to the account. Removed on revocation, replacement, or retirement of the version, after a short delay at most: the server stops serving it, and keeps it for a restore window (rule 7). A device wrap may also stop being served after a period of inactivity. The switch of current version is atomic with the new wraps. |
| `member-keys` | team, account, memberKeysVersion | Write-once. Readable by the team's members. |
| `member-keys-wrap` | account, team, memberKeysVersion, accountKeyVersion | Write-once. Served only to the account. Deleted with its account key version. |
| `team-state` | account, team | Compare-and-set on `revision`. Served only to the account. |
| `team-key-version` | team, version | Write-once; version must be current + 1; stored atomically with its signer's grant, which makes it current. The signer and the listed owners must hold the matching role in the product (defence in depth). |
| `grant` | team, account, memberKeysVersion, teamKeyVersion | Write-once; `teamKeyVersion` must be current (defence in depth: grants of older versions serve no honest purpose, TH-33). |
| `item` | team, item | Write-once; `teamKeyVersion` must be current. |
| Item part | team, item, index | Write-once; accepted only after (or with) the `item` record. |
| `inbox` | team, inbox | Write-once; `teamKeyVersion` must be current. |
| `submission` and its parts | team, inbox, submission | Write-once. |
| Team creation | — | Version 1 and the creator's grant in one atomic batch. |
| OPRF evaluation | account | Per-account key. One total budget per account across `unlock` and `enroll`; the purposes may only split it. |

---

## 12. API shape (informative)

How the operations above surface to developers. Names are indicative; the exact TypeScript API is defined with the implementation.

```ts
// Account vault: holds the account key; anything that wraps member keys runs here.
vault.setup(pin)                          → { recoveryPhrase }
vault.unlock()                            // device; throws DEVICE_NOT_REGISTERED
vault.unlockWithPin(pin)                  // upgrades an outdated PIN wrap (§5.4)
vault.recover(phrase, newPin)
vault.changePin(newPin)
vault.replaceRecoveryPhrase()             → { recoveryPhrase }
vault.listDevices()                       → deviceId[]
vault.revokeDevice(deviceId)              // the device can't unlock again; see §5.5
vault.rotate({ pin, phrase? })            → { recoveryPhrase? }
vault.createTeam(teamId)                  → TeamSession   // creator is the first owner
vault.joinTeam(teamId, { anchor? })       → TeamSession   // "pending" until granted; anchor from the invite link
vault.rekey(teamId)                       → TeamSession   // new member keys; an owner approves them by rotating
vault.openTeam(teamId)                    → TeamSession
vault.leaveTeam(teamId)                   // throws LAST_OWNER for the only owner

// Team session: one team's keys.
team.state                                // "not-joined" | "pending" | "ready" | "unverified"
team.grant(accountId)
team.members()                            → grants of the current version, with signer
team.inviteAnchor()                       → string        // for an invite link's fragment
team.needsRotation(activeAccountIds)      → boolean
team.rotate({ keep, approveRekeys? })     // keep: accounts that receive the new version
team.setOwners(owners, { keep })          // always a rotation with the new owner list
team.createItem(itemId, parts)            → { record, parts }
team.openItem(itemId)                     → parts (plaintext + meta), buffered
team.openItemStream(itemId, index)        → authenticated chunks (opt-in)
team.shareLinkKey(itemId)                 → string
team.createInbox(inboxId)                 → { record, linkKey }
team.replaceInbox(inboxId, newInboxId)    → { record, linkKey }
team.openSubmission(inboxId, submissionId) → parts

// Outside the team: no account needed. teamId and itemId/inboxId come from the
// link's path, linkKey from its fragment (takeLinkKey() in a browser).
openSharedItem(linkKey, teamId, itemId)   → parts
submitToInbox(linkKey, teamId, inboxId, parts) → { record, parts }
```

The integration implements `RecordStore`, `OprfService`, `LocalKeyStore` and `Clock` ([scope.md](scope.md#interfaces-the-integration-provides)).

---

## 13. Test vectors

Frozen JSON files under `test/vectors/`, each with inputs (including fixed random values), intermediate values and outputs. A change to a released vector means stored data would break.

| File | Covers |
| --- | --- |
| `canonical.v1.json` | Every type of the canonical encoding |
| `wrap.v1.json` | `wrap` with each label, and tampering cases |
| `seal.v1.json` | `seal` with context, wrong-context cases, low-order public keys |
| `stream.v1.json` | Empty, one-chunk, exact-multiple and multi-chunk streams; truncation |
| `pin-key.v1.json` | Argon2id, the RFC 9497 vectors, and the final combination |
| `recovery-key.v1.json` | BIP-39 seed and recovery key |
| `team-key.v1.json` | Version records and their chain (owners, hashes, links), grants; forks, rollbacks, gaps, owner-rule cases (a removed owner signing a later version or grant), owner keys not matching `member-keys`, and strict Ed25519 edge cases (non-canonical `S`, small-order keys and `R`) |
| `item.v1.json` | `item` record, manifest, parts |
| `link.v1.json` | Link values: item keys, inbox public keys and invite anchors, with their version prefix; refused prefixes, lengths and low-order keys |
| `submission.v1.json` | Envelope and parts |

---

## 14. Open points

None: every decision this document relies on is accepted ([decisions.md](decisions.md)).

Later, not in v1:
- fingerprints for out-of-band verification (D-11, which would add verified keys to `team-state`);
- author signatures (D-09);
- signed rotating inbox keys, so links survive a member removal without the exposure of TH-30 (D-20).
