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
| `accountId`, `teamId`, `itemId`, `inboxId`, `submissionId` | The integration | Opaque UTF-8 string, 1–128 bytes, no NUL. Unique in its scope (`itemId` and `inboxId` within a team, `submissionId` within an inbox). It may be assigned by the integration's server after the first part is encrypted: ids are bound when a draft is sealed (D-26). |
| `deviceId` | The library, at registration | 16 random bytes, base64url without padding. |
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
| `recovery-signing-key` | Deriving the recovery signing key's seed (§5.2) |
| `recovery-public-key` | Wrapping the recovery public key under the account key (§4.1) |
| `account-key-wrap` | Wrapping the account key for an unlock method |
| `member-keys` | Self-signature of a member keys record |
| `member-keys-recovery` | Optional signature by the recovery key over a member's new keys (§4.2) |
| `member-keys-hash` | Hashing a member's public keys, as rosters pin them (§4.2) |
| `member-keys-wrap` | Wrapping a member keys bundle |
| `team-state` | Wrapping a member's team state |
| `team-key-version` | Signing a team key version record (with its owner list) |
| `team-key-link` | Wrapping version n−1 under version n |
| `roster-seal` | Context inside a roster entry's sealed box (§4.5) |
| `item-key` | Wrapping an item key |
| `item-manifest` | Encrypting an item's manifest |
| `item-part` | Associated data of an item part's stream |
| `inbox-key` | Wrapping an inbox private key |
| `submission` | Context inside a submission envelope |
| `submission-part` | Associated data of a submission part's stream |
| `part-ref` | Deriving the part reference key (§3.9) |
| `team-keys-transfer` | Context inside a sealed team key transfer (§3.8) |
| `local-device-key` | Browser adapter: associated data of a stored device key (§3.7) |
| `local-account-version` | Browser adapter: associated data of the stored account key version (§3.7) |
| `local-anchor` | Browser adapter: associated data of a stored team anchor (§3.7) |

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

- **Strict Ed25519 verification** (RFC 8032 with libsodium's checks). Before the signature equation, in this order:
  1. the public key is 32 bytes and the signature 64 bytes;
  2. `S` (the last 32 bytes of the signature, little-endian) is canonical: S < L, where L = 2^252 + 27742317777372353535851937790883648493;
  3. the public key is a valid point: a canonical encoding (y < p, p = 2^255 − 19), on the curve, of the prime-order subgroup, and not of small order (libsodium's `crypto_core_ed25519_is_valid_point`);
  4. `R` (the first 32 bytes) is not in the **small-order list** below.

  Some libraries (for example Go's `crypto/ed25519`) don't make all these checks by default; they must be added. The same public key check applies to every signing public key a record carries (`MALFORMED_RECORD` otherwise).
- **No low-order X25519 keys:** a published encryption public key or inbox public key in the **low-order list** below is refused (`MALFORMED_RECORD`). Sealing to one would give a shared secret known to anyone; libsodium already refuses it, and other implementations must too.

Both lists are compared with bit 255 (the top bit of the last byte) cleared, so each entry also covers its variant with that bit set. Values in hexadecimal, as encoded (little-endian):

| Ed25519 small-order list (`R`) | X25519 low-order list |
| --- | --- |
| `0000000000000000000000000000000000000000000000000000000000000000` | `0000000000000000000000000000000000000000000000000000000000000000` |
| `0100000000000000000000000000000000000000000000000000000000000000` | `0100000000000000000000000000000000000000000000000000000000000000` |
| `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05` | `e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800` |
| `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a` | `5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157` |
| `ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (p − 1) | `ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (p − 1) |
| `edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (p) | `edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (p) |
| `eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (p + 1) | `eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f` (p + 1) |

### Bounds the client enforces

The client checks these before any work, so a server can't weaken the PIN hashing or make the client run out of memory. The Argon2id values are integration settings (D-17), which can never go below the library's hard floor; the others are fixed by the protocol (D-18).

| Value | Writers use | Readers accept | Hard floor (library) |
| --- | --- | --- | --- |
| Argon2id `opslimit` | 3 (setting) | from the setting's minimum (default 3) to 10 | 2 |
| Argon2id `memlimit` | 256 MiB (setting) | from the setting's minimum (default 256 MiB) to 1 GiB | 64 MiB |
| Owners in a team key version | — | 1–64 | — |
| Accounts in a team key version's roster | — | 1–1,000 | — |
| A team key version record's JSON | at most 384 KiB (393,216 bytes) | — | — |
| Member key bundles in a transfer | — | 1–64 | — |
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
3. Split `plaintext` into chunks of 4 MiB. Every chunk except the last is exactly 4 MiB and is pushed with tag `MESSAGE`; the last chunk (0 to 4 MiB) is pushed with tag `FINAL`. The number of chunks is ⌈length / 4 MiB⌉, at least 1: an empty plaintext is one empty `FINAL` chunk, and a plaintext of exactly k × 4 MiB is k full chunks, the last one `FINAL` (no empty chunk after it).
4. Every chunk is pushed with the same `ad`.
5. Output `header ‖ chunk₀ ‖ chunk₁ ‖ …`.

The reader pulls chunks of 4 MiB + 17 bytes and fails with `DECRYPTION_FAILED` if:

- a chunk fails to authenticate;
- a `FINAL` tag appears before the end;
- the data ends without a `FINAL` tag;
- a non-final chunk is short;
- any tag other than `MESSAGE` or `FINAL` appears.

The **default API is buffered**: it returns the plaintext only after the `FINAL` chunk and every check of §8 have passed. It refuses with `MALFORMED_RECORD`, before downloading, any part whose `ciphertextSize` in the manifest exceeds `maxBufferedSize`, an integration setting, so a sender or member can't exhaust the reader's memory with an oversized part (TH-25). A **streaming API is opt-in**, for content too large to hold in memory: it delivers only authenticated chunks and ends with an error if the content is incomplete. Consumers of the streaming API must discard what they received when it does, for example by writing to a temporary file and keeping it only on success (SP-18).

The **ciphertext hash** of a stream is BLAKE2b-256 of its full output, header included.

### 3.5 Link values

Every value the library puts in a link starts with a one-character **format version**, `1` in v1, so a later format (for example a post-quantum inbox key) can never be confused with this one. Readers refuse any other prefix with `UNSUPPORTED_VERSION` (SP-17).

- `encodeLinkKey(32 bytes)` = `"1"` followed by the key in base64url without padding (44 characters). Used for item keys (§7.3) and inbox public keys (§7.4).
- `decodeLinkKey` accepts only `"1"` followed by input that decodes to exactly 32 bytes, and for an inbox public key, not a low-order point (§2); anything else is `MALFORMED_RECORD`.
- `encodeAnchor(version, recordHash)` = `"1"` followed by `enc(u32 version, bytes recordHash)` in base64url without padding. An **invite anchor** (§6.4) lets someone joining a team start from a chain position they received outside the server. `decodeAnchor` applies the same rules.

The integration places these values in the URL fragment (after `#`), which browsers don't send to servers.

In a browser, `takeLinkKey()` (from `crypto-convoy/browser`) reads the fragment, decodes it, and removes it from the address bar and history (`history.replaceState`), so the key doesn't linger where other scripts, extensions or history sync can read it (D-22).

### 3.6 Random values

Every key, nonce, id and salt comes from libsodium's `randombytes_buf`. There is no other source of randomness. This includes the two values drawn outside libsodium's own functions: the OPRF blinding scalar (the random generator handed to `Blind`, §5.1) and the 16 bytes of BIP-39 entropy behind a recovery phrase (§5.2).

### 3.7 Local storage (browser adapter)

The browser adapter (`crypto-convoy/browser`, D-08) keeps `LocalKeyStore` values in IndexedDB, encrypted with AES-256-GCM under a **local wrapping key**: a non-extractable WebCrypto key, generated once per browser profile and stored by structured clone, so its bytes can't be read or copied as a file. This is the only primitive not taken from the `cc1` suite: only WebCrypto can make a key non-extractable. The format is local to one device and never sent to a server.

Each value is stored as `iv (12 random bytes) ‖ AES-GCM(value, ad)`:

| Value | `ad` | Plaintext |
| --- | --- | --- |
| Device key | `enc(string label("local-device-key"), accountId)` | `enc(string deviceId, bytes deviceKey)` |
| Highest account key version seen | `enc(string label("local-account-version"), accountId)` | `enc(u32 accountKeyVersion)` |
| Team anchor | `enc(string label("local-anchor"), accountId, teamId)` | `enc(u32 version, bytes recordHash)` |

A value that fails to decrypt is an error, never silently discarded: discarding an anchor would send the device back to first-contact trust (SP-07).

### 3.8 Moving a team's keys between contexts

When the account vault and a team session run in separate contexts (D-29), one team's member keys move from the first to the second sealed to a receiver. A transfer is never stored.

1. **Receiver.** The receiving context creates a receiver for an expected `accountId` and `teamId`: an X25519 key pair from `randombytes_buf`, kept in memory. The **transfer request** is `"1"` followed by its public key in base64url without padding, as a link value (§3.5).
2. **Export.** The vault opens the account's member keys bundles for the team (§5.8) and returns the **transfer**: `"1"` followed by `seal(receiverPublicKey, "team-keys-transfer", accountId, teamId, body)` in base64url without padding, where `body` = `enc(list<u32 memberKeysVersion, bytes signingSeed, bytes encryptionSecretKey, bytes teamStateKey>)`, newest `memberKeysVersion` first, 1–64 entries. The vault refuses a request that isn't a valid link value or carries a low-order key (§2), with `MALFORMED_RECORD`.
3. **Open.** The receiver checks the prefix (else `UNSUPPORTED_VERSION`), opens the box with the expected `accountId` and `teamId` (§3.2; any failure, including a second use, is `DECRYPTION_FAILED`), then wipes its secret key: a receiver opens one transfer. It refuses a list out of order or with a key of the wrong size (`MALFORMED_RECORD`), and checks each bundle against the published `member-keys` record of its version (§4.3), else `TRUST_FAILURE` (`key_mismatch`).
4. **Anchor.** On a first open, the receiver takes the invite link's anchor (§6.4) and the session starts from it, exactly as in the vault's context (§6.1). The anchor is decoded before step 3: a malformed one (`MALFORMED_RECORD`, `UNSUPPORTED_VERSION`) leaves the receiver unused.

Which context may ask for which team, and the channel the two values travel on, are the integration's (D-29).

### 3.9 Part references

A keyed reference for a part's plaintext, which the integration may send to its server, for example to deduplicate or to name an attachment (D-28).

- `refKey` = keyed BLAKE2b-256(key = `contentKey`, message = `enc(string label("part-ref"))`), where `contentKey` is the item key or the submission's content key.
- `partRef(content)` = keyed BLAKE2b-256(key = `refKey`, message = `content`), in base64url without padding. The content is hashed as is, incrementally for a stream: the derived key separates this use from every other.

A reference is never stored by the library and never checked by readers: it's a convenience for the integration (SP-21).

---

## 4. Records

Each record lists its fields, how it is protected, and what a reader checks. Key records live in the key store behind `RecordStore`; item parts and submissions are content, which the integration stores (D-25). "Context" means the values bound into associated data or a signature. Field names follow one convention: a `wrap` output is called `wrapped…`, a `seal` output `sealed…`.

### Catalogue

| Record | Written by | Read by | Protected by | Server rule (§11) |
| --- | --- | --- | --- | --- |
| `account-key-wrap` | The account | The account | `wrap` under a PIN, recovery or device key | Write-once; deleted on revoke, replace, retire |
| `member-keys` | The member | Team members | Self-signature | Write-once |
| `member-keys-wrap` | The account | The account | `wrap` under the account key | Write-once; deleted with its account key version |
| `team-state` | The account | The account | `wrap` under the team state key | Compare-and-set |
| `team-key-version` | An owner | Team members | Owner signature, hash chain, `wrap` link, `seal` per roster entry | Write-once; current + 1 |
| `item` | A member | Members, link holders | `wrap` under the team key and the item key | Write-once; current version only |
| Item part (content) | A member | Members, link holders | `stream` under the item key | Stored by the integration (D-25) |
| `inbox` | A member | Members | `wrap` under the team key | Write-once; current version only |
| `submission` and its parts (content) | An outside sender | Members | `seal` to the inbox key, `stream` | Stored by the integration (D-25) |

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
| `wrappedRecoveryPublicKey` | present only for `recovery`: `wrap` output |

Protection: `wrappedAccountKey = wrap(methodKey, "account-key-wrap", accountId, u32 accountKeyVersion, string method, optional<string> deviceId, kdfFields, accountKey)`. For `pin`, `kdfFields` = `bytes salt, u64 opslimit, u64 memlimit, u32 oprfKeyId`; for the others it is empty. `methodKey` is the `pinKey`, `recoveryKey` or `deviceKey`.

For `recovery`, `wrappedRecoveryPublicKey = wrap(accountKey, "recovery-public-key", accountId, u32 accountKeyVersion, recoveryPublicKey)`: the recovery signing key's public half (§5.2), which a vault opened by the PIN or a device reads authenticated, without the phrase. A recovery wrap without it is `MALFORMED_RECORD`.

Reader checks: `kdf` within bounds (§2); `accountKeyVersion` not lower than the highest the device has seen (SP-07); the opened key is 32 bytes. For PIN and recovery, a failed `unwrap` is reported as `WRONG_CREDENTIAL`. `wrappedRecoveryPublicKey` opens with the account key to 32 bytes, a valid Ed25519 public key (§2), else `DECRYPTION_FAILED` or `MALFORMED_RECORD`; when the vault was opened with the phrase, it equals the key derived from it, else `TRUST_FAILURE` (`key_mismatch`).

The server also tells the client which `accountKeyVersion` is current. The client never trusts a lower one than it has seen. A device with no stored state has seen none: a malicious server that kept a retired version's wraps can make it adopt that version, which the user's PIN still opens. That residual is accepted (TH-05, SP-19).

### 4.2 `member-keys`

A member's public keys for one team. Public.

| Field | Type |
| --- | --- |
| `teamId`, `accountId` | string |
| `memberKeysVersion` | integer ≥ 1, increases on each re-key |
| `signingPublicKey`, `encryptionPublicKey` | 32 bytes each |
| `recoveryPublicKey` | 32 bytes: the account's recovery signing key (§5.2) |
| `createdAt` | integer |
| `signature` | 64 bytes |
| `recoverySignature` | 64 bytes, optional: only on a re-key, when the user entered the recovery phrase |

Protection: `signature = sign(memberSigningKey, "member-keys", teamId, accountId, u32 memberKeysVersion, bytes signingPublicKey, bytes encryptionPublicKey, bytes recoveryPublicKey, u64 createdAt)`.

The **keys hash**, which rosters pin, is `keysHash = BLAKE2b-256(enc(string label("member-keys-hash"), teamId, accountId, u32 memberKeysVersion, bytes signingPublicKey, bytes encryptionPublicKey, bytes recoveryPublicKey))`.

The proof on a re-key: `recoverySignature = sign(recoverySigningKey, "member-keys-recovery", keysPayload)`, where `keysPayload = enc(teamId, accountId, u32 memberKeysVersion, bytes signingPublicKey, bytes encryptionPublicKey, bytes recoveryPublicKey)`, by a recovery signing key (D-33). There is no other proof (D-38).

Reader checks:
- `encryptionPublicKey` is not a low-order point; `signingPublicKey` and `recoveryPublicKey` are valid Ed25519 public keys (§2); the signature verifies with `signingPublicKey` (proof that the keys belong to the same holder). It proves nothing about who the member is; that comes from an owner's approval (§4.5, §4.6).
- `recoverySignature`, if present, is checked against the `recoveryPublicKey` of the keys the account **holds** at the current version (its roster entry, §6.1). Only then is the re-key **proven** (§6.8, SP-23). A signature by another recovery key, including the one this record carries, proves nothing.
- A proof that doesn't verify is reported as absent; it never makes the record invalid. A record with no valid proof is approved only by a human (§6.8).

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
| `revision` | integer ≥ 1: 1 on the first write, then +1 on each write |
| `wrappedState` | `wrap` output |

Protection: `wrappedState = wrap(teamStateKey, "team-state", accountId, teamId, u64 revision, state)`, where `state` = `enc(u32 anchorVersion, bytes anchorHash)`: the newest team key version record this account has verified, and its record hash (§4.5).

The server has no `team-state` for an account until its first write; no record means no anchor on the server. The server can't forge a `team-state`, since it doesn't have `teamStateKey`. It can only serve an older revision. A `team-state` that fails to decrypt was corrupted or tampered with (for example by someone holding the account's session): it is a `TRUST_FAILURE` with reason `state_unreadable`, never silently ignored, since ignoring it would send the device back to first-contact trust. How the anchor is used is in §6.1.

### 4.5 `team-key-version`

Announces team key version n, names the team's owners for that version, and links it to version n−1. The records of a team form one hash chain: the team key chain, which is also the history of the owner list (D-07, D-19).

| Field | Type |
| --- | --- |
| `teamId` | string |
| `version` | integer n ≥ 1 |
| `prevHash` | 32 bytes: the record hash of version n−1; 32 zero bytes when n = 1 |
| `owners` | list of `{ accountId, signingPublicKey }`: the owners for version n, sorted by `accountId` (byte order), no duplicate `accountId`, 1–64 |
| `wrappedPreviousKey` | `wrap` output, or `null` when n = 1 |
| `roster` | list of `{ accountId, memberKeysVersion, keysHash, sealedTeamKey }`: the accounts receiving version n, sorted by `accountId` (byte order), no duplicate `accountId`, 1–1,000 |
| `signer` | `{ accountId, signingPublicKey }` |
| `createdAt` | integer |
| `signature` | 64 bytes |

Protection:
- `wrappedPreviousKey = wrap(teamKey_n, "team-key-link", teamId, u32 n, teamKey_{n−1})`.
- Each roster entry: `sealedTeamKey = seal(encryptionPublicKey, "roster-seal", u32 n, bytes keysHash, teamKey_n)`, to the keys whose `keysHash` (§4.2) the entry carries. `keysHash` binds the team, the account and its keys, so the context stays short: a roster entry is about 360 bytes of JSON with 36-byte ids.
- `payload = enc(string label("team-key-version"), teamId, u32 n, bytes prevHash, list<string accountId, bytes signingPublicKey> owners, list<string accountId, u32 memberKeysVersion, bytes keysHash, bytes sealedTeamKey> roster, optional<bytes> BLAKE2b-256(wrappedPreviousKey.nonce ‖ wrappedPreviousKey.ciphertext), string signer.accountId, bytes signer.signingPublicKey, u64 createdAt)`, and `signature` is the signer's Ed25519 signature over `payload`.
- The **record hash** is `BLAKE2b-256(payload)`. The signature isn't part of it, so the chain doesn't depend on how a signature is encoded.

Reader checks, for the chain from the client's anchor (or from version 1 at first contact) to the newest record:

1. Versions are consecutive: n, n+1, n+2, … with no gap.
2. **Version 1:** `prevHash` is all zeros, `wrappedPreviousKey` is `null`, and the signer is in its own `owners` list.
3. **Version n > 1:** `prevHash` equals the record hash of version n−1; `wrappedPreviousKey` is present; and the signer (same `accountId` **and** same key) is in the `owners` list of version n−1.
4. **Owners are real members:** for each owner, a valid `member-keys` record (§4.2) of that `accountId` has that `signingPublicKey`. Otherwise `TRUST_FAILURE` (reason `key_mismatch`). Owner changes reported to the integration (SP-15) therefore name the account the key belongs to.
5. **Owners hold the version:** every owner has a roster entry whose `keysHash` is that of the `member-keys` record holding the owner's `signingPublicKey`, and the signer has a roster entry (with any of its keys: a signer approving its own re-key signs with its previous key). Otherwise `TRUST_FAILURE` (reason `key_mismatch`).
6. The chain contains every anchor the client holds (§6.1). If a version holds a different record: `TRUST_FAILURE` (reason `chain_conflict`). If the chain stops before an anchor: `TRUST_FAILURE` (reason `rollback`).

These checks need no team key, so a `pending` member verifies the chain too. A roster entry is the only way to hold a version (D-37). A reader opening its own roster entry also checks that its `keysHash` is that of its own keys, else `TRUST_FAILURE` (`key_mismatch`), and opens `sealedTeamKey` with the expected context. Opening `wrappedPreviousKey` with `teamKey_n` additionally confirms that `teamKey_n` is the key this record was made with.

**Owner rule.** A record for version n is valid only if its signer is in the `owners` list of version n−1. There's nothing else to compute: every owner change is a new version (§6.7), so the owner list of a version never changes after it's written.

### 4.6 `grant`

Removed before release (D-37): a version is held only through the roster of its record (§4.5). The section number is kept so references stay stable.

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

One part of an item, as raw binary: `stream(itemKey, "item-part", u32 index, plaintext)`.

The part binds only its index: it is tied to its item by the item's own key and by the manifest, which lists its size and ciphertext hash; the item's ids are bound in the `item` record (D-26).

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
| `submissionId` | string, chosen by the integration (§1) |
| `sealedEnvelope` | bytes |

Protection:
- `sealedEnvelope = seal(inboxPublicKey, "submission", teamId, inboxId, submissionId, body)`, where `body` = `enc(bytes contentKey, u64 createdAt, list<u32 index, u64 ciphertextSize, bytes ciphertextHash, bytes meta>)`.
- Each part is `stream(contentKey, "submission-part", u32 index, plaintext)`. As for items, a part binds only its index; the envelope binds the ids and lists every part (D-26).

Every submission uses a fresh `contentKey`, even a short text (D-14).

Reader checks: the envelope opens with the expected context; the manifest rules of §4.7; each part matches its size and hash, then decrypts.

---

### 4.11 `invite`

Removed before release (D-32, deferred): an invite link carries only the team's anchor (§3.5, §6.4). The section number is kept so references stay stable.

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
4. The **recovery signing key** (D-33) is the Ed25519 key pair whose seed is keyed BLAKE2b-256(key = `seed`, message = `enc(string label("recovery-signing-key"), accountId)`). Its public half is `recoveryPublicKey`.

Both are derived when the user types the phrase, used for the one operation that needed them, and wiped. Neither is ever stored.

### 5.3 Setting up an account

1. Generate `accountKey` (version 1) and a 16-byte `salt`.
2. Derive the `pinKey` (§5.1, purpose `enroll`). Create the PIN `account-key-wrap`.
3. Register this device (§5.5).
4. Store the two wraps and set the current version to 1, atomically.
5. Set up recovery (§5.10). Until then the account can unlock with the PIN and its devices, but can't create or join a team (`RECOVERY_NOT_SET_UP`).

### 5.4 Unlocking

The account key opens only through one of these three paths (SP-19).

- **Same device.** Read the `deviceKey` and `deviceId` from `LocalKeyStore`, fetch that device's wrap at the current version, and unwrap. If the wrap is gone (revoked, or removed by a rotation), the device must register again: `DEVICE_NOT_REGISTERED`.
- **PIN.** Fetch the PIN wrap, derive the `pinKey` (purpose `unlock`), unwrap. Then register the device (§5.5).
  - **Upgrade on unlock:** if the wrap's Argon2id cost is below the current writer setting, or its `oprfKeyId` isn't the server's current one, derive a new `pinKey` from the same PIN (new salt, current settings, purpose `enroll`) and replace the PIN wrap (§5.6). The extra evaluation counts in the account's budget.
- **Recovery phrase.** Fetch the recovery wrap, derive the `recoveryKey`, unwrap; check `wrappedRecoveryPublicKey` against the phrase (§4.1). Then register the device (§5.5) and set a new PIN (§5.6). Unlocking with the phrase and registering the device need no server evaluation, so they work even when the PIN budget is used up; only setting the new PIN waits for it.

### 5.5 Registering and revoking a device

- **Register.** With the `accountKey` open: generate `deviceKey` and `deviceId`, keep both in `LocalKeyStore`, and store a device wrap at the current version. The wrap is fetched from the server at each unlock and never cached on the device.
- **List.** `listDevices()` returns the `deviceId` of every device wrap at the current version. Human-readable names and dates belong to the integration's own data.
- **Inactivity.** The server may stop serving a device wrap unused for a period set by the integration ([server contract](scope.md#server-contract), rule 7). The device then gets `DEVICE_NOT_REGISTERED` and registers again with the PIN, which limits how long a forgotten device stays able to unlock.
- **Revoke.** Ask the server to delete the device's wrap. From then on, the device can't unlock the account again (SP-10). That's the whole guarantee of revocation (D-21). The integration also ends that device's sign-in sessions, so it can't fetch other private records.

If the device may have been used by an attacker while unlocked, revocation isn't enough: they may have copied the account key and the member keys of every team the device opened. The remedy is the account key rotation (§5.7, SP-11) followed by a re-key in each affected team (§6.8, SP-12). The library offers both operations; the integration decides whether to guide users through them (TH-10).

### 5.6 Changing the PIN, replacing the recovery phrase

**PIN.** With the `accountKey` open, create the new wrap with a new `salt` and store it in place of the old one. The old credential keeps working until the server stops serving the old wrap, which it must do after a short delay ([server contract](scope.md#server-contract), rule 7; SP-09). The server keeps removed wraps for a restore window, so an account whose wraps were replaced with garbage by someone holding its session can be restored through the integration's support process (TH-36).

**Recovery phrase.** Set up a new phrase as in §5.10; its wrap replaces the old one, under the same rule. Then re-key every team the account has member keys for (§6.8), with the new `recoveryPublicKey`:
- if the user entered the **current** phrase, each re-key carries a `recoverySignature` by the current recovery key: proven, and approved by owners' `reconcile` unless the account is an owner of that team (SP-23);
- otherwise, the re-keys carry no proof, and an owner approves each by hand.

Each team is re-keyed in its own write. The operation reports the teams re-keyed and those that failed; a failed team is retried with the re-key of §6.8.

### 5.7 Rotating the account key (D-10)

1. Open the current `accountKey` (version a).
2. Derive the `pinKey` (purpose `enroll`) from the PIN the user enters (the current one or a new one). If the user enters the recovery phrase, derive the `recoveryKey` and recovery signing key, and check them against the current recovery wrap (§4.1), else `WRONG_CREDENTIAL`; with no recovery wrap, `RECOVERY_NOT_SET_UP`.
3. Generate `accountKey` version a+1.
4. For every team: unwrap the `member-keys-wrap` with version a, re-wrap it with version a+1.
5. Create the PIN and current-device wraps for version a+1, and the recovery wrap if the phrase was entered.
6. Store everything and switch the current version to a+1, in one atomic batch.
7. The server deletes every record of version a. Other devices get `DEVICE_NOT_REGISTERED` on their next unlock.

Without the phrase, version a+1 has no recovery wrap: recovery isn't set up (D-35), and setting up a new phrase re-keys every team as in §5.6.

Rotation retires the account key only. Member keys are unchanged, so anyone who already copied a member keys bundle keeps that team's access until the member re-keys in that team (§6.8) (SP-11). §5.11 does both.

### 5.8 Opening a team (vault → session)

1. The vault fetches the `member-keys-wrap` for `teamId` at the current account key version and unwraps it.
2. It checks the bundle against the `member-keys` record (§4.3).
3. It hands the bundle to the team session, directly in the same context, or as a sealed transfer to a receiver in another context (§3.8). The `accountKey` never leaves the vault (SP-02).

### 5.9 Creating member keys, leaving a team, deleting an account

Anything that wraps or unwraps a member keys bundle needs the `accountKey`, so it runs in the vault:

- **Create member keys** (when creating or joining a team, and when re-keying): requires recovery to be set up, else `RECOVERY_NOT_SET_UP`. Generate the signing key, the encryption key and the `teamStateKey`; publish the `member-keys` record with the account's `recoveryPublicKey`, read from the recovery wrap (§4.1), and a `recoverySignature` when the user entered the phrase (§4.2); store the `member-keys-wrap`. Then open the team (§5.8).
- **Leave a team:** delete this account's `member-keys-wrap` records and its `team-state` for the team. Refused with `LAST_OWNER` if the account is the only owner in the newest version of the team key chain, which the vault verifies first (§6.1 steps 1–2, no team key needed): another owner must be added first (§6.7). The member's keys stay valid for the history they already had; the remaining owners rotate without them in the keep list (§6.6).
- **Delete an account:** delete every record private to the account (§11). The integration must refuse while the account is the only owner of a team, for the same reason as above (TH-18).

### 5.10 Setting up recovery (D-35)

1. **Begin.** With the `accountKey` open, the vault generates a recovery phrase (§3.6) and keeps it in memory. It returns the phrase for the integration to show. Beginning again replaces the phrase held.
2. **Confirm.** The user enters the phrase. It must equal the one held, compared after Unicode NFKD normalisation with case and whitespace ignored, else `WRONG_CREDENTIAL`. Derive the `recoveryKey` and the recovery signing key (§5.2), create the recovery `account-key-wrap` with `wrappedRecoveryPublicKey`, and store it; the vault then forgets the phrase.

Recovery is set up when a recovery wrap exists at the current account key version. Replacing a phrase (§5.6) runs the same two steps.

### 5.11 Securing an account (D-36)

For a device that may have been used while unlocked, or a leaked PIN, run from a device the attacker didn't control. Input: the recovery phrase and a new PIN. Without recovery set up: `RECOVERY_NOT_SET_UP`; a phrase that isn't the current one: `WRONG_CREDENTIAL`, before anything is written.

1. Rotate the account key (§5.7) with the new PIN and the phrase. This cuts every other device: their wraps belong to the retired version (D-10).
2. For every team the account has member keys for, in its own write: create new member keys (§5.9) whose record carries a `recoverySignature` by the recovery signing key (§4.2).
3. Report the teams re-keyed and those that failed. A failed team is retried with the re-key of §6.8, with the phrase.
4. Wipe the phrase and the keys derived from it.

Each team's owners approve the new keys at their next `reconcile` (§6.9, SP-23), except where the account is an owner: another owner approves by hand. Until a team approves them, keys copied by the attacker still open what that team writes. The integration also ends the account's other sign-in sessions.

---

## 6. Team operations

What a team session does.

### 6.1 Loading and verifying team state

Run when a team session starts, before any other team operation.

1. **Collect anchors.** An anchor is a (version, record hash) pair this account already verified. Read the local one (`LocalKeyStore`), the server's `team-state` (§4.4), and on a first join the invite anchor if the invite carried one (§6.4). All are authenticated or received outside the server: the server can serve an older `team-state`, but can't forge one, and one that fails to decrypt stops here with `TRUST_FAILURE` (`state_unreadable`). With no anchor at all, this is a first contact: the chain is accepted as the server presents it (TH-04).
2. **Verify the chain.** Fetch the team key version records from the lowest anchor (or from version 1 at first contact) to the newest, and check them (§4.5). The chain must contain **every** anchor. The client adopts nothing newer than its anchors before this check passes. This order matters: the anchor comes from what the client verified, never from the record it's about to check.
3. **Report owner changes.** For every record newer than the highest anchor whose owner list differs from the previous version, report to the integration the signer and the owners added or removed (SP-15).
4. The current version n is the newest record of the verified chain.
5. Find this member's newest access: the newest version whose roster has an entry for one of its keys (§4.5). Check it and open it. For a version above 1, open its `wrappedPreviousKey` with the opened key. The keys and version it names are the keys the account **holds**.
6. Work out the access state (§9).
7. **Advance the anchor** to version n, locally and in the server's `team-state` (compare-and-set on `revision`). On conflict: reload the server's state, check that the chain contains it, then retry.

Any `TRUST_FAILURE` puts the team in the `unverified` state for this session.

### 6.2 Opening an earlier team key version

To open version m below the held version n: for k = n down to m+1, unwrap `wrappedPreviousKey` of record k (already checked in §6.1) with `teamKey_k` to get `teamKey_{k−1}`. Opened versions are cached for the session.

Records below the lowest anchor aren't fetched by §6.1. When a version below it is needed (to open an older key, or to find an older roster entry), the client fetches the missing records and checks only that each one's record hash equals the `prevHash` of the record above it, down to version 1's all-zero `prevHash` if reached. Any mismatch is `TRUST_FAILURE` (`chain_conflict`); missing records are `rollback`. The hash links pin them to a record already verified, so their signatures and owner lists need no new check.

### 6.3 Creating a team

1. The vault creates the creator's member keys (§5.9), `memberKeysVersion` 1.
2. Generate `teamKey_1`.
3. Create the version record for version 1: owners and roster are the creator; `prevHash` all zeros; no `wrappedPreviousKey`.
4. Store the record with the member keys in one atomic batch.
5. Save the anchor (§6.1 step 7).

### 6.4 Inviting and joining a team

1. **Invite (owner).** Put the team's anchor (`team.inviteAnchor()`, §3.5) in the invite link, for the integration to deliver.
2. **Join.** The vault creates the member's keys for the team (§5.9). On the joiner's first open of the team, the anchor from the link is passed to `openTeam(teamId, { anchor })`, or, in another context, to the receiver's `openTeam(ports, transfer, { anchor })` (§3.8), and becomes the member's first anchor: the chain must contain it (§6.1), so a server can't present a forged team.
3. The member is `pending` until an owner approves their keys (§6.5).

### 6.5 Approving members (owner)

1. Fetch and check the member's `member-keys` record (§4.2), with its proof.
2. The owner confirms the request is genuine (AS-06), unless it is a re-key proven by the recovery key (§6.8). The library reports the member's identity, keys and proof.
3. Approve by a rotation (§6.6) that adds those keys to the roster (D-37). The owner names the `memberKeysVersion` they reviewed; it must be the account's newest published keys, else `STALE_VERSION`: keys replaced by a re-key, or published after the review, are never approved. Several approvals, joins and re-keys alike, share one rotation.

Any member can list who holds the current version, with who signed it (`team.members()`): its roster. A newly admitted member is visible to everyone (SP-15). This is detection, not prevention: a member admitted by a stolen owner key can read until someone notices and rotates.

### 6.6 Rotating the team key (owner)

1. Open the current version n. The caller must be in the `owners` list of version n, else `NOT_AN_OWNER`.
2. **Recipients.** Every account the caller **keeps** (an explicit allowlist, normally the integration's active members) that holds version n, in its roster, plus every account whose keys this rotation **approves** (§6.5). The caller is always kept. Each receives **one** set of keys:
   - its newest published `member-keys` record, if this rotation approves it (for a new member, the only option). An approval names the `memberKeysVersion` the owner reviewed; if the account's newest published keys are no longer that version, the rotation stops with `STALE_VERSION` before anything is written (§6.8);
   - otherwise the keys it holds, resolved from their `member-keys` record and checked against the roster's `keysHash`, else `TRUST_FAILURE` (`key_mismatch`).

   Only access to the **current** version counts, so an older roster entry is never carried forward, and an account's older keys never receive the new version. An account left out of the list loses access to the new version: forgetting someone costs them access, never leaks it. More than 1,000 recipients, or a record over 384 KiB of JSON (§2), is `MALFORMED_RECORD`, before anything is written.
3. Owners of version n+1: the same list as version n, unless the owner list changes (§6.7). Every owner must be a recipient.
4. Generate `teamKey_{n+1}`. Create the version record n+1 (§4.5): `prevHash` = record hash of version n, `wrappedPreviousKey = wrap(teamKey_{n+1}, "team-key-link", …, teamKey_n)`, the roster with `teamKey_{n+1}` sealed to each recipient's keys, signed by the caller.
5. Store it. This makes n+1 current. If the server refuses because n is no longer current, stop with `STALE_VERSION`.

A rotation is one record: it is never half done (D-34).

### 6.7 Changing the owner list (owner)

Every owner change is a rotation (§6.6) whose new version carries the new owner list (D-13, D-19). There is no separate owner record.

1. Choose the new owner list. New owners must hold version n; their signing keys come from their `member-keys` records.
2. Run the rotation (§6.6) with that list in version n+1. The record, signed by an owner of version n, carries the owner list and the roster in one write: an owner change is never half applied.
3. When an owner is removed: members listed in a current roster the removed owner signed are listed for the caller to review before step 2 includes them. This is a **warning**, not a guarantee: access later re-signed by another owner no longer shows as coming from the removed owner (SP-15).

Adding an owner, removing an owner and replacing an owner's signing key (after a re-key) are all this one operation. Any single owner can run it, so a team with two or more owners never depends on one person (SP-16).

A removed owner isn't in the owner list of version n+1 or any later version, so their signatures are refused for all of them. They still hold versions up to n (AS-07), but can't give any version to anyone (TH-33).

### 6.8 Re-keying a member

1. The vault creates new member keys for the team with `memberKeysVersion` + 1 (§5.9), with a `recoverySignature` if the user entered the recovery phrase. The member stays able to read with the old keys until the rotation.
2. An owner approves the new keys by rotating the team key (§6.6), naming the `memberKeysVersion` reviewed. The library classifies the request:
   - **proven**: a `recoverySignature` that verifies with the recovery key of the keys the account holds (§4.2). Owners' `reconcile` approves it, unless the account is an owner (SP-23);
   - **unproven**: anything else. The owner verifies out of band (AS-06, TH-37). The old keys can't vouch for the new ones, since an attacker may hold them (D-38).

   Whatever the class, the rotation is the approval: the new version is sealed to the new keys, and the old keys receive nothing (SP-12). The approval is pinned to the reviewed `memberKeysVersion`: keys published after the review, for example by someone holding the member's session (TH-37), are never approved by it, and for an owner never replace their signing key in the owner list.
3. If the member is an owner, the same rotation replaces their signing key in the owner list (§6.7).

The new keys receive the current version, and the chain gives every earlier one.

### 6.9 Owner overview and `reconcile` (D-31)

**Overview.** For an owner, the library reports, for each account the integration lists and each account holding the current version:
- its status: `no-keys`, `awaiting-approval` (keys published, never in a roster), `approved` (holds the current version with its newest keys), `outdated` (held only an older version), `rekey-awaiting-approval` (holds the current version, newer keys published);
- the newest keys as a handle `{ accountId, memberKeysVersion }`, which every approval takes (§6.5, §6.8);
- the proof those keys carry: `recovery` or `none`;
- whether the account is an owner, and whether it is in the integration's active list.

Deciding `outdated` may need roster entries below the loaded chain: the client then fetches older records (§6.2).

Warnings, each naming the operation that clears it:
- `single-owner` (D-06), cleared by an owner change;
- `members-awaiting-approval` (`awaiting-approval` and `outdated` active accounts) and `rekeys-awaiting-approval`, cleared by an approval;
- `rotation-needed` (an account holding the current version is no longer active), cleared by `reconcile`.

**`reconcile(activeAccountIds, options)`** plans from the overview, then writes:

1. **Remove:** accounts holding the current version that aren't in `activeAccountIds` are left out of a rotation, except owners: removing one is an owner change, left to a human (`inactive-owner`). The caller is always kept.
2. **Approve proven re-keys:** active accounts holding the current version, not owners of it, whose newest keys are proven by their recovery key: the rotation approves those keys.
3. If step 1 or 2 found anything, run one rotation (§6.6) keeping every other holder and approving the keys of step 2.
4. Return the report: the version rotated to, if any; the accounts removed and re-keys approved; and everything else needing a human, with its handle and reason (`awaiting-approval`, `outdated`, `rekey-unproven`, `owner-rekey`, `inactive-owner`).

Rules (SP-22):
- `reconcile` never gives a version to a first-time joiner, to an `outdated` account, to unproven keys, or to an owner's new keys, and never changes the owner list. **Automatic actions only reduce access**; widening it needs a proof the rules accept, or a human.
- On `STALE_VERSION` (another owner wrote first), it reloads the team (§6.1) and plans once more; a second conflict is returned to the caller.
- `options.dryRun` returns the plan without writing; the report says whether it was a dry run.

---

## 7. Content operations

What a team session (and, for links and inboxes, an outside client) does with content. The application passes plaintext and `meta` and gets ciphertext to store; it passes ciphertext and gets plaintext and `meta` back. It never sees `itemKey`, `contentKey` or a team key (D-15). Where parts and submissions are stored is the integration's choice (D-25); the key records `item` and `inbox` go to the key store.

### 7.1 Creating an item

Creation is a draft, sealed last (D-27), so the integration can upload each part as it is encrypted and keep a large file out of memory.

1. **Start.** Check the access state is `ready` (§9), else `NOT_GRANTED`. Generate `itemKey`. No id is needed yet.
2. **Add parts,** in order, i = 0, 1, …: `stream(itemKey, "item-part", u32 i, content)` (§4.8), either buffered (the content in, the ciphertext out) or streamed (chunks in, ciphertext chunks out). The draft records each part's size, ciphertext hash and `meta`. The integration stores each ciphertext where it wants, before the item is sealed.
3. **References** (optional): `partRef(content)` for any part (§3.9).
4. **Seal** with the `itemId`. Check the access state is still `ready`. Build the manifest and the `item` record (§4.7) under the current version n at sealing, which may be newer than at the start: the parts don't depend on it. Store the `item` record in the key store. If the server refuses it because the current version moved (another owner rotated, D-37), reload the team (§6.1) and seal once more at the new current version; if the version didn't move (for example, the `itemId` is taken), or the second write is refused too, stop with `STALE_VERSION`. The draft is then closed and its key wiped.

The item exists, for readers, once its `item` record is stored. Parts of a draft never sealed open with no key; deleting them is the integration's job (D-27).

### 7.2 Opening an item (member)

1. Fetch and check the `item` record from the key store (§8).
2. Open `teamKey_n` (§6.1, §6.2), unwrap `wrappedItemKey`, unwrap `wrappedManifest`. The result is an opened item: each part's index, `meta` and size.
3. **Open a part on demand,** with the ciphertext the integration fetched from its storage:
   - buffered: refuse with `MALFORMED_RECORD`, before the integration downloads it, a part whose manifest size exceeds `maxBufferedSize` (§3.4); check its size and hash, then decrypt (§4.8);
   - streamed: decrypt the chunks as they come; the stream ends with `DECRYPTION_FAILED` if it is incomplete or doesn't match the manifest (SP-18).

A ciphertext that doesn't match its manifest entry, or a part the integration can't produce, is `DECRYPTION_FAILED`: the item is incomplete.

### 7.3 Sharing an item by link

- **Create:** a member opens the item key (§7.2 steps 1–2) and gets `encodeLinkKey(itemKey)`. The integration builds the link with `teamId` and `itemId` in the path and the key in the fragment, and handles it with the share-link checklist ([scope.md](scope.md#what-the-integration-does), D-22). A link sent by the integration's server exposes the key to that server (TH-23).
- **Open:** the recipient's client decodes the key (§3.5; `takeLinkKey()` in a browser) and is given the `item` record by the integration, from whatever route it serves it (the key store, or its own content API). It checks the record (§8 steps 1–3), unwraps `wrappedManifest` with the key, and opens parts on demand as in §7.2 step 3. The recipient can't check `createdBy` or the team key version; they get integrity of the content and manifest only.

### 7.4 Creating an inbox

1. Check the access state is `ready`.
2. Generate an X25519 key pair. Create the `inbox` record under the current version (§4.9) and store it in the key store, retrying once at the new current version if it moved, as in §7.1.
3. Return `encodeLinkKey(publicKey)`. The integration builds the link with `teamId` and `inboxId` in the path and the public key in the fragment.

**Replacing an inbox.** An inbox keeps its key pair for life, so a member removed later can still open submissions sent to it, if they also obtain the ciphertexts (TH-30, D-20). Replacing an inbox creates a new key pair under the current team key version, with a new link; the old link stops being usable for new submissions once the integration retires it. When to replace is the integration's decision.

### 7.5 Submitting to an inbox (sender)

A submission is a draft too (D-27).

1. **Start:** decode the public key from the link (§3.5) and generate `contentKey`. No id is needed yet.
2. **Add parts,** in order: `stream(contentKey, "submission-part", u32 i, content)`, buffered or streamed; the draft records sizes, hashes and `meta`. The integration uploads each ciphertext.
3. **References** (optional): `partRef(content)` (§3.9).
4. **Seal** with the `submissionId` the integration chose (§1): seal the envelope (§4.10) to the public key **from the link** (SP-14), and return the `submission` record. The integration stores it with the parts.

If the integration's page fetches the inbox public key from its server instead of reading it from the link, the server chooses the key (TH-21).

### 7.6 Opening a submission (member)

1. Fetch the `inbox` record from the key store, open `teamKey_n`, unwrap the inbox secret key and check it against `publicKey` (§4.9).
2. Check the `submission` record the integration gives (§8) and open the envelope with the expected context (§4.10). The result is an opened submission: `createdAt`, and each part's index, `meta` and size.
3. Open each part on demand, as in §7.2 step 3.

---

## 8. Verification order

Every record is checked in this order. The first failure stops processing (fail closed).

1. **Shape:** a JSON object whose `v` is an integer, `suite` a string and `type` the expected record type. Else `MALFORMED_RECORD`.
2. **Version and suite:** `v` and `suite` are in the supported list. Else `UNSUPPORTED_VERSION` (SP-17). The rest of the shape depends on `v`, so it is checked next: the required fields and types for that version; byte fields decode as base64url without padding, to the right length; integers, lists and ids within the bounds of §2; nothing unknown. Else `MALFORMED_RECORD`.
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
| `pending` | Member keys exist, but no access to the current version yet. | Versions up to the newest it holds | No |
| `ready` | An entry in the current version's roster. | All versions | Yes |
| `unverified` | A trust check failed in this session. | No | No |

`unverified` never clears by itself within a session, and the library never retries automatically: it signals tampering or a bug, and the integration should surface it.

### Errors

| Code | Meaning | Retry? |
| --- | --- | --- |
| `MALFORMED_RECORD` | A record or link value has the wrong shape. | No |
| `UNSUPPORTED_VERSION` | Unknown `v` or `suite`: update the library. | No |
| `TRUST_FAILURE` | A signature, owner rule, chain or context check failed in a record (a caller who simply isn't an owner gets `NOT_AN_OWNER`). Carries a `reason`: `bad_signature`, `not_an_owner`, `chain_conflict`, `rollback`, `state_unreadable`, `context_mismatch`, `key_mismatch`. | No |
| `DECRYPTION_FAILED` | Authenticated decryption failed: wrong key, tampered or truncated data. | No |
| `WRONG_CREDENTIAL` | The PIN or recovery phrase didn't open the account key. | Yes, by the user |
| `PIN_RATE_LIMITED` | The server refused another PIN evaluation. | Later, or use the recovery phrase |
| `DEVICE_NOT_REGISTERED` | This device has no current wrap (revoked or rotated). | After a PIN unlock |
| `NOT_GRANTED` | The member doesn't hold the version required. | After an owner approves |
| `STALE_VERSION` | A write used a version that is no longer current. | After reloading team state |
| `LAST_OWNER` | The account is the only owner: it can't leave the team until another owner is added. | After adding an owner |
| `NOT_AN_OWNER` | The caller isn't an owner of the current version, so it can't run an owner operation (a caller without current access gets `NOT_GRANTED`). | No |
| `RECOVERY_NOT_SET_UP` | Recovery must be set up before creating or joining a team (§5.10, D-35). | After setting up recovery |
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

The [server contract](scope.md#server-contract) applied to each key record. Content (item parts, submissions) isn't covered (D-25): see the note below the table.

| Record | Identity on the server | Rule |
| --- | --- | --- |
| `account-key-wrap` | account, version, method, deviceId | Write-once. Served only to the account. A recovery wrap may be created after the version's other wraps (§5.10). Removed on revocation, replacement, or retirement of the version, after a short delay at most: the server stops serving it, and keeps it for a restore window (rule 7). A device wrap may also stop being served after a period of inactivity. The switch of current version is atomic with the new wraps. |
| `member-keys` | team, account, memberKeysVersion | Write-once. Readable by the team's members. |
| `member-keys-wrap` | account, team, memberKeysVersion, accountKeyVersion | Write-once. Served only to the account. Deleted with its account key version. |
| `team-state` | account, team | Compare-and-set on `revision`. Served only to the account. |
| `team-key-version` | team, version | Write-once; version must be current + 1, which makes it current. The signer and the listed owners must hold the capability the integration maps to the cryptographic owner role (defence in depth, D-30). Writers keep the record's JSON within 384 KiB (§2), about 1,000 roster entries with 36-byte ids; the server accepts records of that size. |
| `item` | team, item | Write-once; `teamKeyVersion` must be current. Readable by the team's members, and by whoever the integration lets open the item's links, by the route it chooses. |
| `inbox` | team, inbox | Write-once; `teamKeyVersion` must be current. Readable by the team's members. |
| Team creation | — | Version 1 and the creator's member keys in one atomic batch. |
| OPRF evaluation | account | Per-account key. One total budget per account across `unlock` and `enroll`; the purposes may only split it. |

**Content, stored by the integration.** Item parts (team, item, index), submission records and their parts (team, inbox, submission, index) are checked by readers against their key record or envelope, wherever they are stored. Recommended, not relied on: keep them write-once, and don't present an item until its `item` record is stored. Parts of a draft never sealed (§7.1) open with no key and can be deleted.

---

## 12. API shape (informative)

How the operations above surface to developers. Names are indicative; the exact TypeScript API is defined with the implementation (its API reports are the reference).

Operations are asynchronous. An expected failure (§9) is thrown as a `ConvoyError` carrying its `code` and, for `TRUST_FAILURE`, its `reason` (D-23). "Throws X" below names such a code.

```ts
// Account vault: holds the account key; only what needs it runs here (scope, "Key custody").
vault.status()                            → { account: "not-set-up" | "locked" | "unlocked", deviceRegistered,
                                          //   recovery: "not-set-up" | "set-up" }
vault.warnings()                          → recovery not set up; teams whose keys need re-keying
vault.setup(pin)                          // then set up recovery before any team work
vault.beginRecoverySetup()                → { recoveryPhrase }   // held in memory until confirmed (§5.10)
vault.confirmRecoveryPhrase(phrase, { currentPhrase? }) → { rekeyed, failed }   // a replacement re-keys teams (§5.6)
vault.unlock()                            // device; throws DEVICE_NOT_REGISTERED
vault.unlockWithPin(pin)                  // upgrades an outdated PIN wrap (§5.4)
vault.recover(phrase, newPin)
vault.changePin(newPin)
vault.listDevices()                       → deviceId[]
vault.revokeDevice(deviceId)              // the device can't unlock again; see §5.5
vault.rotate({ pin, phrase? })            // without the phrase, recovery must be set up again
vault.secureAccount({ phrase, newPin })   → { rekeyed: teamId[], failed: teamId[] }   // §5.11
vault.createTeam(teamId)                  // creator is the first owner; throws RECOVERY_NOT_SET_UP
vault.joinTeam(teamId)                    // "pending" until an owner approves the keys
vault.rekey(teamId, { phrase? })          // new member keys; with the phrase, proven (§6.8)
vault.leaveTeam(teamId)                   // throws LAST_OWNER for the only owner
vault.openTeam(teamId, { anchor? })       → TeamSession   // same context; the invite link's anchor on a first open
vault.exportTeamKeys(teamId, request)     → transfer      // another context (§3.8)

// Receiving context (split layouts): one receiver per transfer.
createTeamKeyReceiver(accountId, teamId)  → { request, openTeam({ store, anchors }, transfer, { anchor? }) → TeamSession }

// Team session: one team's keys.
team.state                                // "not-joined" | "pending" | "ready" | "unverified"
team.ownerChanges                         // owner list changes since this account's last verified state
team.owners()                             → accountId[]
team.members()                            → the current roster, with who signed it
team.inviteAnchor()                       → string        // a bare anchor for an invite link
team.owner()                              → TeamOwner     // throws NOT_GRANTED (no current access), NOT_AN_OWNER

// Owner operations: plain data in and out.
owner.version                             // the current team key version
owner.overview(activeAccountIds)          → { version, owners, accounts: [{ accountId, status, keys?: handle,
                                          //   proof?: "recovery" | "none", isOwner, active }], warnings }
owner.reconcile(activeAccountIds, { dryRun? })
                                          → { dryRun, rotatedTo?, removed, approvedRekeys, needsHuman }
owner.approve(handles)                    → { rotatedTo, approved }   // handles from overview: one rotation
owner.remove(accountIds)                  → { rotatedTo, approved }   // a rotation keeping every other holder
owner.setOwners(owners, { keep? })        // always a rotation with the new owner list; keeps every holder by default
owner.grantedBy(ownerIds)                 → accounts in a current roster those owners signed (§6.7)
owner.rotate({ keep, approve? })          // low level: keep holders, add or replace approved keys

// Content.
team.beginItem()                          → draft         // §7.1
draft.addPart(content, { meta? })         → ciphertext
draft.addPartStream(chunks, { meta? })    → ciphertext chunks
draft.partRef(content) / partRefStream(chunks) → string // §3.9
draft.seal(itemId)                        // stores the item record; retried once if the version moved (§7.1)
team.openItem(itemId)                     → opened: parts' meta and sizes
opened.part(index, source)                → plaintext     // source: bytes, chunks, or a fetcher
opened.partStream(index, source)          → authenticated chunks
team.shareLinkKey(itemId)                 → string
team.createInbox(inboxId)                 → { linkKey }   // retried once if the version moved (§7.4)
team.replaceInbox(inboxId, newInboxId)    → { linkKey }
team.openSubmission(inboxId, submissionId, submission) → opened: createdAt, parts' meta and sizes

// Outside the team: no account and no store. teamId and itemId/inboxId come from the
// link's path, linkKey from its fragment (takeLinkKey() in a browser).
linkClient.openSharedItem(linkKey, teamId, itemId, itemRecord) → opened
linkClient.beginSubmission(linkKey, teamId, inboxId) → draft  // seal(submissionId) → submission record
```

Every argument and result of the vault's operations is plain data (strings, numbers, byte arrays, plain objects), so an integration can carry them over its own channel between contexts.

The integration implements `RecordStore`, `OprfService`, `LocalKeyStore` and `Clock` ([scope.md](scope.md#interfaces-the-integration-provides)).

### Interface contracts

What the library expects from each interface. A conforming server enforces the rules of §11 behind `RecordStore`; the library never relies on it for confidentiality or authenticity.

**`RecordStore`** is the key store: key records only (D-25). Records are addressed by their §11 identity (a *record key*: the record type and its identity fields). Content never goes through it.

| Method | Contract |
| --- | --- |
| `get(key)` | The record (a JSON value, parsed by the library) or `null`. |
| `list(query)` | The records matching a query, in identity order: an account's wraps at one account key version, its member keys wraps at one version, a team's team key versions from a given version, a team's member keys records (optionally of one account). |
| `getAccountKeyVersion(accountId)` | The current account key version, or `null` for an account that was never set up. |
| `commit(ops)` | Applies every operation or none (atomic). Operations: `create` (a write-once record), `compareAndSet` (a `team-state`, with the expected `revision`, `null` for none), `delete`, and `setAccountKeyVersion` (with the expected current version). |

A write that a server rule refuses (write-once, current version, compare-and-set, ordering) is reported by throwing the library's `StoreConflictError`: the library turns it into `STALE_VERSION`, or reloads and retries for a `team-state` (§6.1 step 7). Any other failure is `STORE_ERROR`. Private records (§11) are served only to their account: the integration authenticates the caller, the library never sees how.

**`OprfService`.** `evaluate(accountId, blindedElement, oprfKeyId, purpose)` returns the evaluated element (§5.1); a refusal by the rate limit is reported by throwing `RateLimitedError`, which the library turns into `PIN_RATE_LIMITED`. `currentKeyId(accountId)` returns the server's current `oprfKeyId`, for enrolment and the upgrade on unlock (§5.4).

**`LocalKeyStore`.** Keeps, on this device: per account, the device key and `deviceId`, and the highest account key version accepted (SP-07), used by the vault; per account and team, the anchor (version, record hash), used by team sessions. In a split layout, each context implements the half it uses. Values that can't be read back are errors, never an empty result (§3.7).

**`Clock`.** `now()` returns Unix seconds (§1).

**Settings.** The Argon2id writer cost and reader minimum (§2, D-17), and `maxBufferedSize` (§3.4). The library refuses settings below its hard floor.

---

## 13. Test vectors

Frozen JSON files under `test/vectors/`, each with inputs (including fixed random values), intermediate values and outputs. A change to a released vector means stored data would break. Protocol v1 isn't released yet: `item.v1.json` and `submission.v1.json` were regenerated for D-26, and `team-key.v1.json`, `recovery-key.v1.json` and `link.v1.json` for D-33, D-34, D-37 and D-38, before the first release; they are frozen from then on.

| File | Covers |
| --- | --- |
| `canonical.v1.json` | Every type of the canonical encoding |
| `wrap.v1.json` | `wrap` with each label, and tampering cases |
| `seal.v1.json` | `seal` with context, wrong-context cases, low-order public keys |
| `stream.v1.json` | Empty, one-chunk, exact-multiple and multi-chunk streams; truncation |
| `pin-key.v1.json` | Argon2id, the RFC 9497 vectors, and the final combination |
| `recovery-key.v1.json` | BIP-39 seed, recovery key, recovery signing key, and member keys recovery signatures |
| `team-key.v1.json` | Version records and their chain (owners, rosters, hashes, links), opening one's roster entry; rosters without the signer or an owner, out of order, duplicated or empty; forks, rollbacks, gaps, owner-rule cases (a removed owner signing a later version), owner keys not matching `member-keys`, and strict Ed25519 edge cases (non-canonical `S`, small-order keys and `R`) |
| `item.v1.json` | `item` record, manifest, parts bound by index (D-26); parts swapped, moved to another item, dropped |
| `link.v1.json` | Link values: item keys, inbox public keys and invite anchors, with their version prefix; refused prefixes, lengths and low-order keys |
| `submission.v1.json` | Envelope and parts bound by index; envelope moved to another inbox or id |
| `transfer.v1.json` | Team key transfer requests and transfers (§3.8): open, wrong receiver, other account or team, refused prefixes and low-order requests |
| `part-ref.v1.json` | Part reference key derivation and references (§3.9), for an item key and a submission content key |

---

## 14. Open points

None: every decision this document relies on is accepted ([decisions.md](decisions.md)).

Later, not in v1:
- fingerprints for out-of-band verification (D-11, which would add verified keys to `team-state`);
- author signatures (D-09);
- signed rotating inbox keys, so links survive a member removal without the exposure of TH-30 (D-20);
- invite proofs, a join secret in the invite link that the joiner's keys prove (D-32).
