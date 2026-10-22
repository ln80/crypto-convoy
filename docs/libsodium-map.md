# libsodium map

> Status: draft. Kept in step with `src/suites/` by `test/unit/libsodium-map.test.ts`.

## Role

Answers: **which libsodium function does each protocol task, and what is checked before calling it?**

Every primitive goes through the suite registry ([architecture guide](../.agents/guides/architecture.md)); only `src/suites/` calls libsodium (`libsodium-wrappers-sumo`). This page maps each call to the suite method that wraps it and the protocol task it serves. The protocol ([protocol.md](protocol.md)) remains the reference for what is computed.

## Audience

Implementers porting the protocol to another language, reviewers, auditors.

## libsodium functions (suite `cc1`)

| libsodium | Suite method | Protocol task | Checked before the call | Source (`src/suites/`) |
| --- | --- | --- | --- | --- |
| `ready` | `ready()` (registry) | Loads libsodium once; the public entry points await it | — | `cc1/sodium.ts` |
| `randombytes_buf` | `randomBytes` | Every key, nonce, id, salt and `deviceId`; the OPRF blinding scalar; BIP-39 entropy (§3.6) | — | `cc1/index.ts` |
| `memcmp` | `equal` | Constant-time comparison of hashes and keys (anchors, manifest hashes) | Equal lengths, else not equal | `cc1/index.ts` |
| `memzero` | `wipe` | Best-effort erasure of keys and plaintext buffers once used | — | `cc1/index.ts` |
| `crypto_aead_xchacha20poly1305_ietf_encrypt` | `aeadEncrypt` | `wrap` (§3.1): account key, member keys, team state, team key link, item key, item manifest, inbox key | Key 32, nonce 24 | `cc1/index.ts` |
| `crypto_aead_xchacha20poly1305_ietf_decrypt` | `aeadDecrypt` | `unwrap` (§3.1); any failure is `DECRYPTION_FAILED` | Key 32, nonce 24, ciphertext ≥ 16 | `cc1/index.ts` |
| `crypto_scalarmult_base` | `generateEncryptionKeyPair`, `encryptionPublicKey` | Member encryption and inbox key pairs (secret from `randombytes_buf`); recomputing a public key in the post-checks of §4.3 and §4.9 | Secret key 32 | `cc1/index.ts` |
| `crypto_box_seal` | `seal` | `seal` (§3.2): `roster-seal`, `submission` envelope, team keys transfer | Public key 32, not in the X25519 low-order list (§2) | `cc1/index.ts` |
| `crypto_box_seal_open` | `sealOpen` | `open` (§3.2); label, context and trailing bytes are then checked by `blocks/seal.ts` | Key pair 32 + 32, sealed ≥ 48 | `cc1/index.ts` |
| `crypto_sign_seed_keypair` | `signingKeyPair` | Member signing key from the bundle's `signingSeed` (§4.3) | Seed 32 | `cc1/index.ts` |
| `crypto_sign_detached` | `sign` | `sign` (§3.3): member keys, member keys recovery signature, team key version | Secret key 64 | `cc1/index.ts` |
| `crypto_sign_verify_detached` | `verify` | `verify` (§3.3), after the strict checks of §2 | Key 32, signature 64, S < L, valid key, R not small order | `cc1/index.ts` |
| `crypto_core_ed25519_is_valid_point` | `verify`, `isValidSigningPublicKey` | Strict check of every signing public key (§2) | Length 32 | `cc1/index.ts` |
| `crypto_generichash` | `hash`, `keyedHash` | Unkeyed BLAKE2b-256: record hash (§4.5), hashes bound in signatures and wraps (§4.5–§4.7), ciphertext hash (§3.4). Keyed: `pinKey` (§5.1), `recoveryKey` (§5.2), the part reference key and references (§3.9) | Key 16–64 bytes when keyed | `cc1/index.ts` |
| `crypto_generichash_init`, `crypto_generichash_update`, `crypto_generichash_final` | `hasher` | Incremental BLAKE2b-256: a stream's ciphertext hash while it is written or read (§3.4), the hash of a wrap's `nonce ‖ ciphertext`; keyed, a part reference over a stream (§3.9) | Key 16–64 bytes when keyed | `cc1/index.ts` |
| `crypto_secretstream_xchacha20poly1305_init_push`, `crypto_secretstream_xchacha20poly1305_push` | `streamPush` | `stream` (§3.4): item parts and submission parts | Key 32 | `cc1/index.ts` |
| `crypto_secretstream_xchacha20poly1305_init_pull`, `crypto_secretstream_xchacha20poly1305_pull` | `streamPull` | Reading a stream (§3.4). `pull` returns `false` on failure, which is turned into `DECRYPTION_FAILED`, never an empty chunk | Key 32, header 24, chunk ≥ 17 | `cc1/index.ts` |
| `crypto_secretstream_xchacha20poly1305_TAG_MESSAGE`, `crypto_secretstream_xchacha20poly1305_TAG_FINAL` | `streamPush`, `streamPull` | The only two tags accepted (§3.4); any other tag is `DECRYPTION_FAILED` | — | `cc1/index.ts` |
| `crypto_pwhash`, `crypto_pwhash_ALG_ARGON2ID13` | `passwordHash` | Argon2id over the PIN (§5.1) | Salt 16; `opslimit` 2–10, `memlimit` 64 MiB–1 GiB (§2) | `cc1/index.ts` |

## Other primitives

Not from libsodium, each for a stated reason.

| Library and function | Protocol task | Why not libsodium | Source |
| --- | --- | --- | --- |
| `@noble/curves`: `ristretto255_oprf.oprf.blind`, `finalize` | OPRF client, RFC 9497 ristretto255-SHA512 base mode (§5.1). The blinding scalar's randomness is `randombytes_buf` | libsodium has ristretto255 arithmetic but no RFC 9497 construction; a hand-written one would be new code to audit | `cc1/index.ts` |
| `@noble/curves`: `ristretto255_oprf.oprf.deriveKeyPair`, `blindEvaluate` | Server side of the OPRF, in the testing kit only (§5.1, D-24) | As above | `testing/` |
| `@scure/bip39`: `entropyToMnemonic`, `validateMnemonic`, `mnemonicToSeedSync` | Recovery phrase: 12 English words from 16 bytes of `randombytes_buf`, checksum, PBKDF2-HMAC-SHA512 seed (§5.2) | libsodium has no BIP-39 word list or PBKDF2 | `cc1/index.ts` |
| WebCrypto `AES-GCM` (`generateKey` non-extractable, `encrypt`, `decrypt`) | Browser adapter's local storage (§3.7) | Only WebCrypto can make a key non-extractable (D-08) | `browser/` |
