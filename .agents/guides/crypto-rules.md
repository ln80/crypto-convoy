# Cryptographic implementation rules

Rules for any code in `src/`. They come from the hardening of an earlier implementation of this model; each one prevents a bug that happened or nearly happened.

## Formats and versions

- **Readers dispatch on what a record declares** (`v`, `suite`, link prefix); **writers use the newest**. Never re-encode a stored record with the current version.
- **Stored data is forever.** Never change a released label, layout, field meaning or vector. A change is a new version (protocol §10).
- **Two-release rollout:** ship the reader of a new format before any writer produces it.
- Every signed, hashed, wrapped or derived value uses the canonical encoding and starts with `string label(name)` (protocol §1). Every label used must be in the §1 table: `npm run check:spec` checks it.

## Inputs

- **Validate before crypto**, in the protocol §8 order: shape → version and suite → context ids → signature and trust → decrypt → post-checks. Stop at the first failure.
- Check exact sizes of every key, nonce, signature and id before calling a primitive. libsodium silently truncates some inputs (an 8-byte KDF context once made two "different" contexts identical).
- Values from the server and from URLs are untrusted: bound every length and count (D-18), refuse unknown fields, refuse trailing bytes.
- Rebuild associated data from the ids the caller **expects**; take only informative fields (`createdAt`, `createdBy`, `kdf`) from the record (§3.1).
- Refuse low-order X25519 keys and verify Ed25519 strictly (§2). Don't rely on one library's defaults: write the check.

## Primitives

- Every primitive goes through the suite registry ([architecture](architecture.md)). No direct libsodium calls outside `suites/`.
- Always check libsodium return values. `crypto_secretstream_*_pull` returns `false` on failure: an earlier bug turned that into an empty message.
- Randomness comes only from libsodium's `randombytes_buf`.
- Compare secrets and MACs with constant-time functions (`sodium.memcmp`), never `===`.
- Keep keys as `Uint8Array` inside opaque objects, not base64 strings; zero them when done where possible (best effort: JavaScript can't guarantee erasure).

## Decryption contract

- Every decryption either returns the complete, authenticated plaintext or fails with a typed error (`DECRYPTION_FAILED`). Never return partial or empty data on failure.
- The buffered API is the default and refuses parts above `maxBufferedSize` before downloading; streaming is opt-in (§3.4).

## Trust

- Trust failures (`TRUST_FAILURE`) are blocking: the team becomes `unverified`, and nothing retries automatically.
- Never accept a signature by keys as approval of their own replacement (SP-12).
- Never adopt a newer chain tip before verifying the chain from the anchor (§6.1).

## Operations

- **Never retry an OPRF evaluation automatically:** each call spends a rate-limited PIN attempt (§5.1).
- Destructive operations must be safe if the server keeps old records (soft delete, TH-36) and if a write is interrupted (resume rules, §6.6).
- Rotations take an allowlist (`keep`), never an exclude list (§6.6).

## Logging

Never log keys, plaintext, record contents or error objects that may carry them. Log only error codes and short messages.
