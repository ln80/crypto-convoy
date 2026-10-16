# Architecture

How the library's code is organized. The behaviour it implements is specified in `docs/` ([protocol](../../docs/protocol.md), [key hierarchy](../../docs/key-hierarchy.md), [scope](../../docs/scope.md)); this guide only says where code goes and which patterns to use.

## `src/` layout (target)

```
src/
  index.ts          the only public entry (D-15: high-level operations only)
  errors.ts         error codes and TRUST_FAILURE reasons of protocol §9; typed errors
  result.ts         Result<T, E> for operations that report expected failures
  ports.ts          RecordStore, OprfService, LocalKeyStore, Clock (scope "Interfaces")
  encoding/         canonical encoding (§1), base64url, labels table and label(name), link values (§3.5)
  suites/           the suite registry (below) and the cc1 implementation
  records/          one module per record type of §4: type, shape validation, payload encoder, build and open
  account/          the account vault (§5): unlock methods, devices, rotation, member-key custody
  team/             the team session (§6): chain verification, anchors, grants, rotation, owners
  content/          items, link shares, inboxes, submissions (§7)
  browser/          optional adapter, published as `crypto-convoy/browser`: IndexedDB LocalKeyStore, takeLinkKey()
```

Rules of the layout:
- `index.ts` exports operations and types only. Primitives, suites, encoders and raw keys stay internal (D-15).
- The core (everything but `browser/`) is platform-neutral: no DOM, no `window`, no Node-only APIs.
- `browser/` may depend on the core; the core never imports `browser/`.

## Suite registry ("dictionary")

Every cryptographic primitive goes through a `Suite` object, selected by the id a record declares (`suite`, `cc1` in v1). This is how algorithms change without touching call sites (protocol §10, TH-32).

```ts
interface Suite {
  readonly id: string;                 // stored in records; never reused, never changed
  wrap / unwrap                        // AEAD with associated data (§3.1)
  seal / open                          // anonymous public-key encryption, context inside (§3.2)
  generateSigningKeyPair / sign / verify   // strict verification (§2, §3.3)
  generateEncryptionKeyPair / isLowOrder   // X25519 checks (§2)
  hash / keyedHash                     // BLAKE2b-256
  streamEncrypt / streamDecrypt        // secretstream, chunking and tags (§3.4)
  passwordHash                         // Argon2id with bounds (§2)
  oprfBlind / oprfFinalize             // RFC 9497 client side (§5.1)
}

const SUITES: ReadonlyMap<string, Suite> = new Map([CC1].map((s) => [s.id, s]));
export const CURRENT_SUITE: Suite = CC1;
export function suiteFor(id: string): Suite  // throws UNSUPPORTED_VERSION for unknown ids, before any crypto
```

- **Writers** use `CURRENT_SUITE`. **Readers** use `suiteFor(record.suite)`.
- **Seals use the recipient key's suite**, not the current one: a key type must match its seal.
- A new suite is registered for reading one release before `CURRENT_SUITE` switches to it (two-release rollout). See [add-algorithm-suite](../workflows/add-algorithm-suite.md).

## Record version dispatch

Each record module has one encoder per format version: `switch (record.v) { case 1: … }`. Readers encode with the record's own `v`; writers use the newest. A released `case` body is frozen: a layout change is a new `case` and new vectors, never an edit.

## Ports and custody

- The library reaches the outside only through the four ports. It never sees auth tokens, URLs or HTTP (scope).
- **Account vault vs team session** (D-03): code that wraps or unwraps under the account key lives in `account/`; a team session receives one team's keys and never the account key. Check every new operation against this split (lesson: API must match custody).

## Errors

- One error class with a `code` from protocol §9, and a `reason` for `TRUST_FAILURE`.
- Messages never include keys, plaintext or record contents.
- Expected failures (wrong PIN, not granted, stale version) are returned as results; programming errors throw.

## Dependencies

Runtime dependencies are limited to `libsodium-wrappers-sumo`, `@noble/curves` (OPRF) and `@scure/bip39`. A boundary test (`test/unit/boundary.test.ts`) fails on any other import in `src/`, and on deep imports of internal modules from outside `src/`. Extending the list needs a decision entry (D-) with the reason.
