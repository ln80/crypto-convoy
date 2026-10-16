# Workflow: add an algorithm suite

**Use when** a primitive changes: a new AEAD, a post-quantum or hybrid key exchange, a new signature scheme, new password-hashing parameters that need a new construction.

A suite bundles every primitive of a protocol version; records name it in `suite`. Old suites stay readable forever (protocol §10, TH-32).

## Steps

1. **Decision first:** add a `D-` entry (problem, chosen primitives, rejected alternatives, rollout) and update the protocol: §2 (a new suite table), and any size that changes (keys, signatures, link values).
2. **Pick a new id** (for example `cc2`). Ids are never reused or renamed.
3. **Implement** the `Suite` interface in `src/suites/<id>.ts` (guide: [architecture](../guides/architecture.md)). Keep the same validation duties: strict signature checks, low-order or invalid-key checks, exact sizes.
4. **Register for reading only:** add it to `SUITES`. Do **not** change `CURRENT_SUITE` yet.
5. **Vectors:** new frozen cases for every primitive of the suite, computed independently.
6. **Cohabitation tests** (`compatibility`): records of the old suite and the new one in the same team; seals use the recipient key's suite; an unknown suite id is refused before any crypto.
7. **Links:** if a key carried in a link changes size or type, define a new link prefix character (§3.5) and test that old readers refuse it cleanly.
8. **Release N** ships the reader. **Release N+1** switches `CURRENT_SUITE`, once no reader older than N is in use.
9. **Migration is explicit:** existing keys keep their suite until replaced (re-key, rotation). Plan it if old data must move (for example against harvest-now-decrypt-later).

## Done when

- `suiteFor(newId)` works, `CURRENT_SUITE` is unchanged in the first release, vectors and cohabitation tests pass, the protocol and decisions are updated, and `npm run check:spec` passes.
