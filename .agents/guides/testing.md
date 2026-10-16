# Testing

Tests prove the security properties. Every property in [docs/security-properties.md](../../docs/security-properties.md) names the test files that check it; those files are the contract.

## Property ↔ test mapping

- Each non-deferred `SP-` entry lists its test files under **Verification**. Those files must exist and test that property.
- Each test file starts with a header comment citing the properties and threats it covers:
  ```ts
  /**
   * SP-03: Encrypted data can't be modified or moved undetected.
   * Threats: TH-06, TH-29.
   */
  ```
- `describe` blocks are named after the property: `describe("SP-03: …", …)`.
- **Traceability test** (`test/unit/traceability.test.ts`): parses the properties doc and fails if a non-deferred property's listed test file is missing or doesn't mention the property id. Keep it green.
- A property's **Limit** is tested too, as specified behaviour (for example: re-admitting a member opens the gap, SP-06).

## Test projects (`vitest.config.ts`)

| Project | Folder | What goes there |
| --- | --- | --- |
| `unit` | `test/unit/` | Example-based tests of encoders, validators, registries; the boundary and traceability tests |
| `properties` | `test/properties/` | fast-check invariants: round trips, any flipped byte fails, any moved record fails |
| `security` | `test/security/` | Adversarial tests named by the properties (`<topic>.test.ts`), sequential |
| `compatibility` | `test/compatibility/` | Replay of frozen vectors; cohabitation of format versions and suites |
| `fuzz` | `test/fuzz/` | Bounded fuzzing of every parser (opt-in: `npm run test:fuzz`) |

## Frozen vectors (`test/vectors/*.v1.json`)

- One file per area, as listed in protocol §13. Each case has inputs (including the fixed random values), intermediate values and outputs.
- Compute expected outputs **independently** (raw libsodium, not the library's own code path), so a bug can't validate itself.
- A released vector is never edited. A new format version gets a new file (`*.v2.json`); the old one keeps being replayed.
- Vectors are the cross-language contract: another implementation must pass them unchanged.

## Adversarial testing

- Prefer attacks over happy paths. For each record and operation: tamper every field, truncate, add trailing data, swap records across items, teams and versions, replay old records, serve unknown or older versions and suites.
- Use the in-memory **fake store** (`test/support/fake-store.ts`): an honest `RecordStore` with tamper hooks: swap, replay, rollback, drop, fork (two records for one version), garbage, withhold.
- Assert the exact error code and reason (`TRUST_FAILURE` / `chain_conflict`, …), not just "throws".
- **Prove the test guards the fix:** temporarily reintroduce the bug, check that the test fails, restore.

## Practicalities

- Tests run in Node (`environment: "node"`). Platform adapters (`browser/`) are tested with fakes of their platform APIs.
- Argon2id at real cost is slow: use the minimum allowed parameters in tests unless the test is about the cost itself.
- Keep tests independent of time and randomness: inject `Clock` and seed values through the ports and test helpers.
