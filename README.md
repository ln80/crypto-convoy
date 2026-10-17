# crypto-convoy

TypeScript library for end-to-end encrypted team storage: account keys, team keys shared through an untrusted server, encrypted items, link shares and inboxes. To be open-sourced.

This package is private (`"private": true`) and at `0.0.0` until a public release is ready. It implements protocol v1 but has had no independent security audit. Flip `private` to `false`, set a real version and license, then publish.

## Using the library

Three entry points:

| Import | For |
| --- | --- |
| `crypto-convoy` | The account vault, team sessions, the link client, errors and the interface types |
| `crypto-convoy/browser` | `createIndexedDbLocalKeyStore()` and `takeLinkKey()` |
| `crypto-convoy/testing` | An honest in-memory server, a fake OPRF server, a memory key store and a clock, for your tests |

### Quick start

```ts
import { createLinkClient, createVault } from "crypto-convoy";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore } from "crypto-convoy/testing";

const server = new MemoryRecordStore(); // in production: your RecordStore over your API
const oprf = new FakeOprfServer();      // in production: your OprfService

const alice = await createVault({ store: server.as("alice"), oprf, localKeys: new MemoryLocalKeyStore() }, "alice");
const { recoveryPhrase } = await alice.setup("1234"); // show the phrase once

const team = await alice.createTeam("team-1");
await team.createItem("note", [{ content: new TextEncoder().encode("hello") }]);
const parts = await team.openItem("note"); // [{ content, meta }]

// Someone outside the team, with a share link:
const outsider = await createLinkClient({ store: server.anonymous() });
await outsider.openSharedItem(await team.shareLinkKey("note"), "team-1", "note");
```

`test/compatibility/scenario.test.ts` walks through every operation with the public API only.

### Key custody

The **vault** (`createVault`) holds the account key: setup, unlock (device, PIN, recovery phrase), devices, credentials, account key rotation, and anything that wraps member keys (create, join, re-key, leave a team). A **team session** (`vault.openTeam`) holds one team's keys only: grants, rotations, owners, items, inboxes. Run them as far apart as your product allows (scope, "Key custody"). The application never handles a raw key (D-15).

### Errors

Every operation throws one class, `ConvoyError`, with a `code` from protocol §9 (and a `reason` for `TRUST_FAILURE`). Branch with `isConvoyError(error, "WRONG_CREDENTIAL")`.

| Code | What to do |
| --- | --- |
| `WRONG_CREDENTIAL` | Ask again |
| `PIN_RATE_LIMITED` | Wait, or offer the recovery phrase; never retry automatically |
| `DEVICE_NOT_REGISTERED` | Unlock with the PIN (this registers the device) |
| `NOT_GRANTED` | Wait for an owner, or show the content as unavailable |
| `STALE_VERSION` | Reopen the team and try again |
| `LAST_OWNER` | Add another owner first |
| `TRUST_FAILURE` | Stop and show a security warning. A team session becomes `unverified` for good (`session.failure`) |
| `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`, `DECRYPTION_FAILED` | Tampered or unsupported data: report, don't retry |
| `STORE_ERROR` | Your `RecordStore` or `OprfService` failed (`error.cause`); retry, except PIN evaluations |

Your `RecordStore` signals a refused write with `StoreConflictError`, and your `OprfService` a spent PIN budget with `RateLimitedError`.

### Share and inbox links

Put `shareLinkKey()` and `createInbox().linkKey` values in the URL **fragment**. On the page that opens them, call `takeLinkKey()` first: it reads the fragment and removes it from the address bar and history. Follow the share-link checklist in [docs/scope.md](docs/scope.md#what-the-integration-does).

### Large content

`openItem` and `openSubmission` are buffered: all parts, or an error and nothing. Parts above `settings.maxBufferedSize` (default 64 MiB) are refused before download. For larger parts, `openItemStream` yields authenticated chunks and ends with an error if the content is incomplete; discard what you received in that case.

### Integrating a server

[docs/integration.md](docs/integration.md) says how to implement the four interfaces and the server rules in any backend.

## Security documents

The files under `docs/` specify a new model, designed from the problems found in an earlier implementation. Each one states the question it answers. Files marked "draft" are under review; `SECURITY.md` is still an authoring guide. Threats, properties and decisions have stable ids (`TH-01`, `SP-01`, `D-01`); cite them from tests and pull requests.

| File | Question |
| --- | --- |
| [docs/scope.md](docs/scope.md) | What is the library responsible for, and what is left to the application? |
| [docs/decisions.md](docs/decisions.md) | Why is the design the way it is? |
| [docs/threat-model.md](docs/threat-model.md) | Against whom are we protecting the system? |
| [docs/security-properties.md](docs/security-properties.md) | What security guarantees must always hold? |
| [docs/key-hierarchy.md](docs/key-hierarchy.md) | How are keys organized, distributed, and managed? |
| [docs/protocol.md](docs/protocol.md) | How does the cryptographic system work? |
| [docs/libsodium-map.md](docs/libsodium-map.md) | Which libsodium function does each protocol task? |
| [docs/integration.md](docs/integration.md) | How does a backend implement the interfaces and the server rules? |
| [SECURITY.md](SECURITY.md) | How should vulnerabilities be reported and handled? |

How they relate:

```text
scope.md
  What the library owns, and what the integration owns
        |
        v
threat-model.md
  Identify threats, attackers, and assumptions
        |
        v
security-properties.md
  Define the guarantees to maintain
        |
        v
key-hierarchy.md                  protocol.md
  Key structure and lifecycle       Cryptographic operations and formats
        |                                 |
        +----------------+----------------+
                         |
                         v
        Automated tests and security review
          Verify implementations against documented properties

decisions.md
  Why each choice was made (cross-cutting)

SECURITY.md
  Cross-cutting disclosure and maintenance policy
```

Write them problem first, one at a time, and review each before starting the next:

1. [docs/scope.md](docs/scope.md) — the library's responsibilities and its boundary with the integration. Record each settled choice in [docs/decisions.md](docs/decisions.md) as you go.
2. [docs/threat-model.md](docs/threat-model.md) — assets, attackers and threats, first at the level of assets.
3. [docs/security-properties.md](docs/security-properties.md) — the guarantees that answer those threats, as checks.
4. [docs/key-hierarchy.md](docs/key-hierarchy.md) — the keys and lifecycles that deliver those properties. Then a second pass on the threat model for threats specific to each key.
5. [docs/protocol.md](docs/protocol.md) — algorithms, serialized formats, and operations, enough to implement a decryptor without this repository's TypeScript.
6. [SECURITY.md](SECURITY.md) — when a public release is close. Turn on GitHub private vulnerability reporting first; do not invent a disclosure address.

## Working with agents

Instructions for AI coding agents live in [AGENTS.md](AGENTS.md) (read natively by Cursor and imported by `CLAUDE.md` for Claude Code), with detailed guides and task workflows in `.agents/`. Claude skills (`.claude/skills/`) and Cursor rules (`.cursor/rules/`) only point to those files, so both tools follow the same rules.

## Scripts

| Script | Purpose |
| --- | --- |
| `npm run typecheck` | TypeScript check for `src`, `test`, and config files |
| `npm run check:spec` | Consistency checks of `docs/`: labels, ids, § references, vectors, traceability, product terms |
| `npm run build` | Vite library build (ESM + CJS + `.d.ts`) into `dist/` |
| `npm test` | Unit, properties, security, and compatibility projects |
| `npm run test:unit` | Unit suite only |
| `npm run test:properties` | Property-based suite (`@fast-check/vitest`) |
| `npm run test:security` | Security suite (sequential files) |
| `npm run test:compatibility` | Compatibility / vector suite |
| `npm run test:fuzz` | Bounded fuzz suite (opt-in; not part of `npm test`) |
| `npm run test:browser` | Browser adapter suite (fake IndexedDB, Node WebCrypto) |
| `npm run test:package` | Smoke test of the built package, as a consumer imports it |
| `npm run vectors:generate` | Generates missing vector files with raw libsodium; refuses to overwrite |
| `npm run test:all` | Every Vitest project, including fuzz |
| `npm run test:watch` | Vitest watch mode |

## Test layout

- `test/vectors/` — frozen JSON fixtures (imported by tests; not executed)
- `test/unit/` — example-based tests
- `test/properties/` — invariants via fast-check
- `test/security/` — isolation, key substitution, removal, recovery
- `test/fuzz/` — parser/decoder campaigns (bounded; coverage-guided fuzzing is a later Jazzer.js target)
- `test/compatibility/` — vector replay and cohabitation of protocol versions (there are no legacy formats, see D-01)

## Publish checklist

1. Finish and review every document in `docs/`, in the order in [Security documents](#security-documents).
2. Configure GitHub private vulnerability reporting, then fill in [SECURITY.md](SECURITY.md).
3. Choose a license.
4. Set `version`, set `"private": false`.
5. `npm run prepublishOnly` (typecheck + test + build + package smoke test).
6. `npm publish`.
