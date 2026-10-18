# crypto-convoy

TypeScript library for end-to-end encrypted team storage: account keys, team keys shared through an untrusted server, encrypted items, link shares and inboxes. To be open-sourced.

This package is private (`"private": true`) and at `0.0.0` until a public release is ready. It implements protocol v1 but has had no independent security audit. Flip `private` to `false`, set a real version and license, then publish.

## Using the library

The library manages keys and does the cryptography. Your app stores the content: parts and submissions go wherever your pipeline puts them (D-25).

Three entry points:

| Import | For |
| --- | --- |
| `crypto-convoy` | The account vault, team sessions, transfers between contexts, the link client, errors and the interface types |
| `crypto-convoy/browser` | `createIndexedDbLocalKeyStore()` and `takeLinkKey()` |
| `crypto-convoy/testing` | An honest in-memory key store, a fake OPRF server, a memory key store and a clock, for your tests |

### Quick start

```ts
import { createVault } from "crypto-convoy";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore } from "crypto-convoy/testing";

const keyStore = new MemoryRecordStore();   // in production: your RecordStore over your key store API
const local = new MemoryLocalKeyStore();    // in a browser: createIndexedDbLocalKeyStore()
const vault = await createVault({ store: keyStore.as("alice"), oprf: new FakeOprfServer(), deviceKeys: local, anchors: local }, "alice");

await vault.setup("1234");
const { recoveryPhrase } = vault.beginRecoverySetup(); // show it, then ask the user to type it back
await vault.confirmRecoveryPhrase(typedBack);           // teams need recovery set up (D-35)
await vault.createTeam("team-1");
const team = await vault.openTeam("team-1");
```

`test/compatibility/scenario.test.ts` walks through every operation with the public API only, shaped like a product's pipelines.

### Creating content: a draft, sealed last

The order fits a create → upload → finalize pipeline. The id can come from your server after the first part is encrypted.

```ts
const draft = team.beginItem();
const value = draft.addPart(text, { meta: format });         // ciphertext: send it with your "create" call
const id = await yourApi.create(value);                      // your server assigns the id
for (const file of files) {
  const ref = draft.partRef(bytes);                          // a keyed reference, safe to send (never a plain hash)
  await yourApi.upload(id, draft.addPartStream(file.stream(), { meta: name })); // ciphertext chunks
}
await draft.seal(id);                                        // writes the item's key record; then finalize
```

Inbox submissions from outside work the same way: `(await createLinkClient()).beginSubmission(linkKey, teamId, inboxId)`, then `addPart`, then `seal(submissionId)`. It returns the submission record, which you store with its parts.

### Reading: open, then parts on demand

```ts
const opened = await team.openItem(id);                      // parts' meta and sizes
const value = await opened.part(0, () => yourApi.download(id, 0));
for await (const chunk of opened.partStream(1, () => yourApi.downloadStream(id, 1))) { /* … */ }
```

`part` is buffered: all of it or an error. A part above `settings.maxBufferedSize` (default 64 MiB) is refused before your fetcher is called. `partStream` yields authenticated chunks and ends with an error if the content is incomplete; discard what you received in that case.

A link holder gets the key from the fragment (`takeLinkKey()`) and the item's key record from you, by whatever route you choose: `linkClient.openSharedItem(linkKey, teamId, itemId, itemRecord)`.

### Key custody: one context or two

The **vault** holds the account key and does only what needs it: setup, unlock, devices, credentials, account rotation, and creating, joining, re-keying and leaving teams. A **team session** holds one team's keys and does everything else.

If both run in one context, `vault.openTeam(teamId)`. If the vault runs elsewhere (for example an iframe on its own origin), the page asks for one team's keys and the vault seals them to it:

```ts
// page
const receiver = await createTeamKeyReceiver(accountId, teamId);
// …send receiver.request to the vault over your channel; the vault calls exportTeamKeys(teamId, request)…
const team = await receiver.openTeam({ store, anchors }, transfer);
```

The transfer opens only for that receiver, once. Your bridge carries the two strings and decides which page may ask for which team; the library never sees your domain layout (D-29).

### Status, warnings and administration

What to render:

- `vault.status()`: `account` (`not-set-up`, `locked`, `unlocked`), `deviceRegistered`, and `recovery` (`not-set-up`, `set-up`).
- `vault.warnings()`: `recovery-not-set-up`, or `rekey-needed` for teams whose keys predate the current phrase.
- `team.state`: `not-joined`, `pending`, `ready` or `unverified`.
- `team.owner().overview(activeIds)`, for owners: each account's `status` (`no-keys`, `awaiting-approval`, `approved`, `outdated`, `rekey-awaiting-approval`), its newest `keys` (a handle to approve), their `proof` (`recovery`, `invite`, `continuity`, `none`), and warnings (`single-owner`, `members-awaiting-approval`, `rekeys-awaiting-approval`, `rotation-needed`) with the operation that clears each.

`team.owner()` throws `NOT_AN_OWNER` for anyone else, so member screens can't reach admin operations. Every call takes and returns plain data.

#### Admin recipes

**At every owner session**, run the autopilot with the accounts your product considers members:

```ts
const report = await team.owner().reconcile(activeIds);
// report.removed, approvedRekeys: done. report.needsHuman: show these, with their reason.
```

It rotates out holders no longer active (never owners), and approves re-keys proven by the member's recovery phrase. It never widens access otherwise, never changes owners, and leaves `awaiting-approval`, `outdated`, `rekey-unproven`, `owner-rekey` and `inactive-owner` to a human (SP-22). `{ dryRun: true }` returns the plan for a preview.

| Situation | Calls |
| --- | --- |
| **New user** | `vault.setup(pin)`, `beginRecoverySetup()`, `confirmRecoveryPhrase(typedBack)` |
| **Invite someone** | Put `team.inviteAnchor()` in the invite link's fragment; the joiner calls `vault.joinTeam(teamId)`, then `vault.openTeam(teamId, { anchor })` on the first open |
| **Approve someone** | Check the request out of band, then `owner.approve([account.keys])` with the handles from `overview`: one rotation for all of them, joiners and re-keys alike. It refuses (`STALE_VERSION`) if newer keys appeared since the review |
| **Someone leaves** | Drop them from `activeIds`; the next `reconcile` rotates. Or `owner.remove([accountId])` now |
| **Device lost, never used by anyone** | `vault.revokeDevice(deviceId)` from another device |
| **Device possibly misused, or PIN leaked** | `vault.secureAccount({ phrase, newPin })` from a clean device: new account key, other devices cut, every team re-keyed with a recovery proof that owners' `reconcile` approves. Retry any `failed` team with `vault.rekey(teamId, { phrase })` |
| **Replace the recovery phrase** | `beginRecoverySetup()`, then `confirmRecoveryPhrase(typedBack, { currentPhrase })`: teams re-key with proof. Without `currentPhrase` (phrase lost) each team needs an owner's approval |
| **Hand over or add an owner** | `owner.setOwners([...])`: a rotation with the new owner list; keeps every holder |
| **Single owner warning** | Add a co-owner with `setOwners`: a team whose only owner loses every credential is frozen (TH-18) |

Every access change is a rotation (D-37), so the team key version moves often. `draft.seal` and `createInbox` retry once by themselves when it moved; `STALE_VERSION` after that means the id is taken or writes keep racing.

### Errors

Every operation throws one class, `ConvoyError`, with a `code` from protocol §9 (and a `reason` for `TRUST_FAILURE`). Branch with `isConvoyError(error, "WRONG_CREDENTIAL")`.

| Code | What to do |
| --- | --- |
| `WRONG_CREDENTIAL` | Ask again |
| `PIN_RATE_LIMITED` | Wait, or offer the recovery phrase; never retry automatically |
| `DEVICE_NOT_REGISTERED` | Unlock with the PIN (this registers the device) |
| `NOT_GRANTED` | Wait for an owner, or show the content as unavailable |
| `STALE_VERSION` | Reopen the team and try again; for an approval, review the newer keys first |
| `LAST_OWNER` | Add another owner first |
| `NOT_AN_OWNER` | Hide owner screens for this account |
| `RECOVERY_NOT_SET_UP` | Run the recovery setup (`beginRecoverySetup`, `confirmRecoveryPhrase`) |
| `TRUST_FAILURE` | Stop and show a security warning. A team session becomes `unverified` for good (`session.failure`) |
| `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`, `DECRYPTION_FAILED` | Tampered or unsupported data: report, don't retry |
| `STORE_ERROR` | Your `RecordStore` or `OprfService` failed (`error.cause`); retry, except PIN evaluations |

Your `RecordStore` signals a refused write with `StoreConflictError`, and your `OprfService` a spent PIN budget with `RateLimitedError`.

### Share and inbox links

Put `shareLinkKey()` and `createInbox().linkKey` values in the URL **fragment**. On the page that opens them, call `takeLinkKey()` first: it reads the fragment and removes it from the address bar and history. Follow the share-link checklist in [docs/scope.md](docs/scope.md#what-the-integration-does).

### Integrating a server

[docs/integration.md](docs/integration.md) covers the key store, the OPRF server and where your content pipeline plugs in.

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
