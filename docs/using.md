# Using the library

> Status: draft. Follows protocol v1.

## Role

Answers: **how does an application call the library?**

## Audience

Integrators writing the client: the account vault, team sessions, content, and administration.

## What the library does

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
// on a joiner's first open, pass the invite link's anchor: openTeam({ store, anchors }, transfer, { anchor })
```

The transfer opens only for that receiver, once. Your bridge carries the two strings and decides which page may ask for which team; the library never sees your domain layout (D-29).

### Status, warnings and administration

What to render:

- `vault.status()`: `account` (`not-set-up`, `locked`, `unlocked`), `deviceRegistered`, this device's `deviceId` (or `null`), `recovery` and `pin` (`not-set-up`, `set-up`).
- `vault.listDevices()`: `{ deviceId, current }` per registered device. Keep names and dates on your server, keyed by `deviceId` (integration guide, Devices).
- `vault.warnings()`: `recovery-not-set-up`, `pin-not-set-up`, `rekey-needed` for teams whose keys predate the current phrase, and `foreign-member-keys` for teams where keys were published under the account that this vault didn't make (D-43): treat it as a sign of session theft.
- `team.ownerChanges` and `team.memberChanges`: owner list and roster changes since this account last verified the team, each with its signer (SP-15).
- `team.state`: `not-joined`, `pending`, `ready` or `unverified`.
- `team.owner().overview(activeIds)`, for owners: each account's `status` (`no-keys`, `awaiting-approval`, `approved`, `outdated`, `rekey-awaiting-approval`), its newest `keys` (a handle to approve), their `proof` (`recovery` or `none`), and warnings (`single-owner`, `members-awaiting-approval`, `rekeys-awaiting-approval`, `rotation-needed`) with the operation that clears each.

`team.owner()` throws `NOT_AN_OWNER` for anyone else, so member screens can't reach admin operations. Every call takes and returns plain data.

#### Admin recipes

**At every owner session**, run the autopilot with the accounts your product considers members:

```ts
const report = await team.owner().reconcile(activeIds);
// report.removed, approvedRekeys: done. report.needsHuman: show these, with their reason.
```

It rotates out holders no longer active (never owners), approves re-keys proven by the member's recovery phrase, and approves your own re-key when this session holds the keys (D-47). It never widens access otherwise, never changes owners, and leaves `awaiting-approval`, `outdated`, `rekey-unproven`, `owner-rekey` and `inactive-owner` to a human (SP-22). `{ dryRun: true }` returns the plan for a preview.

| Situation | Calls |
| --- | --- |
| **New user** | `vault.setup(pin)`, `beginRecoverySetup()`, `confirmRecoveryPhrase(typedBack)` |
| **Invite someone** | Put `team.inviteAnchor()` in the invite link's fragment; the joiner calls `vault.joinTeam(teamId)`, then on the first open `vault.openTeam(teamId, { anchor })`, or in another context `receiver.openTeam(ports, transfer, { anchor })` |
| **Approve someone** | Check the request out of band, then `owner.approve([account.keys])` with the handles from `overview`: one rotation for all of them, joiners and re-keys alike. It refuses (`STALE_VERSION`) if newer keys appeared since the review |
| **Set up a team with many members** | Invite everyone, let them join, then approve every `awaiting-approval` account from `overview` in one `owner.approve(...)` call: one version instead of one per member (integration guide) |
| **Name devices** | After a registration, send your server `status().deviceId` with a label; show `listDevices()` joined with those labels, `current` marking this device |
| **Someone leaves** | Drop them from `activeIds`; the next `reconcile` rotates. Or `owner.remove([accountId])` now |
| **Device lost, never used by anyone** | `vault.revokeDevice(deviceId)` from another device |
| **Device possibly misused, or PIN leaked** | End the account's other sign-in sessions, then `vault.secureAccount({ phrase, newPin? })` from a clean device: new account key, other devices cut, every team re-keyed with a recovery proof that owners' `reconcile` approves. Retry any `failed` team with `vault.rekey(teamId, { phrase })` |
| **Recovery phrase leaked, or after a support restore** | End the account's other sign-in sessions, `beginRecoverySetup()`, then `vault.secureAccount({ phrase, newPhrase: typedBack, newPin? })`: new account key and phrase, other devices cut, every team re-keyed with a proof by the old phrase (D-45). A `failed` team retried with the new phrase needs an owner's approval |
| **Replace the recovery phrase** | `beginRecoverySetup()`, then `confirmRecoveryPhrase(typedBack, { currentPhrase })`: teams re-key with proof. With `{ currentPin }` instead (phrase lost), each team needs an owner's approval (D-41) |
| **Change the PIN** | `vault.changePin(newPin, { currentPin })`, or `{ phrase }` when the PIN is forgotten or not set |
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

Put `shareLinkKey()` and `createInbox().linkKey` values in the URL **fragment**. On the page that opens them, call `takeLinkKey()` first: it reads the fragment and removes it from the address bar and history. Follow the share-link checklist in [scope.md](scope.md#what-the-integration-does).

### Integrating a server

[integration.md](integration.md) covers the key store, the OPRF server and where your content pipeline plugs in.
