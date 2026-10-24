# crypto-convoy

End-to-end encrypted team storage. The service that stores your data can hide it or refuse it. It cannot read it, add a reader, or appoint an owner: your software checks that, not the service.

## Where this kind of product fails

Encrypting a file is ordinary. What goes wrong is who can open it. The service can decide who is a member, who is an owner, or who is given a key, and that decision usually sits in the same place as the data. A break-in, or someone at the company who looks, is enough.

## What this protocol changes

The service stores the data and delivers it. The keys stay with the members. Who can read, and who can change that, is signed, and the software on each member's side checks the signature before it opens anything.

Many systems let the service decide who belongs. That is reasonable when you trust the service with membership. Here, your software can refuse that decision.

## What you can rely on

The service can hide something or refuse to answer. It cannot read an item, add itself or anyone else as a reader, appoint an owner, or replace a key without your software noticing.

You still trust it for three things. It has to slow down guesses of your PIN. The locked copy of your account is for you alone. It cannot overwrite the history of who had access. If it fails at those, you can be locked out, or a short PIN becomes easier to guess. Reading the team's data, or joining the team unnoticed, is still beyond it.

Whoever runs that service follows the [server contract](docs/scope.md#server-contract).

Someone who already had access keeps what they could open. A new member is approved by a person. The service can see who is in the team.

## Who it is for

Someone whose team keeps its data in a product built this way. What that product can promise them is the limit above, whether or not the company means well.

## TypeScript

This repository is a TypeScript implementation of protocol v1. The package is private and at `0.0.0`, and it has had no independent security audit.

| Import | For |
| --- | --- |
| `crypto-convoy` | The account vault, team sessions, and link handling |
| `crypto-convoy/browser` | Device storage and reading a key from a link |
| `crypto-convoy/testing` | An in-memory server, for tests |

```ts
import { createVault } from "crypto-convoy";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore } from "crypto-convoy/testing";

const keyStore = new MemoryRecordStore();
const local = new MemoryLocalKeyStore();
const oprf = new FakeOprfServer();
// In production, the OPRF public keys ship in your client code, never from your server (D-53).
const settings = { oprf: await oprf.clientSettings() };
const vault = await createVault(
  { store: keyStore.as("alice"), oprf, deviceKeys: local, anchors: local, settings },
  "alice",
);

await vault.setup("1234");
const { recoveryPhrase } = vault.beginRecoverySetup(); // show it, then ask the user to type it back
await vault.confirmRecoveryPhrase(typedBack, { currentPin: "1234" });
await vault.createTeam("team-1");
const team = await vault.openTeam("team-1");
```

The rest of the client API is in [docs/using.md](docs/using.md). How a backend implements the server contract is in [docs/integration.md](docs/integration.md).

## In this repository

| File | Question |
| --- | --- |
| [docs/scope.md](docs/scope.md) | What is the library responsible for, and what is left to the application? |
| [docs/threat-model.md](docs/threat-model.md) | Against whom are we protecting the system? |
| [docs/security-properties.md](docs/security-properties.md) | What security guarantees must always hold? |
| [docs/key-hierarchy.md](docs/key-hierarchy.md) | How are keys organized, distributed, and managed? |
| [docs/protocol.md](docs/protocol.md) | How does the cryptographic system work? |
| [docs/decisions.md](docs/decisions.md) | Why is the design the way it is? |

Instructions for AI coding agents live in [AGENTS.md](AGENTS.md). `npm test` runs the suites. `npm run check:spec` checks these documents against each other.
