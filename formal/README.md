# Formal models

Symbolic models of crypto-convoy's sub-protocols, checked with [Tamarin](https://tamarin-prover.com). The attacker controls the network and the server; primitives are ideal; each security property is a lemma that Tamarin proves for every interleaving of unboundedly many sessions, or refutes with an attack trace. Plan: `.agents/plans/027-formal-model.plan.md`.

The models check the design, not the TypeScript: the tests and the vectors check the code. Out of scope: libsodium and parameters, side channels, PIN guessing and the OPRF math, availability, the content layer, parsers.

## Running

Tamarin 1.12.0 with Maude 3.5.1. Where Tamarin has a native build (Linux, Apple Silicon: `brew install tamarin-prover/tap/tamarin-prover` after `brew trust tamarin-prover/tap`), `check:formal` uses it. Intel macOS has none, and Homebrew there builds it from source with LLVM, Rust and GHC; use the container instead, built from the release binaries, each pinned by its SHA-256:

```sh
docker build --platform linux/amd64 -t crypto-convoy-tamarin:1.12.0 formal
npm run check:formal
```

`check:formal` runs each model in batch, compares every lemma's result with `expected.json`, and runs each mutation, which must break the lemma it names (the transfer model: about 16 seconds). With neither Tamarin nor the image it skips with a note. To step through a proof or an attack trace: `tamarin-prover interactive formal/` (or `docker run --rm -p 3001:3001 -v "$PWD/formal:/formal" --entrypoint tamarin-prover crypto-convoy-tamarin:1.12.0 interactive --interface='*4' .`), then open http://127.0.0.1:3001.

## How a model is trusted

- **Executable:** an honest run completes (`executable`), so no lemma holds vacuously.
- **Known attacks:** the attacks the threat model accepts are found as traces (`attack_TH…`). If one weren't, the attacker or the model would be too weak.
- **Mutations:** removing one check (`-D=MUT_…`) breaks the lemma that relies on it.
- **Traceability:** each rule cites its protocol step, each lemma its SP- or TH- id.

## Models

### `transfer.spthy`: moving a team's keys between contexts (§3.8)

Roles: the vault of account A, which holds the team's bundle (member keys and anchor floor); a receiving context C, which asks for account A and team T; the integration's channel between them.

| Lemma | Property | Expected |
| --- | --- | --- |
| `executable` | an honest transfer completes | trace found |
| `keys_secret_on_authentic_channel` | SP-02: on a channel only the integration writes, the attacker learns no member key, though it reads every request and transfer | verified |
| `accepts_only_exports_on_authentic_channel` | SP-02: there, a receiver accepts only keys the vault exported to it | verified |
| `transfer_opens_only_for_its_account_and_team` | SP-02: even on a channel the attacker writes, a receiver accepts another team's or account's real keys only if they leaked: the account key, a receiver's secret, or an export to a key no receiver made (TH-39) | verified |
| `receiver_opens_once` | §3.8 step 3: a receiver opens one transfer, replays included | verified |
| `floor_arrives_intact` | D-66: even on a channel the attacker writes, real keys arrive with the floor the vault holds, unless they leaked as above | verified |
| `attack_TH39_substituted_request` | TH-39, accepted: on a channel the attacker writes, a substituted request receives the keys | trace found |
| `attack_TH49_forged_transfer` | TH-49, accepted: there, a receiver accepts keys no vault exported | trace found |

Mutations: `MUT_NO_CONTEXT` (the box carries no account or team) breaks `transfer_opens_only_for_its_account_and_team`; `MUT_REUSE` (the receiver keeps its key) breaks `receiver_opens_once`.

Abstractions:

- `seal` is ideal public-key encryption with an anonymous sender (`aenc`), as libsodium's sealed box (§3.2), with the context inside the box.
- A bundle's private keys are one fresh secret; its floor is public, as an anchor is.
- The check against the published `member-keys` record (§3.8 step 3) is left out: it binds keys to what the server serves, which the server controls (TH-49).
- The channel is the integration's duty (D-29): the attacker always reads it and replays it; `Chan_inject` stands for a channel the server or a script can write. Lemmas about the duty exclude injection; the accepted attacks need it.
- One reveal per actor: the account key (A7, A9 in the vault: every bundle) and a receiver's secret (A9 in the receiving context), read from a record of its own so a reveal doesn't renew the receiver.
- "Leaked" is stated as protocol events (a reveal, or an export to a key no receiver made), not as the attacker's knowledge `K(k)`: in Tamarin, `K` marks only a term the attacker sends, so a lemma excusing `K(k)` misses an attacker who learns `k` and builds a box with it.

Results (Tamarin 1.12.0, 2026-10-30): every lemma as expected.

| Lemma | Result |
| --- | --- |
| `executable` | trace found, 6 steps |
| `keys_secret_on_authentic_channel` | verified, 7 steps |
| `accepts_only_exports_on_authentic_channel` | verified, 7 steps |
| `transfer_opens_only_for_its_account_and_team` | verified, 30 steps |
| `receiver_opens_once` | verified, 14 steps |
| `floor_arrives_intact` | verified, 15 steps |
| `attack_TH39_substituted_request` | trace found, 4 steps |
| `attack_TH49_forged_transfer` | trace found, 6 steps |
| `MUT_NO_CONTEXT` | breaks `transfer_opens_only_for_its_account_and_team` only (7 steps) |
| `MUT_REUSE` | breaks `receiver_opens_once` only (12 steps) |

What it shows:

- The integration's channel needs to be **authentic, not secret**: the attacker reads every request and transfer in `keys_secret_on_authentic_channel` and still learns no key. D-29's "a channel the server can't write" is exactly the assumption needed.
- On a channel the attacker writes, the two accepted attacks are the only gains: the account and team inside the box, single use and the floor still hold for every transfer the vault sealed to a real receiver. Everything else follows from TH-39's leak.
- No attack outside TH-39 and TH-49 was found.
