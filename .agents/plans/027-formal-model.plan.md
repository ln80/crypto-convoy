# Plan 027: formal models of the transfer, the roster seals and the recovery proof

## Context

The stop rule reached 2 of 2 after reviews 040 and 041: the protocol is a freeze candidate. Before the first release freezes the vectors (§13), the stop rule asks for a formal model of three sub-protocols, then an external audit. Reviews found attacks by people looking hard; a model checks every interleaving of unboundedly many sessions, and makes the accepted residuals exact traces.

This plan adds models; it changes no protocol rule. A model that finds an attack nobody accepted is a finding for a review, handled through protocol-change.

## Tool and layout

- **Tamarin** (with Maude), symbolic: the attacker controls the network and the server, crypto is ideal, and properties are lemmas the tool proves or refutes with an attack trace. Chosen over ProVerif because the protocol is stateful (floors, anchors, rosters, held keys). Install: `brew trust tamarin-prover/tap`, then `brew install tamarin-prover/tap/tamarin-prover` (the user runs the trust step).
- **`formal/`**: one `.spthy` file per model, a README with each model's abstractions, and `expected.json` with each lemma's expected result. Not in the npm package.
- **`npm run check:formal`** (`scripts/check-formal.mjs`): runs each model in batch, compares every lemma's result with `expected.json`, then runs each mutation (a preprocessor flag that removes one check) and expects its named lemma to fail. Skipped, with a note, when Tamarin isn't installed; CI later.

## Validation

1. **Executability:** each model proves an honest run completes, so no lemma holds vacuously.
2. **Known attacks:** each model finds the attacks the threat model accepts, as traces (expected `verified` for an `exists-trace` attack lemma). Not finding one means the attacker or the model is too weak.
3. **Mutations:** removing one check (the context in the seal, single use, the owner rule, a root) makes the lemma that relies on it fail.
4. **Traceability:** every rule cites its § step, every lemma its SP- or TH- id; once a model is done, the property's Verification line names the model and lemma, and `check:spec` checks the ids exist.

## Models, in order

| # | Model | Spec | Lemmas | Accepted attacks it must find |
| --- | --- | --- | --- | --- |
| 1 | Transfer | §3.8, D-29, D-66 | executable; keys secret on an authentic channel; a receiver accepts only what the vault exported on it; a transfer opens only for the account and team it names; once; the floor arrives intact | TH-39 (a substituted request receives the keys), TH-49 (a forged transfer is accepted) on an open channel |
| 2 | Chain, roster seals, roots | §4.5, §6.1, §6.6, D-52, D-54, D-66 | only rostered members learn a version's key; a removed member learns no later key; owner rule; a chain without every root is refused | TH-38 (split view), TH-04 (first contact), 041-A (planted floor, deleted vault anchor) |
| 3 | Recovery proof | §4.2, §5.11, D-33, D-47, D-56 | an automatically approved re-key was made by a holder of the phrase | the rewritten recovery key carried by keys made without the phrase (TH-12, SP-23 residual) |

Stop after model 1 and judge what it found and cost before models 2 and 3.

## Out of scope

The TypeScript code (tests and vectors check it), libsodium and parameters, side channels, PIN guessing and the OPRF math (computational), availability, the content layer, parsers.

## Phases (one commit each)

1. Plan, `formal/` skeleton, check script, `package.json` script.
2. Transfer model, run, results in `formal/README.md`; SP-02's Verification names it.
3. Review the model against §3.8 (`change` mode, model only); decide on models 2 and 3.

## Execution notes
