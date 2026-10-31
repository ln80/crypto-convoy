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
- **Tooling:** Homebrew has no bottle for Intel macOS, so its install builds Tamarin's whole toolchain (LLVM, Rust, GHC) and upgrades 33 libraries; aborted. No Tamarin release ships an Intel macOS binary. Used instead: `formal/Dockerfile`, Ubuntu 24.04 with the Linux release binaries of Tamarin 1.12.0 and Maude 3.5.1, each pinned by the SHA-256 recorded at the first download; `check:formal` uses a native `tamarin-prover`, else that image.
- **Model fixes while running:** Tamarin's preprocessor accepts `#ifdef` only between rules and not nested, so the mutations became whole rules (`MUT_REUSE` an extra rule giving the receiver back its key); capitalised variables in lemmas parse as facts, so lemma variables are lowercase; the receiver's secret is revealed from its own record, since a reveal that consumed and renewed the receiver made `receiver_opens_once` loop.
- **Two lemmas restated:** context binding and floor integrity were first refuted, rightly: on a channel the attacker writes, TH-39 leaks the keys, after which it seals them for any team or floor. They now hold "unless the keys leaked", with the leak named as events (a reveal, or an export to a key no receiver made). A first try excused `K(k)`, which Tamarin logs only when the attacker sends `k`, so it missed the attacker that builds the box itself.
- **Results:** every lemma as expected, each mutation breaks only its lemma; about 16 seconds. No attack beyond TH-39 and TH-49. The channel needs authenticity, not secrecy.
- **Traceability:** SP-02's Verification names the model and its lemmas; `traceability.test.ts` checks the model exists, cites the property and defines each lemma (guarded by a misspelled lemma).
- **Model 2, chain (`formal/chain.spthy`):** owners create and rotate (one owner and one member rostered per version, a fresh key sealed to both, the previous key wrapped), members join with or without the invite anchor and follow the chain; the server serves any stored record in any order and stores records forged with stolen keys.
  - **What made it tractable:** reading records off the network made the search assemble every possible signed record, without end. Signatures are ideal, so the store became a fact only an owner's rotation and a forgery under a stolen key (restriction `ForgeOnlyWithStolenKey`) write. Version names are public and unique (a fresh nonce sent the search through every rotation). The owner's state starts with its fresh key, so Tamarin treats it as used once; a helper lemma (`one_honest_successor`) gives the no-fork proof that fact. Events carry the held version's owner, so a lemma never pairs two holdings of one version.
  - **Secrecy is bounded:** with unbounded rotations, the secrecy proof follows the previous-key links without end, also with induction; under the flag DEPTH3 (three versions; teams, accounts and sessions unbounded) it is proven. The structural lemmas hold on the unbounded chain.
  - **Attack searches:** breadth-first; the split view is stated from one member (it accepts a forged next version while its owner's real one exists), and a second forging rule builds seals from a key the attacker supplies, which adds no power; the two-member form didn't finish in 5 minutes.
  - **Results:** every lemma as expected; `MUT_NO_OWNER_RULE` breaks `owner_rule`, `MUT_SEAL_TO_REMOVED` breaks secrecy. No attack beyond TH-04, TH-38 and 037-A. A stolen owner signing key alone reveals no team key.
  - **Not modelled:** several owners per version (TH-38 without a stolen key), floors and the vault's anchor (041-A), member-keys approval (AS-06).
- **check:formal:** a model can run with flags (`chain.spthy DEPTH3`); Tamarin's output goes to a file (the chain's proofs passed the 64 MB buffer, which failed the first full run); mutations prove only their target lemma; each run prints its time. About 13 minutes in all.
- **Traceability:** SP-04, SP-05, SP-06 and SP-07 name the chain model's lemmas.
