# Formal models

Symbolic models of crypto-convoy's sub-protocols, checked with [Tamarin](https://tamarin-prover.com). The attacker controls the network and the server; primitives are ideal; each security property is a lemma that Tamarin proves for every interleaving of unboundedly many sessions, or refutes with an attack trace. Plan: `.agents/plans/027-formal-model.plan.md`.

The models check the design, not the TypeScript: the tests and the vectors check the code. Out of scope: libsodium and parameters, side channels, PIN guessing and the OPRF math, availability, the content layer, parsers.

## Running

Tamarin 1.12.0 with Maude 3.5.1. Where Tamarin has a native build (Linux, Apple Silicon: `brew install tamarin-prover/tap/tamarin-prover` after `brew trust tamarin-prover/tap`), `check:formal` uses it. Intel macOS has none, and Homebrew there builds it from source with LLVM, Rust and GHC; use the container instead, built from the release binaries, each pinned by its SHA-256:

```sh
docker build --platform linux/amd64 -t crypto-convoy-tamarin:1.12.0 formal
npm run check:formal
```

`check:formal` runs each model in batch, compares every lemma's result with `expected.json`, and runs each mutation, which must break the lemma it names. A model may run several times with preprocessor flags (`chain.spthy` with `DEPTH3`). About 5 minutes in the container: the transfer a few seconds, the chain about 2.5 minutes (most of it the attack searches), the mutations the rest. Existence lemmas are searched breadth-first (`--stop-on-trace=BFS`): depth-first, the search can follow the chain forever. With neither Tamarin nor the image it skips with a note. To step through a proof or an attack trace: `tamarin-prover interactive formal/` (or `docker run --rm -p 3001:3001 -v "$PWD/formal:/formal" --entrypoint tamarin-prover crypto-convoy-tamarin:1.12.0 interactive --interface='*4' .`), then open http://127.0.0.1:3001.

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
- The request carries the team; in §3.8 it is the receiver's public key alone, and which team to export is the integration's (D-29). The same on an authentic channel; on one the attacker writes, it chooses the team either way.
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

### `chain.spthy`: the team key chain, roster seals and the owner rule (§4.5, §6.1, §6.4, §6.6)

Roles: owners, who create a team and rotate it, each version rostering its owner and one member, sealing a fresh team key to both and wrapping the previous key under it; members, who join at version 1, with or without the invite anchor, and follow the chain; the server, which serves any stored record in any order, withholds, and stores forged records signed with stolen keys.

| Lemma | Property | Expected |
| --- | --- | --- |
| `executable` | a member joins with the anchor and accepts the next version | trace found |
| `owner_rule` | SP-05: a member accepts a version only if the owner of the version it holds signed it, unless that owner's key was stolen; a removed owner's signature is refused | verified |
| `anchored_join_holds_the_real_version` | SP-07: with the invite anchor, a joiner holds the real version 1, its key and its owner | verified |
| `one_honest_successor` | helper: an honest version has at most one honest successor | verified |
| `no_fork_without_owner_key` | SP-05: members holding a version from one owner never accept two different next versions, nor one with two keys, unless that owner's key was stolen | verified |
| `link_wraps_the_held_key` | §4.5: with no signing key stolen, the previous-key link a member accepts wraps the key it holds | verified |
| `attack_TH04_first_contact` | TH-04, accepted: without the anchor, a joiner holds a version 1 nobody created for that team | trace found |
| `attack_TH38_split_view` | TH-38, accepted: with a stolen owner key, a member accepts a next version other than the one its owner wrote | trace found |
| `attack_037A_wrong_previous_key` | review 037 A, accepted: with a stolen owner key, a member accepts a version whose link wraps another key | trace found |

With `DEPTH3` (three versions):

| Lemma | Property | Expected |
| --- | --- | --- |
| `executable_depth3` | an honest run completes | trace found |
| `team_key_reaches_only_rostered_accounts` | SP-04, SP-06: a version's key is learned only from an account rostered at that version or a later one of the same chain: a removed member learns no later key, and a stolen owner signing key alone learns none | verified |

Mutations: `MUT_NO_OWNER_RULE` (a member accepts a next version signed by anyone) breaks `owner_rule`; `MUT_SEAL_TO_REMOVED` (a rotation also seals to the member it removes) breaks `team_key_reaches_only_rostered_accounts`.

Abstractions:

- Signatures are ideal: the server's store is a fact only two rules write, an owner's rotation and a forgery under a key the attacker stole (restriction `ForgeOnlyWithStolenKey`). A member reads any stored record, in any order. A second forging rule builds the seals from a key the attacker supplies; it adds no power, only spares the search.
- A version's identity is `<parent, name>`, standing for the version number; "a later version" is the subterm relation. The invite anchor names the whole record, as a record hash does.
- A roster seal binds the team alone, looser than §4.5 (version number and keys hash), and the previous-key link binds nothing (§4.5: team and version), so the attacker may move either between records, more than the protocol allows. Review 042 A checked that every result holds with this looser seal.
- One owner per version and two roster entries; an owner may hand over to an account it rosters. Several owners, which TH-38 needs without a stolen key, are not modelled.
- Readers are the member of a record's second roster slot: an owner never follows the chain as a reader. The reader checks don't depend on the role, but the lemmas are proven for that slot.
- Each account has one signing key, never replaced: reader check 3's "same key" and the owner key replacement of §6.7 and §6.8 step 3 (an old owner key refused after a re-key) are not modelled.
- Accounts publish one encryption and one signing key each, in an authentic registry: approving keys is a human's (AS-06).
- One anchor per member, the version it holds; floors and the vault's anchor are not modelled (local state over the same chain check), so review 041 A's planted floor is out of this model.
- Secrecy is proven for chains of three versions (`DEPTH3`): with unbounded rotations, the proof follows the previous-key links without end. Teams, accounts and sessions stay unbounded. The structural lemmas hold on the unbounded chain.

Not covered: rollback and roots. The model checks the join from an invite anchor, not SP-07's refusal of a chain without the anchor, nor the floor and the vault's anchor as roots (D-50, D-54, D-66), nor 041-A's planted floor. They are local checks over the same chain; the external audit's brief names them.

Results (Tamarin 1.12.0, 2026-10-31): every lemma as expected, each mutation breaks only its lemma.

What it shows:

- A removed member learns no later team key, with no help from the server: the roster seals and the forward-only previous-key links are enough (SP-06), at least over three versions.
- A stolen owner signing key alone reveals no team key: it can sign versions, not open them. Its gains are the ones the threat model accepts: split views (TH-38) and a wrong previous-key link (037-A).
- Without the invite anchor, first contact is trust on first use (TH-04); with it, the joiner holds the real version.
- No attack outside TH-04, TH-38 and 037-A was found.

### `recovery.spthy`: the recovery proof (§4.2, §5.11, §6.8)

Roles: the user, whose phrase gives a recovery signing key; the vault, whose recovery wrap stores the recovery public key that keys made without the phrase carry; the owner's `reconcile`, which approves new member keys alone only if their recovery signature verifies against the recovery key the account's held keys carry.

| Lemma | Property | Expected |
| --- | --- | --- |
| `phrase_key_secret` | helper: the phrase's key is learned only from a leaked phrase | verified |
| `held_keys_carry_the_phrase_key` | helper, by induction over approvals: held keys carry the phrase's key, unless the phrase leaked or an account-key holder rewrote the stored key | verified |
| `executable` | the user's re-key with the phrase is approved alone | trace found |
| `proof_needs_the_phrase` | SP-22, SP-23: keys approved alone were made by the user with the phrase, unless the phrase leaked or the stored key was rewritten; a session thief, publishing any keys, gets none approved | verified |
| `proven_keys_carry_the_phrase_key` | D-56: keys proven with the phrase carry the typed phrase's own key, whatever the vault stores | verified |
| `attack_TH41_leaked_phrase` | TH-41, accepted: a leaked phrase proves a re-key the user never made | trace found |
| `attack_TH12_rewritten_stored_key` | TH-12, SP-23 Limit, accepted: keys made without the phrase after an account-key holder rewrote the stored key carry the attacker's key, so its re-keys are proven there | trace found |

Mutations: `MUT_CHECK_CARRIED` (`reconcile` checks the proof against the key the new keys carry) breaks `held_keys_carry_the_phrase_key`; `MUT_STORED_KEY` (a re-key with the phrase carries the stored key) breaks `proven_keys_carry_the_phrase_key`. A helper marked `[reuse]` is assumed by the lemmas after it even when it fails, so a mutation names the lemma that actually fails, and the baseline requires every helper verified.

Abstractions:

- Member keys are `<'mk', team, account, signing public key, recovery public key>`. The self-signature is left out: it proves nothing about who made the keys.
- Signatures are ideal: recovery signatures live in a store that only the user, with the phrase, and the attacker, with a key it knows, write. Team and account names are public.
- Held keys are pinned by the roster (keys hash), so the attacker can't choose them; a human approves only keys the user made (AS-06).
- The vault's stored recovery key is a store of every key written: the real one, and any an account-key holder writes; the vault may read any of them, as a server replaying an earlier recovery wrap makes it (§4.1).
- Owners' own re-keys (D-47), approved by holding the keys, and a phrase replaced with the PIN alone, are not modelled.

Not covered: freshness. The version number orders re-keys, and `reconcile` approves only keys newer than those held (§6.9, `proofOf`). The model leaves the version out and approves any proven record, an earlier one included, which is safe for its lemmas, but none of them states that an earlier proven record, whose private keys a device thief may have copied, is never approved again.

Results (Tamarin 1.12.0, 2026-10-31): every lemma as expected, each mutation breaks its lemma; about 6 seconds.

What it shows:

- A session thief who publishes any keys under the account gets none approved: the proof is checked against the key the *held* keys carry, never the one the new keys carry (`MUT_CHECK_CARRIED` is exactly the attack it stops).
- The only routes to an automatic approval the user didn't make are the two the threat model accepts: a leaked phrase (TH-41) and keys made without the phrase after the stored key was rewritten (TH-12). Re-keying with the phrase ends the second, since proven keys carry the typed phrase's key (D-56).

