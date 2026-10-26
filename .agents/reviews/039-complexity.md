# Review 039: complexity, after plans 017 to 025

Mode: `complexity`. Scope: §4.3, §4.4, §5–§7 and §11 of `docs/protocol.md`, the decisions, the scope's server contract, `src/team/`, `src/account/`, the records and the testing kit, at `7bf7ab2` (after plan 025 and 037-A), against review 015 (`7978c94`). Asked to decide 011-A, 026-F and 028-C together. Read only.

## Checked

- **Baseline.** `check:spec` passes. Ledger: 2 of 2 (037 `adversarial`, 038 `change`); open: 011-A (low), 026-F, 028-C (for this review). 48 commits since review 015: plans 017 to 025, reviews 016 to 038.
- **Inventory** of review 015's measures, at this commit.
- **Retirement test** on `team-state`, the one mechanism 011-A, 026-F and 028-C all touch; **decision log** for decisions amended more than once.
- **Not checked:** a full deletion test of every rule added by plans 017 to 025 (each passed its own `change` review, and their guards show each rule has a test that needs it); the content layer (§7), unchanged since review 015; the browser adapter.

## Counts

| Measure | Review 015 (`7978c94`) | Now (`7bf7ab2`) | Grown by |
| --- | --- | --- | --- |
| Roots of trust for a team | 6 | 6 | — |
| Local values (§3.7) | 4 | 4 | — |
| Vault memory state (besides the account key) | 3 | 3 | — |
| Vault warnings | 6 | 6 | — (`foreign-member-keys` widened by D-58) |
| Error codes | 14 | 14 | — |
| Integration duties (the Duties table, after 015-A) | — | 25 | new baseline |
| Words in §5–§7 | 6,080 | 6,707 | +10%: D-58 to D-65 (plans 017–024) |
| Decisions | 56 | 65 | D-57 to D-65 |
| Accepted residuals | 30 | 42 | reviews 016–037, mostly session and server availability (TH-46, TH-28) and the server-controlled history group |

**Reading.** No root, local value, port, warning or error code was added since review 015: the growth is in rules and their text (+10% words, nine decisions) and in documented residuals (+12). Four of those decisions (D-52's amendments, D-62, D-63, part of D-58) and four residual rows exist because of one record, `team-state`, and most of plans 019 and 020 dealt with it. That is where this review looks.

## Retirement test: `team-state`

What it is for (§4.4, §6.1, D-52): an anchor on the server, encrypted under a `teamStateKey` the account's bundles hold, so a context with no local anchor starts from the newest version some context of the account verified. With a floor it is not a root: it counts only on the chain the roots verify, and fails an open when it contradicts that chain (`state_conflict`) or lies above it (`rollback`).

Who it protects against, with a floor:
- **The server (A2)** is the only actor that serves the chain, so the only one that can roll it back or fork it. It can't forge a `team-state`, but it can withhold it or serve an archived older revision (rule 7 keeps them all), which turns both checks off. Against A2 the record bounds nothing; it detects only a server that rolls the chain back but not the `team-state` (028-C).
- **Everyone else** can't roll back the chain. But whoever holds a `teamStateKey` (A7, A9, a receiving context) or the session (A11) can write or delete it, which is what the residuals in TH-46 and TH-28 accept: a forged anchor stops the account's devices (`state_conflict`, `rollback`), garbage made a team unavailable, and D-62 and D-63 were added to limit that.

So with a floor, `team-state` gives detection that its only target can switch off, and an availability surface for everyone else. Without a floor it is worse: a root that anyone holding a key or the session writes (011-A). Every bundle written since D-48 has a floor; floorless ones exist only in data written before it, which v1 doesn't have to read (unreleased; doconvoy resets its v1 data).

What the account's rollback protection rests on without it: the floor (written by the vault from a verified chain, and advanced at every open and export, §5.8), the vault's own anchor and each context's local anchor (D-54). Those already bound everything `team-state` bounds against an honest-looking server; a new device starting from a lagging floor faces the same TH-05 window as today, since the server can serve it an old `team-state`.

### A. Require the floor and retire `team-state` (011-A, 026-F, 028-C)

- **Kind:** simplification. **Severity:** low (removes the availability residuals of TH-46 and TH-28 that `team-state` carries; no confidentiality or integrity change).
- **Actors:** none added. Removes surface for A7, A9, A11 (forged, garbage or deleted `team-state`).
- **Disposition:** retire, with the user's decision (it changes formats, a server rule and the public API). Supersedes the three open findings: 011-A (the floor required), 026-F (conflicts never fail an open: there is nothing to conflict with), 028-C (the record bounds nothing against the server).
- **Proposal:**
  1. Every bundle holds a floor: the `member-keys-wrap` plaintext and the transfer entry carry `signingSeed`, `encryptionSecretKey` and the floor, nothing optional. A bundle without one doesn't open (D-58: absent).
  2. `teamStateKey` leaves the bundle and the transfer; the `team-state` record (§4.4), its label, its server rules (revision + 1, archived revisions) and the `compare-and-set` write op go.
  3. §6.1: the roots are the floor, the local anchor and, in the vault, the vault's anchor; step 7 advances the local anchor only. `state_unreadable` and `state_conflict` leave §9's reasons.
  4. D-62 and D-63 are superseded; D-48 and D-52 keep their history with a pointer; D-42 drops `team-state` from what is archived; D-58 loses the `team-state` slices.
- **Delta** (budget class **free**: it deletes far more than it adds):
  - Deleted: one record type, one key per bundle, one label, one write op, two server rules, two `TRUST_FAILURE` reasons, one root of trust (6 → 5), the "with a floor / with no floor" branches of §4.4 and §6.1 and their code (`readServerState`, the server half of `advanceAnchor`, the no-floor root in `loadChain`), two decisions, about four residual rows (TH-46's `team-state` part, the forged-anchor row, TH-28's replay row, 011-A's floorless-planted case in TH-20).
  - Added: nothing. The layouts change in place, since v1 is unreleased (§13: the first release freezes them), and their vectors are regenerated.
- **What is lost:** `state_conflict` between an account's own devices, when the server forks the chain but serves the newest `team-state`. That case already needs key transparency (TH-38), which is the server-controlled history group's mechanism.
- **Product cost:**
  - **Integrators:** the store drops the `team-state` record, its compare-and-set and its revision rule (doconvoy's Go store and mock: remove, not add); `TeamStateKey` and the `compare-and-set` op leave the port types; stored v1 data is reset.
  - **Users:** two failure states fewer (`state_conflict`, `state_unreadable`), and the support restores of `team-state` go.
  - **Reach:** split layouts no longer share a receiving context's advances across devices through the server; each context keeps its local anchor and the vault's floor advances at every open and export, which is what rollback protection already rests on.
  - **API:** breaking, before the first release: two reasons, one port type and one write op removed.
- **Needs:** a decision (D-66) and a plan; protocol-change with a `design` review is not needed for a pure deletion, but the plan's `change` review must check that nothing still cites the record.

## Decision log

### B. D-58 is amended three times

- **Kind:** simplification. **Severity:** none. **Disposition:** correct the text.
- **Where:** D-58 carries amendments for reviews 028 A, 035 B and 037 B, C; its current rule is spread over four paragraphs.
- **Fix:** a "Current rule" paragraph at the top of D-58 stating what is absent, what is unreadable and what each costs, the amendments kept as history (as review 011 C did for D-48). If A is decided, write it after A, which removes D-58's `team-state` slices.

## Not a finding

- **The vault's anchor (D-54) and the same-PIN check** keep review 015's verdict: each closes a case integrators rely on (`secureAccount` as the remedy; SP-19), and they belong to the server-controlled history group.
- **The growth in residuals:** apart from A's four rows, each is a documented availability or combined-actor case in a deferred group, as the direction asks.

## Edits ready now (no decision)

B (better after A).

## Stop rule

A is a simplification with no current attack: it doesn't count. Still **2 of 2**. If A is decided, its plan's `change` review is the next review.
