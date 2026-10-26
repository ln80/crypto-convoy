---
name: protocol-review
description: "Review crypto-convoy's protocol in one of five modes: change (after a plan changes docs/), design (a proposal before code), adversarial (forgeable inputs, combined attackers, with a fresh-context reviewer), complexity (rules to delete or merge), residuals (accepted risks still acceptable). Reproduces findings, rates them with the severity rubric, writes .agents/reviews/NNN-name.md and updates the ledger. Read only. Use to review, harden or simplify the protocol, or before a freeze."
---

# Workflow: review the protocol

**Use when** a plan changed `docs/` (change), before implementing a protocol change (design), periodically and before a freeze (adversarial, complexity, residuals), or when asked to harden or simplify the protocol. It finds what `check:spec` can't: claims nothing delivers, inputs someone can forge, attacks that need two actors, rules that can go, and accepted risks that no longer hold.

Read only: a review writes a findings file and updates the [ledger](../../reviews/ledger.md); it changes no spec or code. Fixes go through [protocol-change](../protocol-change/SKILL.md).

Every review applies the [hardening direction](../../guides/direction.md): its action rule decides which findings change the protocol, and its complexity budget bounds the fixes a review may propose. Finding something is not a reason to add a rule.

## Modes

Pick one per review; the findings file names it. The mode comes from the request or the skill's arguments (`change`, `design`, `adversarial`, `complexity`, `residuals`); without one, pick it from the "When" column and the ledger's stop-rule line, and say which.

| Mode | When | Question | Reviewer |
| --- | --- | --- | --- |
| `change` | After each plan that changes `docs/` | Do the changed sections and everything they ripple into still agree, with each other and with the code? | This session |
| `design` | Before implementing a plan that changes the protocol | What does the proposal add (an input, a state, a fallback, a branch), and who can abuse it? | Fresh context |
| `adversarial` | Every three plans or so, and before a freeze | Who can forge each input, and what do two actors together gain? | Fresh context |
| `complexity` | Every three plans or so, and after any plan with a costly change | Which rules can be deleted or merged, and what would break? Which exist only for a combined attack we could accept? | This session |
| `residuals` | When a review accepts a new risk, and before a freeze | Are the accepted risks still acceptable, and do two of them chain into something worse? | This session |

## Steps, every mode

1. **Baseline.** Run `npm run check:spec`; note its failures and `known` notes. Read the [ledger](../../reviews/ledger.md), the latest plan, and `git log` since the last review.
2. **Run the mode** (below).
3. **Fresh-context reviewer** (`design`, `adversarial`; optional for the others). Give a reviewer who hasn't seen this work only `docs/`, `src/`, `test/` and the mode's brief (below): not the plans, the reviews, the ledger or this conversation. In Claude Code, an Agent subagent (`general-purpose`) given only the brief and the paths; in Cursor, a new chat. The point is a reader with no stake in the rationale. Ask it for candidate findings with their evidence, not for fixes.
4. **Merge.** Put this session's candidates and the reviewer's together. Drop what the ledger already holds as fixed or accepted, unless the candidate shows the acceptance rests on a wrong premise: that is a finding.
5. **Reproduce.** Each candidate that claims behaviour gets a throwaway test against the code (in `test/security/`, deleted after the review), or a quoted code path when a test isn't practical. Say which, per finding. A candidate nobody can show is dropped or listed as unconfirmed.
6. **Rate** with the [severity rubric](#severity-rubric), then give each finding its **disposition** by the [action rule](../../guides/direction.md#the-action-rule): fix, accept and document, or correct the text. A finding that belongs to a [deferred mechanism](../../guides/direction.md#deferred-mechanisms) names its group.
7. **Write** `.agents/reviews/NNN-name.md` (next free number): mode, scope and commit, what was checked and what wasn't, then each finding: id (letters A, B, … within the review), kind, severity, actors (one alone, or which together), disposition, where (files and lines), evidence (reproduced or read), and, for a fix, its [budget class and product cost](../../guides/direction.md#complexity-budget) and whether it needs a decision or only an edit; for an acceptance, the text that documents it. List edit-only findings apart, so they can be done right away.
8. **Ledger.** Add each finding with status `open` (a fix or a text correction to do) or `accepted` (with the residual row and the text that documents it); add each risk the review accepts to the residuals table. Update the [stop rule](#stop-rule) line.

Finding kinds: overclaim, missing threat, wrong claim, stale text, spec → code, forgeable input, combined attack, hardening, simplification.

## Mode `change`

1. **Read in order:** the changed sections of the [threat model](../../../docs/threat-model.md), [security properties](../../../docs/security-properties.md) and [protocol](../../../docs/protocol.md), then the [decisions](../../../docs/decisions.md) of the plan and the [server contract](../../../docs/scope.md#server-contract). Skim `key-hierarchy.md`, `integration.md`, `using.md` and `README.md`, which repeat claims.
2. **Properties → protocol.** For each sentence of each changed property, name the § that delivers it. A sentence with no § is an **overclaim**: either the protocol misses a step, or the property needs a Limit.
3. **Threats → mechanism.** For each changed threat, check that its actor really can't do the attack with what the protocol allows. For each "detected", "refused with" or "reported" claim, find the code path in `src/` or the test that produces exactly that error, reason or report.
4. **Decisions → text.** For each decision of the plan, search every document for what it changed. Wording that still describes the old behaviour is **stale**; add it to `scripts/retired-terms.json` when you file the finding.
5. **Spec → code.** Where the library or the testing kit (`src/testing/`) behaves differently from the spec, record which one is right, if you can tell.
6. **Plan notes.** Read the plan's execution notes: a risk the plan accepted on its own goes to the residuals table, or becomes a finding.

## Mode `design`

Input: the proposed plan or decision, before code.

1. List what the proposal **adds**: inputs a component now accepts, states it can be in, fallbacks ("if X is missing, use Y"), branches in a rule, and records or fields.
2. For each input and fallback: who can produce it, withhold it, or make it stale (the [forgeability table](#forgeability-table) columns). A fallback is an attack surface: whoever controls the missing value chooses the branch.
3. For each actor (A1–A11) and each pair in the [combined-attacker list](#combined-attackers): what does the proposal let them do that they couldn't before?
4. **Simpler alternative:** state the smallest rule that would give the same guarantee. If it differs from the proposal, it is a finding.
5. **Budget:** state the proposal's delta and [class](../../guides/direction.md#complexity-budget). Remembered state, a new root, a fallback, an integration duty or a human step added for a combined-actor finding is a finding in itself: propose accepting the risk instead.
6. Write the review before the plan is approved; the plan cites it.

## Mode `adversarial`

1. **Forgeability.** Update the [forgeability table](../../reviews/forgeability.md) from the protocol and the code: one row per value a component accepts. A row whose producer includes an actor who shouldn't produce it, and whose authentication doesn't stop them, is a **forgeable input**. A row nobody can explain is a finding too.
2. **Actors × operations first.** For each actor alone, especially whoever holds an unlocked vault or a session, go through every public operation and ask what calling it gains them. One-actor attacks are what the [action rule](../../guides/direction.md#the-action-rule) fixes: spend most of the review here.
3. **Combined attackers.** For each pair in the list below, go through the public operations (§12) and the forgeable rows: what does the pair gain that neither gets alone? A harmful result no threat names is a **combined attack** (a missing threat). Its default disposition is to accept and document it, or to point it to its deferred mechanism.
4. **Assets.** For each asset of the threat model, name every path to it; a path no threat covers is a missing threat.

### Combined attackers

At least: A2 + A11 (server and session), A2 + A9 (server and injected script), A2 + A4 (server and removed member), A2 + A6 (server and owner key), A7 + A11 (device and session), A8 + A11 (credential and session), A2 + an integration error (a link or a transfer relayed by the server).

## Mode `complexity`

1. **Inventory.** List every rule of §5–§7 and the decisions they come from: one line each, with its reason. Count the rules and the branches ("if…, else…") per operation, the remembered state (local values, roots of trust), the integration duties and the user-visible failures, and record the counts in the findings file next to the previous review's. A count that grew since the last `complexity` review is reported, with the plans that grew it.
2. **Retirement test.** For each rule that exists only for a combined-actor attack: would accepting that attack and deleting the rule lose a guarantee the integration relies on? If not, propose the deletion (a simplification).
3. **Deletion test.** For each rule: delete it in thought (or in a throwaway change, with the tests). If no property's sentence and no test needs it, it is a **simplification**. For each branch: can one rule cover both cases?
4. **Merge test.** Rules written in several places (the same idea in D-, §, SP- and the guides): can the text cite one place?
5. **Decision log.** Decisions amended more than once: propose folding the current rule into the newest decision, the others keeping their history.

## Mode `residuals`

1. Read the residuals table of the [ledger](../../reviews/ledger.md) and every accepted or partly mitigated threat.
2. For each residual: does its reason still hold after the decisions since it was accepted? Has its revisit condition happened?
3. **Chains:** for each pair of residuals, can one actor or a pair use both to reach more than either allows? A chain is a combined attack; a chain one actor can run alone is a finding to fix.
4. **Groups:** sort the residuals into the [deferred mechanisms](../../guides/direction.md#deferred-mechanisms). A group whose residuals keep growing, or that a product now needs closed, is reported as a candidate v2 project, with the rules it would retire.
5. Before a freeze: list the residuals a user or integration must be told about, and check that each is in `scope.md`, the integration guide or the using guide.

## Briefs for the fresh-context reviewer

Give the brief, the paths, and nothing else. Ask for candidates with evidence (quotes with file and line), ranked, and for what it didn't cover.

- **design:** "Here is a proposed change to the crypto-convoy protocol: {proposal}. Read `docs/protocol.md`, `docs/threat-model.md` and `docs/security-properties.md`. List every input, state and fallback the change adds; for each, who among the actors A1–A11 can produce, withhold or replay it, and what they gain. State what the change costs: new remembered state, fallbacks, public API, integration duties and failures a user must act on. Propose the smallest rule that would give the same guarantee, and say which rules could be deleted instead."
- **adversarial:** "You are attacking crypto-convoy, an end-to-end encrypted team storage library. Read `docs/` and `src/`. For every value the library accepts from outside a component (records from the server, link values, transfers between contexts, local storage, values handed from the vault to a session), say who can produce it and what authenticates it. Look first for attacks one actor A1–A11 can do alone, with no mistake by the integration; then for attacks that need two actors together, saying what each brings. Report what you can show from the code, with file and line, one-actor attacks first."

## Forgeability table

Kept in [`.agents/reviews/forgeability.md`](../../reviews/forgeability.md), updated by every `adversarial` review and by any `design` review that adds an input. Columns: the value, the component that accepts it, who can produce it, what authenticates it, what the component does when it is missing or stale, and the rule (§) that covers it.

## Severity rubric

Rate by what the attacker must hold, what they gain, and whether anyone sees it.

| Severity | Rule |
| --- | --- |
| **Critical** | One actor alone, with no user or integration error, reads or forges team content or keys, or takes over accounts, silently, for any member. |
| **High** | One actor alone reads or forges content or keys for some members or teams, or takes over an account, silently; or a documented procedure leaves a compromised user compromised. |
| **Medium** | The same gains, but the attack needs two actors, an integration error, or a window that closes by itself; or it is reported to members; or a guarantee the integration relies on is overclaimed. |
| **Low** | Availability only; a rollback to a real, older state within an accepted window; an unlikely combination; or text that is wrong with no security consequence. |

Simplifications and hardening without a current attack take the severity of the risk they remove, or none. Severity measures harm; whether to fix is the [action rule](../../guides/direction.md#the-action-rule)'s.

## Ledger

[`.agents/reviews/ledger.md`](../../reviews/ledger.md) holds every finding (id `NNN-X`, kind, severity, status `open`, `fixed`, `accepted` or `dropped`, and where it was resolved) and every accepted residual (threat, actor, why it is accepted, when to revisit). A finding leaves `open` only with a decision, a commit or an acceptance recorded. Reviews cite the ledger instead of repeating old findings.

## Stop rule

The protocol is a **freeze candidate** when two reviews in a row, in different modes, at least one of them `adversarial` with a fresh-context reviewer, find nothing the [action rule](../../guides/direction.md#the-action-rule) says to fix beyond availability, and the ledger has no such finding open. Findings accepted and documented, text corrected, and availability-only fixes (a small change the action rule takes for availability) don't count: they are still done, before the first release, but don't reset the count. Then: a formal model of the transfer, the roster seals and the recovery proof (for example in Tamarin or ProVerif), and an external audit, before the first release freezes the vectors (§13). The ledger keeps the current count.

## Done when

- The mode's steps were run, and the findings file says what was checked and what wasn't.
- Every finding was reproduced or shown from the code, or is marked unconfirmed.
- The ledger and the stop-rule line are updated.
