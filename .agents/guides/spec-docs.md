# Editing the specs (`docs/`)

The documents in `docs/` are the source of truth for the library. Code follows them; a behaviour change starts here ([protocol-change](../skills/protocol-change/SKILL.md)).

## Order and roles

[scope](../../docs/scope.md) → [threat model](../../docs/threat-model.md) → [security properties](../../docs/security-properties.md) → [key hierarchy](../../docs/key-hierarchy.md) → [protocol](../../docs/protocol.md), with [decisions](../../docs/decisions.md) recording every choice. Problem before solution.

## Ids

- `D-` decisions, `TH-` threats, `SP-` properties, `AS-` assumptions, `A1…` actors, `§` protocol sections.
- Ids are stable: never renumber or reuse one. A removed item stays with a status (for example "Superseded by D-NN").
- Cite ids instead of repeating content.

## Entry shapes

- **Decision:** Status (Accepted / Proposed / Deferred / Superseded), Problem, Decision, Rejected, Consequence.
- **Threat:** Actor, Attack, Impact, Disposition (mitigated by SP-, or accepted with the reason). Update the index row too: its disposition starts with Mitigated, Partly mitigated, Accepted or Not applicable, and cites the same properties as the entry.
- **Threats cite, they don't restate.** A disposition is one to three sentences with ids (SP-, D-, §). How a mechanism works lives in the protocol only, so a change is edited in one place.
- **Property:** Property (falsifiable), Limit when it doesn't cover something, Assumptions, Verification (test files), Related threats. Never claim more than the design delivers: write the Limit next to the claim. A threat in Related threats cites the property in its index row, and the reverse.
- **Protocol record:** fields, protection (exact construction with labels), reader checks, server rule (§11), and catalogue row.

## Writing

- Plain language for generalist engineers; explain a crypto term on first use.
- Vocabulary from the scope (team, member, owner, item, inbox, link share…). No product names.
- Short sentences; lists for parallel items; tables for comparisons.

## After every edit

Run `npm run check:spec`. It checks labels against the §1 table, ids, `§` references, vector names, property traceability, product terms, the threat index against the entries, threats ↔ properties in both directions, error codes and reasons against §9 and `src/errors.ts`, table cell counts, and retired wording.

**Retired wording** (`scripts/retired-terms.json`): when a decision removes or changes something, add the wording it retires, with the sections allowed to keep it as history (`allow`). A match kept on purpose until an open question is decided goes in `known`, with the reason; the check fails once it no longer matches, so the entry leaves with the fix.
