# Editing the specs (`docs/`)

The documents in `docs/` are the source of truth for the library. Code follows them; a behaviour change starts here ([protocol-change](../workflows/protocol-change.md)).

## Order and roles

[scope](../../docs/scope.md) → [threat model](../../docs/threat-model.md) → [security properties](../../docs/security-properties.md) → [key hierarchy](../../docs/key-hierarchy.md) → [protocol](../../docs/protocol.md), with [decisions](../../docs/decisions.md) recording every choice. Problem before solution.

## Ids

- `D-` decisions, `TH-` threats, `SP-` properties, `AS-` assumptions, `A1…` actors, `§` protocol sections.
- Ids are stable: never renumber or reuse one. A removed item stays with a status (for example "Superseded by D-NN").
- Cite ids instead of repeating content.

## Entry shapes

- **Decision:** Status (Accepted / Proposed / Deferred / Superseded), Problem, Decision, Rejected, Consequence.
- **Threat:** Actor, Attack, Impact, Disposition (mitigated by SP-, or accepted with the reason). Update the index row too.
- **Property:** Property (falsifiable), Limit when it doesn't cover something, Assumptions, Verification (test files), Related threats. Never claim more than the design delivers: write the Limit next to the claim.
- **Protocol record:** fields, protection (exact construction with labels), reader checks, server rule (§11), and catalogue row.

## Writing

- Plain language for generalist engineers; explain a crypto term on first use.
- Vocabulary from the scope (team, member, owner, item, inbox, link share…). No product names.
- Short sentences; lists for parallel items; tables for comparisons.

## After every edit

Run `npm run check:spec`. It checks labels against the §1 table, ids, `§` references, vector names, property traceability and product terms.
