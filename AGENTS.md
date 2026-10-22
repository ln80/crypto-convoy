# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, others) working on crypto-convoy. This file is the single source of truth for agent instructions: tool-specific files (`CLAUDE.md`, `.cursor/rules/`, `.claude/skills/`) only point here and to `.agents/`.

## What this is

crypto-convoy is a TypeScript library for end-to-end encrypted team storage: account keys protected by a PIN, a recovery phrase and per-device keys; team keys shared through an untrusted server; encrypted items, link shares and inboxes. It is product-agnostic, framework-agnostic and platform-neutral.

## The specs are the source of truth

| Document | Ids | Role |
| --- | --- | --- |
| [docs/scope.md](docs/scope.md) | — | What the library does, the integration's duties, server contract |
| [docs/decisions.md](docs/decisions.md) | `D-` | Why each choice was made |
| [docs/threat-model.md](docs/threat-model.md) | `TH-`, `AS-`, `A1…` | Attackers, assumptions, threats |
| [docs/security-properties.md](docs/security-properties.md) | `SP-` | Guarantees, each with its tests |
| [docs/key-hierarchy.md](docs/key-hierarchy.md) | — | Keys and lifecycles |
| [docs/protocol.md](docs/protocol.md) | `§` | Exact algorithms, records, operations, errors |

Never implement behaviour the protocol doesn't specify. If the spec is missing or ambiguous, change it first ([protocol-change](.agents/workflows/protocol-change.md)).

## Non-negotiable rules

1. **Readers dispatch on what a record declares** (`v`, `suite`, link prefix); **writers use the newest**.
2. **Stored data is forever:** released labels, layouts and vectors never change; changes are new versions, shipped readers first.
3. **Canonical encoding only**, every payload starting with `label(name)` from the protocol §1 table.
4. **Validate before crypto** and fail closed, in the protocol §8 order.
5. **Decryption returns all or nothing:** never partial or empty data on failure.
6. **No keys, plaintext or record contents** in logs, errors or exceptions.
7. **Never retry an OPRF evaluation automatically.**
8. **Randomness only from libsodium**; primitives only through the suite registry.
9. **Boundaries:** dependency allowlist, platform-neutral core, public API only through `src/index.ts`.
10. **The application never sees raw keys** (D-15); the vault/session custody split is respected (D-03).

## Guides and workflows

- Guides: [architecture](.agents/guides/architecture.md) · [crypto rules](.agents/guides/crypto-rules.md) · [testing](.agents/guides/testing.md) · [editing specs](.agents/guides/spec-docs.md) · [workflow](.agents/guides/workflow.md)
- Workflows: [implement from spec](.agents/workflows/implement-from-spec.md) · [add an algorithm suite](.agents/workflows/add-algorithm-suite.md) · [security property tests](.agents/workflows/security-property-tests.md) · [protocol change](.agents/workflows/protocol-change.md) · [capture a learning note](.agents/workflows/capture-learning.md) · [maintain the protocol course](.agents/workflows/maintain-course.md) · [spec review](.agents/workflows/spec-review.md)
- Plans: `.agents/plans/NNN-name.plan.md` · Reviews: `.agents/reviews/NNN-name.md`

## Commands

| Command | Purpose |
| --- | --- |
| `npm run typecheck` | TypeScript check |
| `npm test` | Unit, properties, security and compatibility projects |
| `npm run test:security` | Adversarial tests only |
| `npm run test:fuzz` | Bounded fuzzing (opt-in) |
| `npm run test:browser` | Browser adapter tests (Node, with fake IndexedDB) |
| `npm run check:spec` | Consistency of `docs/` (labels, ids, § references, vectors, traceability, product terms, threat index, threats ↔ properties, errors, tables, retired wording in `scripts/retired-terms.json`) |
| `npm run build` | Library build: `crypto-convoy`, `crypto-convoy/browser`, `crypto-convoy/testing` |
| `npm run test:package` | Runs the built package as a consumer, after `build` |
| `npm run vectors:generate` | Writes missing vector files from independent generators; never overwrites |

Every security property's tests must exist and pass: the traceability test (`test/unit/traceability.test.ts`) enforces it.
