# crypto-convoy

TypeScript library for end-to-end encrypted team storage: account keys, team keys shared through an untrusted server, encrypted items, link shares and inboxes. To be open-sourced.

This package is private (`"private": true`) and at `0.0.0` until a public release is ready. There is no public API beyond a version constant, and no independent security audit. Flip `private` to `false`, set a real version and license, then publish.

## Security documents

The files under `docs/` specify a new model, designed from the problems found in an earlier implementation. Each one states the question it answers. Files marked "draft" are under review; `SECURITY.md` is still an authoring guide. Threats, properties and decisions have stable ids (`TH-01`, `SP-01`, `D-01`); cite them from tests and pull requests.

| File | Question |
| --- | --- |
| [docs/scope.md](docs/scope.md) | What is the library responsible for, and what is left to the application? |
| [docs/decisions.md](docs/decisions.md) | Why is the design the way it is? |
| [docs/threat-model.md](docs/threat-model.md) | Against whom are we protecting the system? |
| [docs/security-properties.md](docs/security-properties.md) | What security guarantees must always hold? |
| [docs/key-hierarchy.md](docs/key-hierarchy.md) | How are keys organized, distributed, and managed? |
| [docs/protocol.md](docs/protocol.md) | How does the cryptographic system work? |
| [SECURITY.md](SECURITY.md) | How should vulnerabilities be reported and handled? |

How they relate:

```text
scope.md
  What the library owns, and what the integration owns
        |
        v
threat-model.md
  Identify threats, attackers, and assumptions
        |
        v
security-properties.md
  Define the guarantees to maintain
        |
        v
key-hierarchy.md                  protocol.md
  Key structure and lifecycle       Cryptographic operations and formats
        |                                 |
        +----------------+----------------+
                         |
                         v
        Automated tests and security review
          Verify implementations against documented properties

decisions.md
  Why each choice was made (cross-cutting)

SECURITY.md
  Cross-cutting disclosure and maintenance policy
```

Write them problem first, one at a time, and review each before starting the next:

1. [docs/scope.md](docs/scope.md) — the library's responsibilities and its boundary with the integration. Record each settled choice in [docs/decisions.md](docs/decisions.md) as you go.
2. [docs/threat-model.md](docs/threat-model.md) — assets, attackers and threats, first at the level of assets.
3. [docs/security-properties.md](docs/security-properties.md) — the guarantees that answer those threats, as checks.
4. [docs/key-hierarchy.md](docs/key-hierarchy.md) — the keys and lifecycles that deliver those properties. Then a second pass on the threat model for threats specific to each key.
5. [docs/protocol.md](docs/protocol.md) — algorithms, serialized formats, and operations, enough to implement a decryptor without this repository's TypeScript.
6. [SECURITY.md](SECURITY.md) — when a public release is close. Turn on GitHub private vulnerability reporting first; do not invent a disclosure address.

## Working with agents

Instructions for AI coding agents live in [AGENTS.md](AGENTS.md) (read natively by Cursor and imported by `CLAUDE.md` for Claude Code), with detailed guides and task workflows in `.agents/`. Claude skills (`.claude/skills/`) and Cursor rules (`.cursor/rules/`) only point to those files, so both tools follow the same rules.

## Scripts

| Script | Purpose |
| --- | --- |
| `npm run typecheck` | TypeScript check for `src`, `test`, and config files |
| `npm run check:spec` | Consistency checks of `docs/`: labels, ids, § references, vectors, traceability, product terms |
| `npm run build` | Vite library build (ESM + CJS + `.d.ts`) into `dist/` |
| `npm test` | Unit, properties, security, and compatibility projects |
| `npm run test:unit` | Unit suite only |
| `npm run test:properties` | Property-based suite (`@fast-check/vitest`) |
| `npm run test:security` | Security suite (sequential files) |
| `npm run test:compatibility` | Compatibility / vector suite |
| `npm run test:fuzz` | Bounded fuzz suite (opt-in; not part of `npm test`) |
| `npm run test:all` | Every Vitest project, including fuzz |
| `npm run test:watch` | Vitest watch mode |

## Test layout

- `test/vectors/` — frozen JSON fixtures (imported by tests; not executed)
- `test/unit/` — example-based tests
- `test/properties/` — invariants via fast-check
- `test/security/` — isolation, key substitution, removal, recovery
- `test/fuzz/` — parser/decoder campaigns (bounded; coverage-guided fuzzing is a later Jazzer.js target)
- `test/compatibility/` — vector replay and cohabitation of protocol versions (there are no legacy formats, see D-01)

## Publish checklist

1. Finish and review every document in `docs/`, in the order in [Security documents](#security-documents).
2. Configure GitHub private vulnerability reporting, then fill in [SECURITY.md](SECURITY.md).
3. Choose a license.
4. Set `version`, set `"private": false`.
5. `npm run prepublishOnly` (typecheck + test + build).
6. `npm publish`.
