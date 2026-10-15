# crypto-convoy

TypeScript library for Convoy end-to-end encryption primitives. Intended to be extracted from Doconvoy and open-sourced later.

This package is private (`"private": true`) and at `0.0.0` until a public release is ready. Flip `private` to `false`, set a real version and license, then publish.

## Scripts

| Script | Purpose |
| --- | --- |
| `npm run typecheck` | TypeScript check for `src`, `test`, and config files |
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
- `test/compatibility/` — legacy envelopes and vector replay

## Publish checklist

1. Fill in `docs/` and `SECURITY.md`
2. Choose a license
3. Set `version`, set `"private": false`
4. `npm run prepublishOnly` (typecheck + test + build)
5. `npm publish`
