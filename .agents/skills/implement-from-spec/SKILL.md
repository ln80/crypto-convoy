---
name: implement-from-spec
description: "Implement a record, building block or operation from docs/protocol.md in crypto-convoy: vectors first, validation order, suite registry, security tests for every property it serves. Use when writing library code from the spec."
---

# Workflow: implement part of the protocol

**Use when** implementing a record, a building block or an operation described in `docs/protocol.md`.

**Inputs:** the protocol section (§), the properties (SP-) and threats (TH-) it serves.

## Steps

1. **Read** the section, the records it touches (§4), the operations using them (§5–§7), the verification order (§8) and the errors (§9). List the SP- ids that cite it.
2. **Check scope:** if the spec is ambiguous or missing a rule, stop and use [protocol-change](../protocol-change/SKILL.md). Don't guess.
3. **Plan** the steps (guide: [workflow](../../guides/workflow.md)) and place the code (guide: [architecture](../../guides/architecture.md)):
   - building blocks in `encoding/` or `suites/`;
   - records in `records/<name>.ts`: type, shape validation, payload encoder per `v`, build, open;
   - operations in `account/`, `team/` or `content/`, respecting the vault/session split.
4. **Vectors first:** write the frozen vector cases for the new format in `test/vectors/<area>.v1.json`, with outputs computed independently.
5. **Implement**, following [crypto-rules](../../guides/crypto-rules.md): validation order, exact sizes, labels from the §1 table, typed errors.
6. **Test** (guide: [testing](../../guides/testing.md)): vector replay (`compatibility`), round trips and tampering (`properties`), the adversarial tests named by each SP (`security`), fuzzing of new parsers.
7. **Prove** each security test guards its rule: break the rule, see the test fail, restore.
8. **Check:** `npm run typecheck`, `npm test`, `npm run check:spec`; the traceability test is green.

## Done when

- The behaviour matches the section exactly; nothing unspecified was added.
- Every SP citing the section has passing tests in the files it names.
- Vectors are committed and replayed.
